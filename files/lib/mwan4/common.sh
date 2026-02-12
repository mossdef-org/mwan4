#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Based on original mwan3 by Florian Eckert <fe@dev.tdt.de>

IP4="ip -4"
IP6="ip -6"
SCRIPTNAME="$(basename "$0")"
config_get_list() { config_get "$@"; }

MWAN4_STATUS_DIR="/var/run/mwan4"
MWAN4_STATUS_NFT_LOG_DIR="${MWAN4_STATUS_DIR}/nft_log"
MWAN4TRACK_STATUS_DIR="/var/run/mwan4track"

MWAN4_INTERFACE_MAX=""

MMX_MASK=""
MMX_DEFAULT=""
MMX_BLACKHOLE=""
MM_BLACKHOLE=""

MMX_UNREACHABLE=""
MM_UNREACHABLE=""
MAX_SLEEP=$(((1<<31)-1))

# nftables variables (only declare once to avoid readonly errors on re-source)
if [ -z "$nft" ]; then
	# shellcheck disable=SC2155  # Declare and assign separately - not critical for command -v
	readonly nft="$(command -v nft)"
	# shellcheck disable=SC2034  # Used by sourcing scripts
	readonly nftTable='fw4'
	readonly nftPrefix='mwan4'
	# shellcheck disable=SC2034  # Used by sourcing scripts
	readonly nftIPv4Flag='ip'
	# shellcheck disable=SC2034  # Used by sourcing scripts
	readonly nftIPv6Flag='ip6'
	# shellcheck disable=SC2034  # Used by sourcing scripts
	readonly nftTempFile="/var/run/${nftPrefix}.nft"
	# shellcheck disable=SC2034  # Used by sourcing scripts
	readonly nftMainFile="/usr/share/nftables.d/ruleset-post/10-${nftPrefix}-base.nft"
	# shellcheck disable=SC2034  # Used by sourcing scripts
	readonly nftIfaceFile="/usr/share/nftables.d/ruleset-post/11-${nftPrefix}-interfaces.nft"
	# shellcheck disable=SC2034  # Used by sourcing scripts
	readonly nftPolicyFile="/usr/share/nftables.d/ruleset-post/12-${nftPrefix}-policies.nft"
	# shellcheck disable=SC2034  # Used by sourcing scripts
	readonly nftRulesFile="/usr/share/nftables.d/ruleset-post/13-${nftPrefix}-rules.nft"
fi

# Check IPv6 support
command -v ip > /dev/null && ip -6 addr show > /dev/null 2>&1
NO_IPV6=$?

LOG()
{
	local facility=$1; shift
	# in development, we want to show 'debug' level logs
	# when this release is out of beta, the comment in the line below
	# should be removed
	[ "$facility" = "debug" ] && return
	logger -t "${SCRIPTNAME}[$$]" -p $facility "$*"
}

# Get list of families for an interface
# Supports both 'list family' (new) and 'option family' (legacy, auto-migrated)
# Defaults to 'ipv4' if no family specified
mwan4_get_families()
{
	local iface="$2"
	local families

	config_get_list families "$iface" family

	# Default to ipv4 if no family specified
	[ -z "$families" ] && families="ipv4"

	export "$1=$families"
}

# Execute callback for each family of an interface
# Usage: mwan4_foreach_family <interface> <callback> [additional args...]
# Callback receives: <interface> <family> [additional args...]
mwan4_foreach_family()
{
	local iface="$1"
	local callback="$2"
	shift 2
	local families family

	mwan4_get_families families "$iface"

	for family in $families; do
		"$callback" "$iface" "$family" "$@"
	done
}

mwan4_get_true_iface()
{
	local family V
	_true_iface=$2

	# If family is provided as 3rd argument, use it
	# Otherwise get it from config (backward compatibility)
	if [ -n "$3" ]; then
		family="$3"
	else
		config_get family "$2" family ipv4
	fi

	if [ "$family" = "ipv4" ]; then
		V=4
	elif [ "$family" = "ipv6" ]; then
		V=6
	fi
	ubus call "network.interface.${2}_${V}" status &>/dev/null && _true_iface="${2}_${V}"
	export "$1=$_true_iface"
}

mwan4_get_src_ip()
{
	local family _src_ip interface true_iface device addr_cmd default_ip IP sed_str
	interface=$2

	# If family is provided as 3rd argument, use it
	# Otherwise get it from config (backward compatibility)
	if [ -n "$3" ]; then
		family="$3"
	else
		config_get family "$interface" family ipv4
	fi

	mwan4_get_true_iface true_iface "$interface" "$family"

	unset "$1"
	if [ "$family" = "ipv4" ]; then
		addr_cmd='network_get_ipaddr'
		default_ip="0.0.0.0"
		sed_str='s/ *inet \([^ \/]*\).*/\1/;T;p;q'
		IP="$IP4"
	elif [ "$family" = "ipv6" ]; then
		addr_cmd='network_get_ipaddr6'
		default_ip="::"
		sed_str='s/ *inet6 \([^ \/]*\).* scope.*/\1/;T;p;q'
		IP="$IP6"
	fi

	$addr_cmd _src_ip "$true_iface"
	if [ -z "$_src_ip" ]; then
		if [ "$family" = "ipv6" ]; then
			# on IPv6-PD interfaces (like PPPoE interfaces) we don't
			# have a real address, just a prefix, that can be delegated
			# to interfaces, because using :: (the fallback above) or
			# the local address (fe80:... which will be returned from
			# the sed_str expression defined above) will not work
			# (reliably, if at all) try to find an address which we can
			# use instead
			network_get_prefix6 _src_ip "$true_iface"
			if [ -n "$_src_ip" ]; then
				# got a prefix like 2001:xxxx:yyyy::/48, clean it up to
				# only contain the prefix -> 2001:xxxx:yyyy
				_src_ip=$(echo "$_src_ip" | sed -e 's;:*/.*$;;')
				# find an interface with a delegated address, and use
				# it, this would be sth like 2001:xxxx:yyyy:zzzz:...
				# we just select the first address that matches the prefix
				# NOTE: is there a better/more reliable way to get a
				#       usable address to use as source for pings here?
				local pfx_sed
				pfx_sed='s/ *inet6 \('"$_src_ip"':[0-6a-f:]\+\).* scope.*/\1/'
				_src_ip=$($IP address ls | sed -ne "${pfx_sed};T;p;q")
			fi
		fi
		if [ -z "$_src_ip" ]; then
			network_get_device device $true_iface
			_src_ip=$($IP address ls dev $device 2>/dev/null | sed -ne "$sed_str")
		fi
		if [ -n "$_src_ip" ]; then
			LOG warn "no src $family address found from netifd for interface '$true_iface' dev '$device' guessing $_src_ip"
		else
			_src_ip="$default_ip"
			LOG warn "no src $family address found for interface '$true_iface' dev '$device'"
		fi
	fi
	export "$1=$_src_ip"
}

readfile() {
	[ -f "$2" ] || return 1
	# read returns 1 on EOF
	read -d'\0' $1 <"$2" || :
}

mwan4_get_mwan4track_status()
{
	local interface=$2
	local family="$3"
	local status_iface="$interface"
	local track_ips pid cmdline started

	# For dual-stack, use family-specific status directory
	[ -n "$family" ] && status_iface="${interface}_${family}"

	mwan4_list_track_ips()
	{
		track_ips="$1 $track_ips"
	}
	config_list_foreach "$interface" track_ip mwan4_list_track_ips

	if [ -z "$track_ips" ]; then
		export -n "$1=disabled"
		return
	fi
	readfile pid "$MWAN4TRACK_STATUS_DIR/$status_iface/PID" 2>/dev/null
	if [ -z "$pid" ]; then
		export -n "$1=down"
		return
	fi
	readfile cmdline /proc/$pid/cmdline 2>/dev/null
	if [ "$cmdline" != "/bin/sh/usr/sbin/mwan4track${status_iface}" ]; then
		export -n "$1=down"
		return
	fi
	readfile started "$MWAN4TRACK_STATUS_DIR/$status_iface/STARTED"
	case "$started" in
		0)
			export -n "$1=paused"
			;;
		1)
			export -n "$1=active"
			;;
		*)
			export -n "$1=down"
			;;
	esac
}

mwan4_init()
{
	local bitcnt mmdefault source_routing

	config_load mwan4

	[ -d $MWAN4_STATUS_DIR ] || mkdir -p $MWAN4_STATUS_DIR/iface_state
	[ -d "$MWAN4_STATUS_NFT_LOG_DIR" ] || mkdir -p "$MWAN4_STATUS_NFT_LOG_DIR"

	# mwan4's MARKing mask (at least 3 bits should be set)
	if [ -e "${MWAN4_STATUS_DIR}/mmx_mask" ]; then
		readfile MMX_MASK "${MWAN4_STATUS_DIR}/mmx_mask"
		MWAN4_INTERFACE_MAX=$(uci_get_state mwan4 globals iface_max)
	else
		config_get MMX_MASK globals mmx_mask '0xFF00'
		echo "$MMX_MASK"| tr 'A-F' 'a-f' > "${MWAN4_STATUS_DIR}/mmx_mask"
		LOG debug "Using firewall mask ${MMX_MASK}"

		bitcnt=$(mwan4_count_one_bits MMX_MASK)
		mmdefault=$(((1<<bitcnt)-1))
		MWAN4_INTERFACE_MAX=$((mmdefault-3))
		uci_toggle_state mwan4 globals iface_max "$MWAN4_INTERFACE_MAX"
		LOG debug "Max interface count is ${MWAN4_INTERFACE_MAX}"
	fi

	# remove "linkdown", expiry and source based routing modifiers from route lines
	config_get_bool source_routing globals source_routing 0
	[ $source_routing -eq 1 ] && unset source_routing
	MWAN4_ROUTE_LINE_EXP="s/offload//; s/linkdown //; s/expires [0-9]\+sec//; s/error [0-9]\+//; ${source_routing:+s/default\(.*\) from [^ ]*/default\1/;} p"

	# mark mask constants
	bitcnt=$(mwan4_count_one_bits MMX_MASK)
	mmdefault=$(((1<<bitcnt)-1))
	MM_BLACKHOLE=$((mmdefault-2))
	MM_UNREACHABLE=$((mmdefault-1))

	# MMX_DEFAULT should equal MMX_MASK
	MMX_DEFAULT=$(mwan4_id2mask mmdefault MMX_MASK)
	MMX_BLACKHOLE=$(mwan4_id2mask MM_BLACKHOLE MMX_MASK)
	MMX_UNREACHABLE=$(mwan4_id2mask MM_UNREACHABLE MMX_MASK)
}

# maps the 1st parameter so it only uses the bits allowed by the bitmask (2nd parameter)
# which means spreading the bits of the 1st parameter to only use the bits that are set to 1 in the 2nd parameter
# 0 0 0 0 0 1 0 1 (0x05) 1st parameter
# 1 0 1 0 1 0 1 0 (0xAA) 2nd parameter
#     1   0   1          result
mwan4_id2mask()
{
	local bit_msk bit_val result
	bit_val=0
	result=0
	for bit_msk in $(seq 0 31); do
		if [ $((($2>>bit_msk)&1)) = "1" ]; then
			if [ $((($1>>bit_val)&1)) = "1" ]; then
				result=$((result|(1<<bit_msk)))
			fi
			bit_val=$((bit_val+1))
		fi
	done
	printf "0x%x" $result
}

# counts how many bits are set to 1
# n&(n-1) clears the lowest bit set to 1
mwan4_count_one_bits()
{
	local count n
	count=0
	n=$(($1))
	while [ "$n" -gt "0" ]; do
		n=$((n&(n-1)))
		count=$((count+1))
	done
	echo $count
}

get_uptime() {
	local _tmp
	readfile _tmp /proc/uptime
	if [ $# -eq 0 ]; then
		echo "${_tmp%%.*}"
	else
		export -n "$1=${_tmp%%.*}"
	fi
}

get_online_time() {
	local time_n time_u iface
	iface="$2"
	readfile time_u "$MWAN4TRACK_STATUS_DIR/${iface}/ONLINE" 2>/dev/null
	[ -z "${time_u}" ] || [ "${time_u}" = "0" ] || {
		get_uptime time_n
		export -n "$1=$((time_n-time_u))"
	}
}
