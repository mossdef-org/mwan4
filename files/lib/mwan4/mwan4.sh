#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 MOSSDeF, Stan Grishin (stangri@melmac.ca).
# Based on original mwan3 by Florian Eckert <fe@dev.tdt.de>

. "${IPKG_INSTROOT}/usr/share/libubox/jshn.sh"
. "${IPKG_INSTROOT}/lib/mwan4/common.sh"

CONNTRACK_FILE="/proc/net/nf_conntrack"
IPv6_REGEX="([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
IPv6_REGEX="${IPv6_REGEX}([0-9a-fA-F]{1,4}:){1,7}:|"
IPv6_REGEX="${IPv6_REGEX}([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
IPv6_REGEX="${IPv6_REGEX}([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
IPv6_REGEX="${IPv6_REGEX}([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
IPv6_REGEX="${IPv6_REGEX}([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
IPv6_REGEX="${IPv6_REGEX}([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
IPv6_REGEX="${IPv6_REGEX}[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
IPv6_REGEX="${IPv6_REGEX}:((:[0-9a-fA-F]{1,4}){1,7}|:)|"
IPv6_REGEX="${IPv6_REGEX}fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
IPv6_REGEX="${IPv6_REGEX}::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|"
IPv6_REGEX="${IPv6_REGEX}([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])"
IPv4_REGEX="((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"

DEFAULT_LOWEST_METRIC=256

# nftables helper - writes to nft file (adds to fw4 table)
mwan4_nft_write()
{
	# Writes nft commands to the appropriate file
	# All commands add to table inet fw4 (shared with firewall4/pbr)
	local file="$1"
	shift
	echo "$@" >> "$file"
}

mwan4_update_dev_to_table()
{
	local _tid
	# shellcheck disable=SC2034
	mwan4_dev_tbl_ipv4=" "
	# shellcheck disable=SC2034
	mwan4_dev_tbl_ipv6=" "

	update_table()
	{
		local family curr_table device enabled
		let _tid++
		config_get family "$1" family ipv4
		network_get_device device "$1"
		[ -z "$device" ] && return
		config_get_bool enabled "$1" enabled
		[ "$enabled" -eq 0 ] && return
		curr_table=$(eval "echo	 \"\$mwan4_dev_tbl_${family}\"")
		export "mwan4_dev_tbl_$family=${curr_table}${device}=$_tid "
	}
	network_flush_cache
	config_foreach update_table interface
}

mwan4_update_iface_to_table()
{
	local _tid
	mwan4_iface_tbl=" "
	update_table()
	{
		let _tid++
		export mwan4_iface_tbl="${mwan4_iface_tbl}${1}=$_tid "
	}
	config_foreach update_table interface
}

mwan4_route_line_dev()
{
	# must have mwan4 config already loaded
	# arg 1 is route device
	local _tid route_line route_device route_family entry curr_table
	route_line=$2
	route_family=$3
	route_device=$(echo "$route_line" | sed -ne "s/.*dev \([^ ]*\).*/\1/p")
	unset "$1"
	[ -z "$route_device" ] && return

	curr_table=$(eval "echo \"\$mwan4_dev_tbl_${route_family}\"")
	for entry in $curr_table; do
		if [ "${entry%%=*}" = "$route_device" ]; then
			_tid=${entry##*=}
			export "$1=$_tid"
			return
		fi
	done
}

mwan4_get_iface_id()
{
	local _tmp
	[ -z "$mwan4_iface_tbl" ] && mwan4_update_iface_to_table
	_tmp="${mwan4_iface_tbl##* ${2}=}"
	_tmp=${_tmp%% *}
	export "$1=$_tmp"
}

# nftables set management - custom networks
mwan4_set_custom_nftset_v4()
{
	local custom_network_v4 file="$1" table_id="$2"
	local marker_v4="${nftTempFile}.custom_v4_marker"

	for custom_network_v4 in $($IP4 route list table "$table_id" | awk '{print $1}' | grep -E "$IPv4_REGEX"); do
		LOG notice "Adding network $custom_network_v4 from table $table_id to ${nftPrefix}_custom_ipv4 set"
		echo "		$custom_network_v4," >> "$file"
		touch "$marker_v4"
	done
}

mwan4_set_custom_nftset_v6()
{
	local custom_network_v6 file="$1" table_id="$2"
	local marker_v6="${nftTempFile}.custom_v6_marker"

	for custom_network_v6 in $($IP6 route list table "$table_id" | awk '{print $1}' | grep -E "$IPv6_REGEX"); do
		LOG notice "Adding network $custom_network_v6 from table $table_id to ${nftPrefix}_custom_ipv6 set"
		echo "		$custom_network_v6," >> "$file"
		touch "$marker_v6"
	done
}

mwan4_set_custom_nftset()
{
	local tmpfile="${nftTempFile}.custom_sets"
	local marker_v4="${nftTempFile}.custom_v4_marker"
	local marker_v6="${nftTempFile}.custom_v6_marker"

	# Clean markers
	rm -f "$marker_v4" "$marker_v6"

	# Create nft set definitions in fw4 table
	cat > "$tmpfile" <<EOF
# Custom network sets for routing table lookups
table inet ${nftTable} {
	set ${nftPrefix}_custom_ipv4 {
		type ipv4_addr
		flags interval
		auto-merge
		elements = {
EOF

	config_list_foreach "globals" "rt_table_lookup" mwan4_set_custom_nftset_v4 "$tmpfile"

	# Add placeholder if no custom IPv4 networks found
	[ ! -f "$marker_v4" ] && echo "			127.0.0.1," >> "$tmpfile"

	cat >> "$tmpfile" <<EOF
		}
	}
EOF

	if [ $NO_IPV6 -eq 0 ]; then
		cat >> "$tmpfile" <<EOF

	set ${nftPrefix}_custom_ipv6 {
		type ipv6_addr
		flags interval
		auto-merge
		elements = {
EOF
		config_list_foreach "globals" "rt_table_lookup" mwan4_set_custom_nftset_v6 "$tmpfile"

		# Add placeholder if no custom IPv6 networks found
		[ ! -f "$marker_v6" ] && echo "			::1," >> "$tmpfile"

		cat >> "$tmpfile" <<EOF
		}
	}
EOF
	fi

	echo "}" >> "$tmpfile"

	# Apply the nft rules
	$nft -f "$tmpfile" 2>&1 | logger -t "${SCRIPTNAME}[$$]" -p error || LOG error "set_custom_nftset failed"
	rm -f "$tmpfile" "$marker_v4" "$marker_v6"
}

mwan4_set_connected_ipv4()
{
	local connected_network_v4
	local candidate_list cidr_list
	local tmpfile="${nftTempFile}.connected_v4"

	candidate_list=""
	cidr_list=""
	route_lists()
	{
		$IP4 route | awk '{print $1}'
		$IP4 route list table 0 | awk '{print $2}'
	}
	for connected_network_v4 in $(route_lists | grep -E "$IPv4_REGEX"); do
		if [ -z "${connected_network_v4##*/*}" ]; then
			cidr_list="$cidr_list $connected_network_v4"
		else
			candidate_list="$candidate_list $connected_network_v4"
		fi
	done

	# Create nft set in fw4 table
	cat > "$tmpfile" <<EOF
table inet ${nftTable} {
	set ${nftPrefix}_connected_ipv4 {
		type ipv4_addr
		flags interval
		auto-merge
		elements = {
EOF

	for connected_network_v4 in $cidr_list; do
		echo "			$connected_network_v4," >> "$tmpfile"
	done
	for connected_network_v4 in $candidate_list; do
		echo "			$connected_network_v4," >> "$tmpfile"
	done
	echo "			224.0.0.0/3" >> "$tmpfile"

	cat >> "$tmpfile" <<EOF
		}
	}
}
EOF

	$nft -f "$tmpfile" 2>&1 | logger -t "${SCRIPTNAME}[$$]" -p error || LOG error "set_connected_ipv4 failed"
	rm -f "$tmpfile"
}

mwan4_set_connected_ipv6()
{
	local connected_network_v6
	local tmpfile="${nftTempFile}.connected_v6"
	local has_elements=0

	[ $NO_IPV6 -eq 0 ] || return

	cat > "$tmpfile" <<EOF
table inet ${nftTable} {
	set ${nftPrefix}_connected_ipv6 {
		type ipv6_addr
		flags interval
		auto-merge
		elements = {
EOF

	for connected_network_v6 in $($IP6 route | awk '{print $1}' | grep -E "$IPv6_REGEX"); do
		echo "			$connected_network_v6," >> "$tmpfile"
		has_elements=1
	done

	# Add placeholder if no elements found to avoid empty set syntax error
	[ $has_elements -eq 0 ] && echo "			::1," >> "$tmpfile"

	cat >> "$tmpfile" <<EOF
		}
	}
}
EOF

	$nft -f "$tmpfile" 2>&1 | logger -t "${SCRIPTNAME}[$$]" -p error || LOG error "set_connected_ipv6 failed"
	rm -f "$tmpfile"
}

mwan4_set_connected_nftset()
{
	# Initialize empty sets
	local tmpfile="${nftTempFile}.connected_init"

	cat > "$tmpfile" <<EOF
table inet ${nftTable} {
	set ${nftPrefix}_connected_ipv4 {
		type ipv4_addr
		flags interval
		auto-merge
	}
EOF

	if [ $NO_IPV6 -eq 0 ]; then
		cat >> "$tmpfile" <<EOF

	set ${nftPrefix}_connected_ipv6 {
		type ipv6_addr
		flags interval
		auto-merge
	}
EOF
	fi

	echo "}" >> "$tmpfile"

	$nft -f "$tmpfile" 2>&1 | logger -t "${SCRIPTNAME}[$$]" -p error || LOG error "set_connected_nftset failed"
	rm -f "$tmpfile"
}

mwan4_set_dynamic_nftset()
{
	# Initialize empty dynamic sets
	local tmpfile="${nftTempFile}.dynamic_init"

	cat > "$tmpfile" <<EOF
table inet ${nftTable} {
	set ${nftPrefix}_dynamic_ipv4 {
		type ipv4_addr
		flags interval
		auto-merge
	}
EOF

	if [ $NO_IPV6 -eq 0 ]; then
		cat >> "$tmpfile" <<EOF

	set ${nftPrefix}_dynamic_ipv6 {
		type ipv6_addr
		flags interval
		auto-merge
	}
EOF
	fi

	echo "}" >> "$tmpfile"

	$nft -f "$tmpfile" 2>&1 | logger -t "${SCRIPTNAME}[$$]" -p error || LOG error "set_dynamic_nftset failed"
	rm -f "$tmpfile"
}

mwan4_set_general_rules()
{
	local IP

	for IP in "$IP4" "$IP6"; do
		[ "$IP" = "$IP6" ] && [ $NO_IPV6 -ne 0 ] && continue
		RULE_NO=$((MM_BLACKHOLE+2000))
		if [ -z "$($IP rule list | awk -v var="$RULE_NO:" '$1 == var')" ]; then
			$IP rule add pref $RULE_NO fwmark $MMX_BLACKHOLE/$MMX_MASK blackhole
		fi

		RULE_NO=$((MM_UNREACHABLE+2000))
		if [ -z "$($IP rule list | awk -v var="$RULE_NO:" '$1 == var')" ]; then
			$IP rule add pref $RULE_NO fwmark $MMX_UNREACHABLE/$MMX_MASK unreachable
		fi
	done
}

mwan4_set_general_nftables()
{
	# Create base nftables structure in fw4 table
	local tmpfile="$nftMainFile"
	local family

	cat > "$tmpfile" <<EOF
# mwan4 base chains and sets in shared fw4 table
# IMPORTANT: Uses table inet fw4 (shared with firewall4/pbr)
table inet ${nftTable} {
	# Base sets
	set ${nftPrefix}_connected_ipv4 {
		type ipv4_addr
		flags interval
		auto-merge
	}

	set ${nftPrefix}_custom_ipv4 {
		type ipv4_addr
		flags interval
		auto-merge
	}

	set ${nftPrefix}_dynamic_ipv4 {
		type ipv4_addr
		flags interval
		auto-merge
	}
EOF

	if [ $NO_IPV6 -eq 0 ]; then
		cat >> "$tmpfile" <<EOF

	set ${nftPrefix}_connected_ipv6 {
		type ipv6_addr
		flags interval
		auto-merge
	}

	set ${nftPrefix}_custom_ipv6 {
		type ipv6_addr
		flags interval
		auto-merge
	}

	set ${nftPrefix}_dynamic_ipv6 {
		type ipv6_addr
		flags interval
		auto-merge
	}
EOF
	fi

	cat >> "$tmpfile" <<EOF

	# Base chains
	chain ${nftPrefix}_ifaces_in {
	}

	chain ${nftPrefix}_rules {
	}

	# Main hook chain at mangle priority
	chain ${nftPrefix}_prerouting {
		type filter hook prerouting priority mangle; policy accept;

		# IPv6 Router Advertisement exemptions
		ip6 nexthdr icmpv6 icmpv6 type {
			nd-router-solicit,
			nd-router-advert,
			nd-neighbor-solicit,
			nd-neighbor-advert,
			nd-redirect
		} return

		# Restore mark from conntrack
		meta mark & $MMX_MASK == 0 ct mark set meta mark & $MMX_MASK

		# Interface input processing
		meta mark & $MMX_MASK == 0 jump ${nftPrefix}_ifaces_in

		# Custom/connected/dynamic set matching
		meta mark & $MMX_MASK == 0 ${nftIPv4Flag} daddr @${nftPrefix}_custom_ipv4 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
		meta mark & $MMX_MASK == 0 ${nftIPv4Flag} daddr @${nftPrefix}_connected_ipv4 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
		meta mark & $MMX_MASK == 0 ${nftIPv4Flag} daddr @${nftPrefix}_dynamic_ipv4 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
EOF

	if [ $NO_IPV6 -eq 0 ]; then
		cat >> "$tmpfile" <<EOF
		meta mark & $MMX_MASK == 0 ${nftIPv6Flag} daddr @${nftPrefix}_custom_ipv6 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
		meta mark & $MMX_MASK == 0 ${nftIPv6Flag} daddr @${nftPrefix}_connected_ipv6 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
		meta mark & $MMX_MASK == 0 ${nftIPv6Flag} daddr @${nftPrefix}_dynamic_ipv6 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
EOF
	fi

	cat >> "$tmpfile" <<EOF

		# User rules
		meta mark & $MMX_MASK == 0 jump ${nftPrefix}_rules

		# Save mark to conntrack
		ct mark set meta mark & $MMX_MASK

		# Post-marking custom/connected/dynamic checks
		meta mark != $MMX_DEFAULT & $MMX_MASK ${nftIPv4Flag} daddr @${nftPrefix}_custom_ipv4 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
		meta mark != $MMX_DEFAULT & $MMX_MASK ${nftIPv4Flag} daddr @${nftPrefix}_connected_ipv4 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
		meta mark != $MMX_DEFAULT & $MMX_MASK ${nftIPv4Flag} daddr @${nftPrefix}_dynamic_ipv4 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
EOF

	if [ $NO_IPV6 -eq 0 ]; then
		cat >> "$tmpfile" <<EOF
		meta mark != $MMX_DEFAULT & $MMX_MASK ${nftIPv6Flag} daddr @${nftPrefix}_custom_ipv6 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
		meta mark != $MMX_DEFAULT & $MMX_MASK ${nftIPv6Flag} daddr @${nftPrefix}_connected_ipv6 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
		meta mark != $MMX_DEFAULT & $MMX_MASK ${nftIPv6Flag} daddr @${nftPrefix}_dynamic_ipv6 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
EOF
	fi

	cat >> "$tmpfile" <<EOF
	}

	# Output chain
	chain ${nftPrefix}_output {
		type route hook output priority mangle; policy accept;

		# IPv6 Router Advertisement exemptions
		ip6 nexthdr icmpv6 icmpv6 type {
			nd-router-solicit,
			nd-router-advert,
			nd-neighbor-solicit,
			nd-neighbor-advert,
			nd-redirect
		} return

		meta mark & $MMX_MASK == 0 ct mark set meta mark & $MMX_MASK
		meta mark & $MMX_MASK == 0 jump ${nftPrefix}_ifaces_in
		meta mark & $MMX_MASK == 0 ${nftIPv4Flag} daddr @${nftPrefix}_custom_ipv4 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
		meta mark & $MMX_MASK == 0 ${nftIPv4Flag} daddr @${nftPrefix}_connected_ipv4 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
		meta mark & $MMX_MASK == 0 ${nftIPv4Flag} daddr @${nftPrefix}_dynamic_ipv4 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
EOF

	if [ $NO_IPV6 -eq 0 ]; then
		cat >> "$tmpfile" <<EOF
		meta mark & $MMX_MASK == 0 ${nftIPv6Flag} daddr @${nftPrefix}_custom_ipv6 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
		meta mark & $MMX_MASK == 0 ${nftIPv6Flag} daddr @${nftPrefix}_connected_ipv6 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
		meta mark & $MMX_MASK == 0 ${nftIPv6Flag} daddr @${nftPrefix}_dynamic_ipv6 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
EOF
	fi

	cat >> "$tmpfile" <<EOF
		meta mark & $MMX_MASK == 0 jump ${nftPrefix}_rules
		ct mark set meta mark & $MMX_MASK
		meta mark != $MMX_DEFAULT & $MMX_MASK ${nftIPv4Flag} daddr @${nftPrefix}_custom_ipv4 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
		meta mark != $MMX_DEFAULT & $MMX_MASK ${nftIPv4Flag} daddr @${nftPrefix}_connected_ipv4 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
		meta mark != $MMX_DEFAULT & $MMX_MASK ${nftIPv4Flag} daddr @${nftPrefix}_dynamic_ipv4 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
EOF

	if [ $NO_IPV6 -eq 0 ]; then
		cat >> "$tmpfile" <<EOF
		meta mark != $MMX_DEFAULT & $MMX_MASK ${nftIPv6Flag} daddr @${nftPrefix}_custom_ipv6 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
		meta mark != $MMX_DEFAULT & $MMX_MASK ${nftIPv6Flag} daddr @${nftPrefix}_connected_ipv6 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
		meta mark != $MMX_DEFAULT & $MMX_MASK ${nftIPv6Flag} daddr @${nftPrefix}_dynamic_ipv6 meta mark set (meta mark & ~$MMX_MASK) | $MMX_DEFAULT
EOF
	fi

	cat >> "$tmpfile" <<EOF
	}
}
EOF

	LOG info "Created base nftables structure in $tmpfile"
}

mwan4_create_iface_nftables_family()
{
	local id family nftflag current tmpfile error iface device chain_name

	iface="$1"
	device="$2"
	family="$3"

	mwan4_get_iface_id id "$iface"

	[ -n "$id" ] || return 0

	if [ "$family" = "ipv4" ]; then
		nftflag="$nftIPv4Flag"
	elif [ "$family" = "ipv6" ] && [ $NO_IPV6 -eq 0 ]; then
		nftflag="$nftIPv6Flag"
	else
		return
	fi

	# Use family suffix for dual-stack interfaces
	chain_name="${nftPrefix}_iface_in_${iface}_${family}"

	tmpfile="${nftIfaceFile}.tmp"

	# Create interface-specific chain
	cat > "$tmpfile" <<EOF
table inet ${nftTable} {
	chain ${chain_name} {
EOF

	# Add rules for custom/connected/dynamic sets
	for settype in custom connected dynamic; do
		cat >> "$tmpfile" <<EOF
		iifname "${device}" ${nftflag} saddr @${nftPrefix}_${settype}_${family} meta mark & $MMX_MASK == 0 meta mark set $MMX_DEFAULT comment "default"
EOF
	done

	# Add interface-specific marking rule
	cat >> "$tmpfile" <<EOF
		iifname "${device}" meta mark & $MMX_MASK == 0 meta mark set $(mwan4_id2mask id MMX_MASK) comment "${iface}"
	}
}
EOF

	# Apply the nftables configuration
	error=$($nft -f "$tmpfile" 2>&1) || {
		LOG error "create_iface_nftables_family (${iface}_${family}): $error"
		return 1
	}

	# Add jump to this chain from mwan4_ifaces_in if not already present
	if [ -z "$($nft -a list chain inet ${nftTable} ${nftPrefix}_ifaces_in 2>/dev/null | grep "jump ${chain_name}")" ]; then
		$nft add rule inet ${nftTable} ${nftPrefix}_ifaces_in meta mark \& $MMX_MASK == 0 ${nftflag} jump ${chain_name} 2>&1 | logger -t "${SCRIPTNAME}[$$]" -p error
		LOG debug "create_iface_nftables_family: ${chain_name} not in nftables, adding"
	else
		LOG debug "create_iface_nftables_family: ${chain_name} already in nftables, skip"
	fi

	rm -f "$tmpfile"
}

mwan4_create_iface_nftables()
{
	local iface="$1"
	local device="$2"

	# Create chains for each family configured on this interface
	mwan4_foreach_family "$iface" mwan4_create_iface_nftables_family "$device"
}

mwan4_delete_iface_nftables_family()
{
	local iface family nftflag error handle chain_name

	iface="$1"
	family="$2"

	if [ "$family" = "ipv4" ]; then
		nftflag="$nftIPv4Flag"
	elif [ "$family" = "ipv6" ]; then
		[ $NO_IPV6 -ne 0 ] && return
		nftflag="$nftIPv6Flag"
	else
		return
	fi

	# Use family suffix for dual-stack interfaces
	chain_name="${nftPrefix}_iface_in_${iface}_${family}"

	# Find and delete the jump rule from mwan4_ifaces_in chain
	handle=$($nft -a list chain inet ${nftTable} ${nftPrefix}_ifaces_in 2>/dev/null | \
		grep "jump ${chain_name}" | \
		sed -n 's/.*# handle \([0-9]*\)$/\1/p')

	if [ -n "$handle" ]; then
		$nft delete rule inet ${nftTable} ${nftPrefix}_ifaces_in handle $handle 2>&1 | \
			logger -t "${SCRIPTNAME}[$$]" -p error
	fi

	# Delete the interface-specific chain
	$nft delete chain inet ${nftTable} ${chain_name} 2>&1 | \
		logger -t "${SCRIPTNAME}[$$]" -p error
}

mwan4_delete_iface_nftables()
{
	local iface="$1"

	# Delete chains for each family configured on this interface
	mwan4_foreach_family "$iface" mwan4_delete_iface_nftables_family
}

mwan4_extra_tables_routes()
{
	$IP route list table "$1"
}

mwan4_get_routes()
{
	{
		$IP route list table main
		config_list_foreach "globals" "rt_table_lookup" mwan4_extra_tables_routes
	} | sed -ne "$MWAN4_ROUTE_LINE_EXP" | sort -u
}

mwan4_create_iface_route_family()
{
	local tid route_line family IP id tbl iface
	iface="$1"
	family="$2"

	mwan4_get_iface_id id "$iface"

	[ -n "$id" ] || return 0

	if [ "$family" = "ipv4" ]; then
		IP="$IP4"
	elif [ "$family" = "ipv6" ]; then
		IP="$IP6"
	fi

	tbl=$($IP route list table $id 2>/dev/null)$'\n'
	mwan4_update_dev_to_table
	mwan4_get_routes | while read -r route_line; do
		mwan4_route_line_dev "tid" "$route_line" "$family"
		{ [ -z "${route_line##default*}" ] || [ -z "${route_line##fe80::/64*}" ]; } && [ "$tid" != "$id" ] && continue
		if [ -z "$tid" ] || [ "$tid" = "$id" ]; then
			# possible that routes are already in the table
			# if 'connected' was called after 'ifup'
			[ -n "$tbl" ] && [ -z "${tbl##*$route_line$'\n'*}" ] && continue
			$IP route add table $id $route_line ||
				LOG debug "Route '$route_line' already added to table $id"
		fi

	done
}

mwan4_create_iface_route()
{
	local iface="$1"

	# Create routes for each family - they share the same table but use different IP commands
	mwan4_foreach_family "$iface" mwan4_create_iface_route_family
}

mwan4_delete_iface_route_family()
{
	local id family iface

	iface="$1"
	family="$2"

	mwan4_get_iface_id id "$iface"

	if [ -z "$id" ]; then
		LOG warn "delete_iface_route_family: could not find table id for interface $iface"
		return 0
	fi

	if [ "$family" = "ipv4" ]; then
		$IP4 route flush table "$id"
	elif [ "$family" = "ipv6" ] && [ $NO_IPV6 -eq 0 ]; then
		$IP6 route flush table "$id"
	fi
}

mwan4_delete_iface_route()
{
	local iface="$1"

	# Delete routes for each family
	mwan4_foreach_family "$iface" mwan4_delete_iface_route_family
}

mwan4_create_iface_rules_family()
{
	local id family IP iface device

	iface="$1"
	family="$2"
	device="$3"

	mwan4_get_iface_id id "$iface"

	[ -n "$id" ] || return 0

	if [ "$family" = "ipv4" ]; then
		IP="$IP4"
	elif [ "$family" = "ipv6" ] && [ $NO_IPV6 -eq 0 ]; then
		IP="$IP6"
	else
		return
	fi

	mwan4_delete_iface_rules_family "$iface" "$family"

	$IP rule add pref $((id+1000)) iif "$device" lookup "$id"
	$IP rule add pref $((id+2000)) fwmark "$(mwan4_id2mask id MMX_MASK)/$MMX_MASK" lookup "$id"
	$IP rule add pref $((id+3000)) fwmark "$(mwan4_id2mask id MMX_MASK)/$MMX_MASK" unreachable
}

mwan4_create_iface_rules()
{
	local iface="$1"
	local device="$2"

	# Create rules for each family
	mwan4_foreach_family "$iface" mwan4_create_iface_rules_family "$device"
}

mwan4_delete_iface_rules_family()
{
	local id family IP rule_id iface

	iface="$1"
	family="$2"

	mwan4_get_iface_id id "$iface"

	[ -n "$id" ] || return 0

	if [ "$family" = "ipv4" ]; then
		IP="$IP4"
	elif [ "$family" = "ipv6" ] && [ $NO_IPV6 -eq 0 ]; then
		IP="$IP6"
	else
		return
	fi

	for rule_id in $($IP rule list | awk -F : '$1 % 1000 == '$id' && $1 > 1000 && $1 < 4000 {print $1}'); do
		$IP rule del pref $rule_id
	done
}

mwan4_delete_iface_rules()
{
	local iface="$1"

	# Delete rules for each family
	mwan4_foreach_family "$iface" mwan4_delete_iface_rules_family
}

mwan4_delete_iface_nftset_entries()
{
	local id setname entry mask_hex

	mwan4_get_iface_id id "$1"

	[ -n "$id" ] || return 0

	mask_hex=$(mwan4_id2mask id MMX_MASK | awk '{ printf "0x%08x", $1; }')

	# Get all sets that start with mwan4_rule_
	for setname in $($nft -j list sets inet ${nftTable} | jsonfilter -e '@.nftables[@.set.name]' | grep "^${nftPrefix}_rule_"); do
		# List elements in the set and find ones matching our interface mark
		$nft -j list set inet ${nftTable} "$setname" | \
			jsonfilter -e '@.nftables[*].set.elem[*]' | \
			grep "$mask_hex" | \
			while read -r entry; do
				$nft delete element inet ${nftTable} "$setname" "{ $entry }" 2>&1 | \
					logger -t "${SCRIPTNAME}[$$]" -p notice
			done
	done
}

mwan4_set_policy()
{
	local id iface family metric weight device is_lowest is_offline nftflag total_weight

	is_lowest=0
	config_get iface "$1" interface
	config_get metric "$1" metric 1
	config_get weight "$1" weight 1

	[ -n "$iface" ] || return 0
	network_get_device device "$iface"
	[ "$metric" -gt $DEFAULT_LOWEST_METRIC ] && LOG warn "Member interface $iface has >$DEFAULT_LOWEST_METRIC metric. Not appending to policy" && return 0

	mwan4_get_iface_id id "$iface"

	[ -n "$id" ] || return 0

	[ "$(mwan4_get_iface_hotplug_state "$iface")" = "online" ]
	is_offline=$?

	config_get family "$iface" family ipv4

	if [ "$family" = "ipv4" ]; then
		nftflag="$nftIPv4Flag"
	elif [ "$family" = "ipv6" ]; then
		nftflag="$nftIPv6Flag"
	fi

	if [ "$family" = "ipv4" ] && [ $is_offline -eq 0 ]; then
		if [ "$metric" -lt "$lowest_metric_v4" ]; then
			is_lowest=1
			total_weight_v4=$weight
			lowest_metric_v4=$metric
		elif [ "$metric" -eq "$lowest_metric_v4" ]; then
			total_weight_v4=$((total_weight_v4+weight))
			total_weight=$total_weight_v4
		else
			return
		fi
	elif [ "$family" = "ipv6" ] && [ $NO_IPV6 -eq 0 ] && [ $is_offline -eq 0 ]; then
		if [ "$metric" -lt "$lowest_metric_v6" ]; then
			is_lowest=1
			total_weight_v6=$weight
			lowest_metric_v6=$metric
		elif [ "$metric" -eq "$lowest_metric_v6" ]; then
			total_weight_v6=$((total_weight_v6+weight))
			total_weight=$total_weight_v6
		else
			return
		fi
	fi

	# Store policy member info for later nftables generation
	if [ $is_lowest -eq 1 ]; then
		# First member with lowest metric - will flush and recreate chain
		echo "flush:$iface:$weight:$weight:$(mwan4_id2mask id MMX_MASK)" >> "${nftTempFile}.policy_${policy}_${family}"
	elif [ $is_offline -eq 0 ]; then
		# Additional member - load balancing using numgen
		echo "member:$iface:$weight:$total_weight:$(mwan4_id2mask id MMX_MASK)" >> "${nftTempFile}.policy_${policy}_${family}"
	elif [ -n "$device" ]; then
		# Offline member - add device-based default marking
		echo "offline:$iface:$device" >> "${nftTempFile}.policy_${policy}_${family}"
	fi
}

mwan4_create_policies_nftables()
{
	local last_resort lowest_metric_v4 lowest_metric_v6 total_weight_v4 total_weight_v6 policy tmpfile error
	local family nftflag line action iface weight total_weight mark device
	local cumulative_weight mod_value last_resort_mark

	policy="$1"

	config_get last_resort "$1" last_resort unreachable

	if [ "$1" != "$(echo "$1" | cut -c1-15)" ]; then
		LOG warn "Policy $1 exceeds max of 15 chars. Not setting policy" && return 0
	fi

	# Determine last_resort mark
	case "$last_resort" in
		blackhole)
			last_resort_mark="$MMX_BLACKHOLE"
			;;
		default)
			last_resort_mark="$MMX_DEFAULT"
			;;
		*)
			last_resort_mark="$MMX_UNREACHABLE"
			;;
	esac

	tmpfile="${nftPolicyFile}.tmp"

	# Start building the policy chains
	cat > "$tmpfile" <<EOF
table inet ${nftTable} {
EOF

	for family in ipv4 ipv6; do
		[ "$family" = "ipv6" ] && [ $NO_IPV6 -ne 0 ] && continue

		if [ "$family" = "ipv4" ]; then
			nftflag="$nftIPv4Flag"
		else
			nftflag="$nftIPv6Flag"
		fi

		# Create the policy chain
		cat >> "$tmpfile" <<EOF
	chain ${nftPrefix}_policy_${policy}_${family} {
		meta mark & $MMX_MASK == 0 meta mark set $last_resort_mark comment "$last_resort"
EOF

		# Process members if temp file exists
		if [ -f "${nftTempFile}.policy_${policy}_${family}" ]; then
			cumulative_weight=0
			total_weight=0

			# First pass: calculate total weight
			while IFS=: read -r action iface weight total mark device; do
				[ "$action" = "member" ] && total_weight=$total
			done < "${nftTempFile}.policy_${policy}_${family}"

			# Second pass: generate load balancing rules
			while IFS=: read -r action iface weight total mark device; do
				case "$action" in
					flush)
						# Just note it's the first member, already handled by chain creation
						cumulative_weight=$weight
						cat >> "$tmpfile" <<EOF
		meta mark & $MMX_MASK == 0 meta mark set $mark comment "$iface $weight $weight"
EOF
						;;
					member)
						# Load balancing with numgen
						mod_value=$total_weight
						cat >> "$tmpfile" <<EOF
		meta mark & $MMX_MASK == 0 numgen random mod $mod_value < $cumulative_weight meta mark set $mark comment "$iface $weight $total_weight"
EOF
						cumulative_weight=$((cumulative_weight + weight))
						;;
					offline)
						# Check if any online member exists before adding offline rule
					# Also ensure device is non-empty to avoid nftables syntax error
						if [ -n "$device" ] && \
					   ! grep -q "^member:" "${nftTempFile}.policy_${policy}_${family}" && \
					   ! grep -q "^flush:" "${nftTempFile}.policy_${policy}_${family}"; then
							cat >> "$tmpfile" <<EOF
		oifname "$device" meta mark & $MMX_MASK == 0 meta mark set $MMX_DEFAULT comment "out $iface $device"
EOF
						fi
						;;
				esac
			done < "${nftTempFile}.policy_${policy}_${family}"

			rm -f "${nftTempFile}.policy_${policy}_${family}"
		fi

		cat >> "$tmpfile" <<EOF
	}
EOF
	done

	cat >> "$tmpfile" <<EOF
}
EOF

	# Apply the nftables configuration
	error=$($nft -f "$tmpfile" 2>&1) || {
		LOG error "create_policies_nftables ($1): $error"
		rm -f "$tmpfile"
		return 1
	}

	rm -f "$tmpfile"

	# Now process the members to populate the chains
	lowest_metric_v4=$DEFAULT_LOWEST_METRIC
	total_weight_v4=0

	lowest_metric_v6=$DEFAULT_LOWEST_METRIC
	total_weight_v6=0

	config_list_foreach "$1" use_member mwan4_set_policy
}

mwan4_set_policies_nftables()
{
	config_foreach mwan4_create_policies_nftables policy
}

mwan4_set_sticky_nftables()
{
	local interface="${1}"
	local rule="${2}"
	local family="${3}"
	local policy="${4}"

	local id iface nftflag mark

	# Check if this interface is in the policy
	if $nft list chain inet ${nftTable} ${nftPrefix}_policy_${policy}_${family} 2>/dev/null | grep -q "comment \"$interface"; then
		mwan4_get_iface_id id "$interface"

		[ -n "$id" ] || return 0

		mark=$(mwan4_id2mask id MMX_MASK)

		# Check if the interface chain exists
		if $nft list chain inet ${nftTable} ${nftPrefix}_iface_in_${interface} >/dev/null 2>&1; then
			# Add sticky session rules to the rule chain
			# These will be added to the rule-specific chain during user rule processing
			echo "sticky:$interface:$mark:$family" >> "${nftTempFile}.rule_${rule}_sticky"
		fi
	fi
}

mwan4_set_sticky_nftset()
{
	local rule="$1"
	local mmx="$2"
	local timeout="$3"
	local tmpfile error

	tmpfile="${nftTempFile}.sticky_sets"

	# Create nftables sets for sticky sessions (maps IP+mark to timeout)
	cat > "$tmpfile" <<EOF
table inet ${nftTable} {
	set ${nftPrefix}_rule_ipv4_${rule} {
		type ipv4_addr . mark
		flags timeout
		timeout ${timeout}s
	}
EOF

	if [ $NO_IPV6 -eq 0 ]; then
		cat >> "$tmpfile" <<EOF
	set ${nftPrefix}_rule_ipv6_${rule} {
		type ipv6_addr . mark
		flags timeout
		timeout ${timeout}s
	}
EOF
	fi

	cat >> "$tmpfile" <<EOF
}
EOF

	error=$($nft -f "$tmpfile" 2>&1) || {
		LOG error "set_sticky_nftset (${rule}): $error"
	}
	rm -f "$tmpfile"
}

mwan4_set_user_nftables_rule()
{
	local ipset family proto policy src_ip src_port src_iface src_dev
	local sticky dest_ip dest_port use_policy timeout policy_name rule family_flag
	local global_logging rule_logging loglevel rule_policy nftflag
	local proto_spec src_spec dest_spec ipset_spec port_spec mark_action

	rule="$1"
	family_flag="$2"  # ipv4 or ipv6
	rule_policy=0

	config_get sticky "$1" sticky 0
	config_get timeout "$1" timeout 600
	config_get ipset "$1" ipset
	config_get proto "$1" proto all
	config_get src_ip "$1" src_ip
	config_get src_iface "$1" src_iface
	config_get src_port "$1" src_port
	config_get dest_ip "$1" dest_ip
	config_get dest_port "$1" dest_port
	config_get use_policy "$1" use_policy
	config_get family "$1" family any
	config_get rule_logging "$1" logging 0
	config_get global_logging globals logging 0
	config_get loglevel globals loglevel notice

	[ "$family_flag" = "ipv6" ] && [ $NO_IPV6 -ne 0 ] && return
	[ "$family" = "ipv4" ] && [ "$family_flag" = "ipv6" ] && return
	[ "$family" = "ipv6" ] && [ "$family_flag" = "ipv4" ] && return

	# Fix malformed IPv6 addresses BEFORE validation (UCI might strip leading :: in some cases)
	# Check for any dest_ip that looks like /0, /64, etc. without leading address
	if [ "$family_flag" = "ipv6" ]; then
		case "$dest_ip" in
			/*)
				LOG warn "Fixing malformed IPv6 dest_ip '$dest_ip' to ':$dest_ip' for rule $rule"
				dest_ip=":$dest_ip"
				;;
		esac
		case "$src_ip" in
			/*)
				LOG warn "Fixing malformed IPv6 src_ip '$src_ip' to ':$src_ip' for rule $rule"
				src_ip=":$src_ip"
				;;
		esac
	fi

	# Validate IP addresses
	for ipaddr in "$src_ip" "$dest_ip"; do
		if [ -n "$ipaddr" ] && { { [ "$family_flag" = "ipv4" ] && echo "$ipaddr" | grep -qE "$IPv6_REGEX"; } ||
						 { [ "$family_flag" = "ipv6" ] && echo "$ipaddr" | grep -qE $IPv4_REGEX; } }; then
			LOG warn "invalid $family_flag address $ipaddr specified for rule $rule"
			return
		fi
	done

	if [ -n "$src_iface" ]; then
		network_get_device src_dev "$src_iface"
		if [ -z "$src_dev" ]; then
			LOG notice "could not find device corresponding to src_iface $src_iface for rule $1"
			return
		fi
	fi

	# Clean up empty parameters
	[ -z "$dest_ip" ] && unset dest_ip
	[ -z "$src_ip" ] && unset src_ip
	[ -z "$ipset" ] && unset ipset
	[ -z "$src_port" ] && unset src_port
	[ -z "$dest_port" ] && unset dest_port

	# Validate ports
	if [ "$proto" != 'tcp' ] && [ "$proto" != 'udp' ]; then
		[ -n "$src_port" ] && {
			LOG warn "src_port set to '$src_port' but proto set to '$proto' not tcp or udp. src_port will be ignored"
		}
		[ -n "$dest_port" ] && {
			LOG warn "dest_port set to '$dest_port' but proto set to '$proto' not tcp or udp. dest_port will be ignored"
		}
		unset src_port
		unset dest_port
	fi

	if [ "$1" != "$(echo "$1" | cut -c1-15)" ]; then
		LOG warn "Rule $1 exceeds max of 15 chars. Not setting rule" && return 0
	fi

	[ -z "$use_policy" ] && return

	# Set nftflag based on family
	if [ "$family_flag" = "ipv4" ]; then
		nftflag="$nftIPv4Flag"
	else
		nftflag="$nftIPv6Flag"
	fi

	# Determine policy action
	if [ "$use_policy" = "default" ]; then
		policy_name="$use_policy"
		mark_action="meta mark set $MMX_DEFAULT"
	elif [ "$use_policy" = "unreachable" ]; then
		policy_name="$use_policy"
		mark_action="meta mark set $MMX_UNREACHABLE"
	elif [ "$use_policy" = "blackhole" ]; then
		policy_name="$use_policy"
		mark_action="meta mark set $MMX_BLACKHOLE"
	else
		rule_policy=1
		policy_name="$use_policy"
		mark_action="jump ${nftPrefix}_policy_${use_policy}_${family_flag}"
		if [ "$sticky" -eq 1 ]; then
			mwan4_set_sticky_nftset "$rule" "$MMX_MASK" "$timeout"
		fi
	fi

	# Build match criteria
	proto_spec=""
	[ "$proto" != "all" ] && proto_spec="meta l4proto $proto"

	src_spec=""
	[ -n "$src_ip" ] && src_spec="${nftflag} saddr $src_ip"
	[ -n "$src_dev" ] && src_spec="$src_spec iifname \"$src_dev\""

	dest_spec=""
	[ -n "$dest_ip" ] && dest_spec="${nftflag} daddr $dest_ip"

	ipset_spec=""
	[ -n "$ipset" ] && ipset_spec="${nftflag} daddr @$ipset"

	port_spec=""
	if [ -n "$src_port" ] && [ -n "$dest_port" ]; then
		port_spec="$proto sport { $src_port } $proto dport { $dest_port }"
	elif [ -n "$src_port" ]; then
		port_spec="$proto sport { $src_port }"
	elif [ -n "$dest_port" ]; then
		port_spec="$proto dport { $dest_port }"
	fi

	# Store rule info for later nftables generation
	if [ $rule_policy -eq 1 ] && [ "$sticky" -eq 1 ]; then
		# Sticky session rule - needs special handling
		# First collect sticky interface info to see if any interfaces match
		config_foreach mwan4_set_sticky_nftables interface "$rule" "$family_flag" "$use_policy"

		# Only create sticky rule if sticky file was created (i.e., at least one interface matched)
		if [ -f "${nftTempFile}.rule_${rule}_sticky" ]; then
			echo "sticky_rule|$rule|$family_flag|$proto_spec|$src_spec|$dest_spec|$ipset_spec|$port_spec|$policy_name|$global_logging|$rule_logging|$loglevel" >> "${nftTempFile}.user_rules"
		else
			# No interfaces matched, fall back to regular rule with policy jump
			echo "regular_rule|$rule|$family_flag|$proto_spec|$src_spec|$dest_spec|$ipset_spec|$port_spec|$mark_action|$global_logging|$rule_logging|$loglevel" >> "${nftTempFile}.user_rules"
		fi
	else
		# Regular rule
		echo "regular_rule|$rule|$family_flag|$proto_spec|$src_spec|$dest_spec|$ipset_spec|$port_spec|$mark_action|$global_logging|$rule_logging|$loglevel" >> "${nftTempFile}.user_rules"
	fi
}

mwan4_set_user_iface_rules()
{
	local iface device family is_src_iface
	iface=$1
	device=$2

	if [ -z "$device" ]; then
		LOG notice "set_user_iface_rules: could not find device corresponding to iface $iface"
		return
	fi

	config_get family "$iface" family ipv4

	# Check if any rules already exist for this device in nftables
	$nft list chain inet ${nftTable} ${nftPrefix}_rules 2>/dev/null | grep -q "iifname \"$device\"" && return

	is_src_iface=0

	iface_rule()
	{
		local src_iface
		config_get src_iface "$1" src_iface
		[ "$src_iface" = "$iface" ] && is_src_iface=1
	}
	config_foreach iface_rule rule
	[ $is_src_iface -eq 1 ] && mwan4_set_user_rules
}

mwan4_set_user_rules()
{
	local family_flag tmpfile error
	local rule_line action rule fam proto src dest ipset ports mark log_en log_lev
	local sticky_file iface sticky_mark sticky_fam

	tmpfile="${nftRulesFile}.tmp"

	# Clean up temp files
	rm -f "${nftTempFile}.user_rules"
	rm -f "${nftTempFile}.rule_"*

	# Process all rules first to generate temp files
	config_foreach mwan4_set_user_nftables_rule rule ipv4
	config_foreach mwan4_set_user_nftables_rule rule ipv6

	# Build rules chains - sticky chains MUST be defined before main rules that reference them
	cat > "$tmpfile" <<EOF
table inet ${nftTable} {
EOF

	# First, create all sticky rule chains (if any exist)
	for sticky_file in "${nftTempFile}.rule_"*"_sticky"; do
		[ -f "$sticky_file" ] || continue
		rule=$(echo "$sticky_file" | sed "s|${nftTempFile}.rule_||;s|_sticky||")

		for fam in ipv4 ipv6; do
			[ "$fam" = "ipv6" ] && [ $NO_IPV6 -ne 0 ] && continue

			cat >> "$tmpfile" <<EOF
	chain ${nftPrefix}_rule_${rule}_${fam} {
EOF

			# Add sticky logic for each interface in policy
			while IFS=: read -r _ iface sticky_mark sticky_fam; do
				[ "$sticky_fam" != "$fam" ] && continue

				cat >> "$tmpfile" <<EOF
		meta mark == $sticky_mark @${nftPrefix}_rule_${fam}_${rule} != { ${fam} saddr . meta mark } meta mark set 0x0
		meta mark == 0 meta mark set $sticky_mark
EOF
			done < "$sticky_file"

			# Add rules to update the sticky set and call policy
			cat >> "$tmpfile" <<EOF
		meta mark & $MMX_MASK != 0 meta mark != 0xfc00 delete @${nftPrefix}_rule_${fam}_${rule} { ${fam} saddr . meta mark }
		meta mark & $MMX_MASK != 0 meta mark != 0xfc00 add @${nftPrefix}_rule_${fam}_${rule} { ${fam} saddr . meta mark }
	}
EOF
		done

		rm -f "$sticky_file"
	done

	# Now create main rules chains that can safely jump to sticky chains
	cat >> "$tmpfile" <<EOF
	chain ${nftPrefix}_rules_ipv4 {
EOF

	# Generate rules from temp file
	if [ -f "${nftTempFile}.user_rules" ]; then
		while IFS='|' read -r action rule fam proto src dest ipset ports mark log_en log_lev; do
			[ "$fam" != "ipv4" ] && continue

			case "$action" in
				regular_rule)
					# Add logging rule if enabled
					if [ "$log_en" = "1" ] && [ "$log_lev" = "1" ]; then
						cat >> "$tmpfile" <<EOF
		$proto $src $dest $ipset $ports meta mark & $MMX_MASK == 0 log prefix "MWAN4($rule) " comment "$rule"
EOF
					fi
					# Add the actual rule
					cat >> "$tmpfile" <<EOF
		$proto $src $dest $ipset $ports meta mark & $MMX_MASK == 0 $mark comment "$rule"
EOF
					;;
				sticky_rule)
					# Create sticky rule chain
					cat >> "$tmpfile" <<EOF
		$proto $src $dest $ipset $ports meta mark & $MMX_MASK == 0 jump ${nftPrefix}_rule_${rule}_ipv4 comment "$rule"
EOF
					;;
			esac
		done < "${nftTempFile}.user_rules"
	fi

	cat >> "$tmpfile" <<EOF
	}
EOF

	# Now IPv6 rules
	if [ $NO_IPV6 -eq 0 ]; then
		cat >> "$tmpfile" <<EOF
	chain ${nftPrefix}_rules_ipv6 {
EOF

		# Generate rules from temp file
		if [ -f "${nftTempFile}.user_rules" ]; then
			while IFS='|' read -r action rule fam proto src dest ipset ports mark log_en log_lev; do
				[ "$fam" != "ipv6" ] && continue

				case "$action" in
					regular_rule)
						# Add logging rule if enabled
						if [ "$log_en" = "1" ] && [ "$log_lev" = "1" ]; then
							cat >> "$tmpfile" <<EOF
		$proto $src $dest $ipset $ports meta mark & $MMX_MASK == 0 log prefix "MWAN4($rule) " comment "$rule"
EOF
						fi
						# Add the actual rule
						cat >> "$tmpfile" <<EOF
		$proto $src $dest $ipset $ports meta mark & $MMX_MASK == 0 $mark comment "$rule"
EOF
						;;
					sticky_rule)
						# Create sticky rule chain
						cat >> "$tmpfile" <<EOF
		$proto $src $dest $ipset $ports meta mark & $MMX_MASK == 0 jump ${nftPrefix}_rule_${rule}_ipv6 comment "$rule"
EOF
						;;
				esac
			done < "${nftTempFile}.user_rules"
		fi

		cat >> "$tmpfile" <<EOF
	}
EOF
	fi

	cat >> "$tmpfile" <<EOF
}
EOF

	# Apply the nftables configuration
	error=$($nft -f "$tmpfile" 2>&1) || {
		LOG error "set_user_rules: $error"
		rm -f "$tmpfile"
		return 1
	}

	rm -f "$tmpfile"
	rm -f "${nftTempFile}.user_rules"
}

mwan4_interface_hotplug_shutdown()
{
	local interface status device ifdown families family status_iface
	interface="$1"
	ifdown="$2"

	# Check if any family is online
	status=offline
	mwan4_get_families families "$interface"
	for family in $families; do
		status_iface="${interface}_${family}"
		[ -f "$MWAN4TRACK_STATUS_DIR/$status_iface/STATUS" ] && {
			readfile status "$MWAN4TRACK_STATUS_DIR/$status_iface/STATUS"
			[ "$status" = "online" ] && break
		}
	done

	[ "$status" != "online" ] && [ "$ifdown" != 1 ] && return

	if [ "$ifdown" = 1 ]; then
		env -i ACTION=ifdown \
			INTERFACE=$interface \
			DEVICE=$device \
			sh /etc/hotplug.d/iface/15-mwan4
	else
		[ "$status" = "online" ] && {
			env -i MWAN4_SHUTDOWN="1" \
				ACTION="disconnected" \
				INTERFACE="$interface" \
				DEVICE="$device" /sbin/hotplug-call iface
		}
	fi
}

mwan4_interface_shutdown()
{
	mwan4_interface_hotplug_shutdown $1
	mwan4_track_clean $1
}

mwan4_ifup()
{
	local interface=$1
	local caller=$2

	local up l3_device status true_iface

	if [ "${caller}" = "cmd" ]; then
		# It is not necessary to obtain a lock here, because it is obtained in the hotplug
		# script, but we still want to do the check to print a useful error message
		/etc/init.d/mwan4 running || {
			echo 'The service mwan4 is global disabled.'
			echo 'Please execute "/etc/init.d/mwan4 start" first.'
			exit 1
		}
		config_load mwan4
	fi
	mwan4_get_true_iface true_iface $interface
	status=$(ubus -S call network.interface.$true_iface status)

	[ -n "$status" ] && {
		json_load "$status"
		json_get_vars up l3_device
	}
	hotplug_startup()
	{
		env -i MWAN4_STARTUP=$caller ACTION=ifup \
		    INTERFACE=$interface DEVICE=$l3_device \
		    sh /etc/hotplug.d/iface/15-mwan4
	}

	if [ "$up" != "1" ] || [ -z "$l3_device" ]; then
		return
	fi

	if [ "${caller}" = "init" ]; then
		hotplug_startup &
		hotplug_pids="$hotplug_pids $!"
	else
		hotplug_startup
	fi
}

mwan4_set_iface_hotplug_state() {
	local iface=$1
	local state=$2

	echo "$state" > "$MWAN4_STATUS_DIR/iface_state/$iface"
}

mwan4_get_iface_hotplug_state() {
	local iface=$1
	local state=offline
	readfile state "$MWAN4_STATUS_DIR/iface_state/$iface"
	echo "$state"
}

mwan4_report_iface_status_family()
{
	local device result tracking IP iface family status_iface
	local status online uptime result id

	iface="$1"
	family="$2"

	mwan4_get_iface_id id "$iface"
	network_get_device device "$iface"
	config_get_bool enabled "$iface" enabled 0

	if [ "$family" = "ipv4" ]; then
		IP="$IP4"
	fi

	if [ "$family" = "ipv6" ]; then
		IP="$IP6"
	fi

	# Use family-specific status directory
	status_iface="${iface}_${family}"

	if [ -f "$MWAN4TRACK_STATUS_DIR/${status_iface}/STATUS" ]; then
		readfile status "$MWAN4TRACK_STATUS_DIR/${status_iface}/STATUS"
	else
		status="unknown"
	fi

	if [ "$status" = "online" ]; then
		get_online_time online "$iface"
		network_get_uptime uptime "$iface"
		online="$(printf '%02dh:%02dm:%02ds\n' $((online/3600)) $((online%3600/60)) $((online%60)))"
		uptime="$(printf '%02dh:%02dm:%02ds\n' $((uptime/3600)) $((uptime%3600/60)) $((uptime%60)))"
		result="$(mwan4_get_iface_hotplug_state $iface) $online, uptime $uptime"
	else
		result=0
		[ -n "$($IP rule | awk '$1 == "'$((id+1000)):'"')" ] ||
			result=$((result+1))
		[ -n "$($IP rule | awk '$1 == "'$((id+2000)):'"')" ] ||
			result=$((result+2))
		[ -n "$($IP rule | awk '$1 == "'$((id+3000)):'"')" ] ||
			result=$((result+4))
		[ -n "$($nft list chain inet ${nftTable} ${nftPrefix}_iface_in_${iface}_${family} 2> /dev/null)" ] ||
			result=$((result+8))
		[ -n "$($IP route list table $id default dev $device 2> /dev/null)" ] ||
			result=$((result+16))
		[ "$result" = "0" ] && result=""
	fi

	mwan4_get_mwan4track_status tracking "$iface" "$family"
	if [ -n "$result" ]; then
		echo " interface $iface ($family) is $status and tracking is $tracking ($result)"
	else
		echo " interface $iface ($family) is $status and tracking is $tracking"
	fi
}

mwan4_report_iface_status()
{
	local iface="$1"

	# Report status for each family
	mwan4_foreach_family "$iface" mwan4_report_iface_status_family
}

mwan4_report_policies()
{
	local chain="$1"
	local policy="$2"

	local percent total_weight weight iface comment

	# Extract policy info from nftables chain comments
	total_weight=$($nft list chain inet ${nftTable} "$chain" 2>/dev/null | \
		grep -v 'comment "out ' | \
		grep 'comment' | \
		sed -n 's/.*comment "\([^ ]*\) [0-9]* \([0-9]*\)".*/\2/p' | \
		head -1)

	if [ -n "${total_weight##*[!0-9]*}" ]; then
		# Load balanced policy
		$nft list chain inet ${nftTable} "$chain" 2>/dev/null | \
			grep -v 'comment "out ' | \
			grep 'comment' | \
			sed -n 's/.*comment "\([^ ]*\) \([0-9]*\) [0-9]*".*/\1 \2/p' | \
			while read -r iface weight; do
				percent=$((weight*100/total_weight))
				echo " $iface ($percent%)"
			done
	else
		# Single interface policy
		$nft list chain inet ${nftTable} "$chain" 2>/dev/null | \
			grep -v 'comment "out ' | \
			grep 'comment' | \
			sed -n 's/.*comment "\([^ ]*\)".*/\1/p' | \
			head -1 | \
			xargs -r echo " "
	fi
}

mwan4_report_policies_v4()
{
	local policy

	for policy in $($nft list chains inet ${nftTable} 2>/dev/null | \
		awk '{print $2}' | \
		grep "${nftPrefix}_policy_.*_ipv4" | \
		sort -u); do
		echo "$policy:" | sed "s/${nftPrefix}_policy_//;s/_ipv4//"
		mwan4_report_policies "$policy" "${policy#${nftPrefix}_policy_}"
	done
}

mwan4_report_policies_v6()
{
	local policy

	[ $NO_IPV6 -ne 0 ] && return

	for policy in $($nft list chains inet ${nftTable} 2>/dev/null | \
		awk '{print $2}' | \
		grep "${nftPrefix}_policy_.*_ipv6" | \
		sort -u); do
		echo "$policy:" | sed "s/${nftPrefix}_policy_//;s/_ipv6//"
		mwan4_report_policies "$policy" "${policy#${nftPrefix}_policy_}"
	done
}

mwan4_report_connected_v4()
{
	if $nft list set inet ${nftTable} ${nftPrefix}_connected_ipv4 >/dev/null 2>&1; then
		$nft list set inet ${nftTable} ${nftPrefix}_connected_ipv4 | \
			sed -n '/elements = {/,/}/p' | \
			tr -d '\t {},' | \
			grep -v elements
	fi
}

mwan4_report_connected_v6()
{
	[ $NO_IPV6 -ne 0 ] && return

	if $nft list set inet ${nftTable} ${nftPrefix}_connected_ipv6 >/dev/null 2>&1; then
		$nft list set inet ${nftTable} ${nftPrefix}_connected_ipv6 | \
			sed -n '/elements = {/,/}/p' | \
			tr -d '\t {},' | \
			grep -v elements
	fi
}

mwan4_report_rules_v4()
{
	if $nft list chain inet ${nftTable} ${nftPrefix}_rules_ipv4 >/dev/null 2>&1; then
		$nft list chain inet ${nftTable} ${nftPrefix}_rules_ipv4 | \
			grep -E '(counter|comment)' | \
			sed 's/meta mark.*//' | \
			sed "s/${nftPrefix}_policy_/- /" | \
			sed "s/${nftPrefix}_rule_/S /"
	fi
}

mwan4_report_rules_v6()
{
	[ $NO_IPV6 -ne 0 ] && return

	if $nft list chain inet ${nftTable} ${nftPrefix}_rules_ipv6 >/dev/null 2>&1; then
		$nft list chain inet ${nftTable} ${nftPrefix}_rules_ipv6 | \
			grep -E '(counter|comment)' | \
			sed 's/meta mark.*//' | \
			sed "s/${nftPrefix}_policy_/- /" | \
			sed "s/${nftPrefix}_rule_/S /"
	fi
}

mwan4_flush_conntrack()
{
	local interface="$1"
	local action="$2"

	handle_flush() {
		local flush_conntrack="$1"
		local action="$2"

		if [ "$action" = "$flush_conntrack" ]; then
			echo f > ${CONNTRACK_FILE}
			LOG info "Connection tracking flushed for interface '$interface' on action '$action'"
		fi
	}

	if [ -e "$CONNTRACK_FILE" ]; then
		config_list_foreach "$interface" flush_conntrack handle_flush "$action"
	fi
}

mwan4_track_clean()
{
	local interface families family status_iface
	interface="$1"

	# Clean up family-specific status directories
	mwan4_get_families families "$interface"
	for family in $families; do
		status_iface="${interface}_${family}"
		rm -rf "${MWAN4TRACK_STATUS_DIR:?}/${status_iface}" &> /dev/null
	done

	rm -rf "${MWAN4_STATUS_DIR:?}/${interface}" &> /dev/null
	rmdir --ignore-fail-on-non-empty "$MWAN4_STATUS_DIR"
	rmdir --ignore-fail-on-non-empty "$MWAN4TRACK_STATUS_DIR"
}

