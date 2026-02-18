'use strict';
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 MOSSDeF, Stan Grishin (stangri@melmac.ca).
// Based on original mwan3 by Florian Eckert <fe@dev.tdt.de>

import { readfile, writefile, popen, stat, unlink } from 'fs';
import { cursor } from 'uci';

// ── Constants ────────────────────────────────────────────────────────

const STATUS_DIR = '/var/run/mwan4';
const STATUS_NFT_LOG_DIR = STATUS_DIR + '/nft_log';
const TRACK_STATUS_DIR = '/var/run/mwan4track';
const CONNTRACK_FILE = '/proc/net/nf_conntrack';
const DEFAULT_LOWEST_METRIC = 256;

const NFT_TABLE = 'fw4';
const NFT_PREFIX = 'mwan4';
const NFT_IPV4 = 'ip';
const NFT_IPV6 = 'ip6';
const NFT_TEMP = '/var/run/mwan4.nft';
const NFT_BASE_FILE = '/usr/share/nftables.d/ruleset-post/10-mwan4-base.nft';
const NFT_SETS_FILE = '/usr/share/nftables.d/ruleset-post/11-mwan4-sets.nft';
const NFT_IFACE_FILE = '/usr/share/nftables.d/ruleset-post/12-mwan4-interfaces.nft';
const NFT_STRATEGY_FILE = '/usr/share/nftables.d/ruleset-post/13-mwan4-strategies.nft';
const NFT_RULES_FILE = '/usr/share/nftables.d/ruleset-post/14-mwan4-rules.nft';

const IPv4_RE = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/[0-9]+)?$/;
const IPv6_RE = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}(\/[0-9]+)?$/;

// ── Module State ─────────────────────────────────────────────────────

let scriptname = 'mwan4';
let uci_ctx = null;
let ubus_conn = null;
let no_ipv6 = 1;
let mmx_mask = '';
let mmx_default = '';
let mmx_blackhole = '';
let mm_blackhole = '';
let mmx_unreachable = '';
let mm_unreachable = '';
let iface_max = 0;
let iface_tbl = {};
let dev_tbl = { ipv4: {}, ipv6: {} };
let source_routing = false;
let _sets_nft_lines = [];
let _sets_accumulate = false;

// ── Utility Functions ────────────────────────────────────────────────

function set_scriptname(name) { scriptname = name; }

function LOG(facility, ...args) {
	if (facility == 'debug') return;
	let msg = replace(join(' ', args), "'", "'\\''");
	system(sprintf("logger -t '%s' -p %s '%s'", scriptname, facility, msg));
}

function run(c) {
	return system(c + ' >/dev/null 2>&1');
}

function cmd_output(c) {
	let p = popen(c, 'r');
	if (!p) return '';
	let out = p.read('all') || '';
	p.close();
	return out;
}

function cmd_lines(c) {
	let raw = cmd_output(c);
	if (!length(raw)) return [];
	return split(rtrim(raw, '\n'), '\n');
}

function read_str(path) {
	return rtrim(readfile(path) || '', '\n') || null;
}

function read_int(path) {
	return int(read_str(path) || '0');
}

function write_str(path, data) {
	writefile(path, data);
}

function ensure_dir(path) {
	if (!stat(path))
		system(sprintf("mkdir -p '%s'", path));
}

function file_exists(path) {
	return !!stat(path);
}

function rm(path) {
	unlink(path);
}

function nft_file(command, tmpfile, destfile) {
	let err;
	switch (command) {
	case 'check':
		err = trim(cmd_output(sprintf('nft -c -f %s 2>&1', tmpfile)));
		if (length(err)) {
			LOG('error', 'nft check failed for', tmpfile + ':', err);
			return false;
		}
		return true;
	case 'apply':
		if (!nft_file('check', tmpfile))
			return false;
		err = trim(cmd_output(sprintf('nft -f %s 2>&1', tmpfile)));
		if (length(err)) {
			LOG('error', 'nft -f', tmpfile + ':', err);
			return false;
		}
		return true;
	case 'install':
		// No nft -c -f check here: individual files have cross-file chain
		// references (e.g. rules file references strategy chains) that only
		// resolve when fw4 loads all include files together.
		let content = readfile(tmpfile);
		if (!content) {
			LOG('error', 'Cannot read temp file', tmpfile);
			return false;
		}
		// Ensure parent directory exists
		let dir = match(destfile, /^(.+)\//);
		if (dir) ensure_dir(dir[1]);
		writefile(destfile, content);
		LOG('info', 'Installed nft file to', destfile);
		return true;
	}
}

function fw4_reload() {
	let rc = system('fw4 -q reload 2>/dev/null');
	if (rc != 0)
		LOG('error', 'fw4 reload failed');
	return rc == 0;
}

function nft_output(args) {
	return cmd_output('nft ' + args);
}

// ── Ubus Helpers ─────────────────────────────────────────────────────

function ubus_call(path, method, args) {
	if (!ubus_conn)
		ubus_conn = require('ubus').connect();
	return ubus_conn?.call(path, method, args || {});
}

function network_get_device(iface) {
	let s = ubus_call(sprintf('network.interface.%s', iface), 'status');
	return s?.l3_device || s?.device;
}

function network_get_ipaddr(iface) {
	let s = ubus_call(sprintf('network.interface.%s', iface), 'status');
	let addrs = s?.['ipv4-address'];
	return (type(addrs) == 'array' && length(addrs)) ? addrs[0]?.address : null;
}

function network_get_ipaddr6(iface) {
	let s = ubus_call(sprintf('network.interface.%s', iface), 'status');
	let addrs = s?.['ipv6-address'];
	return (type(addrs) == 'array' && length(addrs)) ? addrs[0]?.address : null;
}

function network_get_prefix6(iface) {
	let s = ubus_call(sprintf('network.interface.%s', iface), 'status');
	let pfxs = s?.['ipv6-prefix'];
	if (type(pfxs) == 'array' && length(pfxs)) {
		let pfx = pfxs[0];
		return sprintf('%s/%d', pfx.address, pfx.mask);
	}
	return null;
}

function network_get_uptime(iface) { // ucode-lsp disable
	let s = ubus_call(sprintf('network.interface.%s', iface), 'status');
	return s?.uptime || 0;
}

// ── Bit Manipulation ─────────────────────────────────────────────────

function count_one_bits(n) {
	let count = 0;
	n = int(n);
	while (n > 0) {
		n = n & (n - 1);
		count++;
	}
	return count;
}

function id2mask(id, mask) {
	let bit_val = 0, result = 0;
	let m = int(mask), v = int(id);
	for (let bit = 0; bit < 32; bit++) {
		if ((m >> bit) & 1) {
			if ((v >> bit_val) & 1)
				result |= (1 << bit);
			bit_val++;
		}
	}
	return sprintf('0x%x', result);
}

// ── UCI Helpers ──────────────────────────────────────────────────────

function uci_bool(val) {
	if (val == null) return false;
	switch ('' + val) {
		case '1': case 'yes': case 'on': case 'true': case 'enabled':
			return true;
		default:
			return false;
	}
}

function uci_get(section, option, def) {
	let val = uci_ctx?.get('mwan4', section, option);
	return val ?? def ?? null;
}

function uci_get_list(section, option) {
	let val = uci_ctx?.get('mwan4', section, option);
	if (val == null) return [];
	if (type(val) == 'array') return val;
	return [val];
}

function uci_get_bool(section, option, def) {
	let val = uci_get(section, option);
	if (val == null) return def || false;
	return uci_bool(val);
}

function uci_foreach(stype, callback) {
	uci_ctx?.foreach('mwan4', stype, callback);
}

// ── Uptime ───────────────────────────────────────────────────────────

function get_uptime() {
	return int(split(readfile('/proc/uptime') || '0', '.')[0]);
}

function get_online_time(iface) {
	let time_u = read_int(sprintf('%s/%s/ONLINE', TRACK_STATUS_DIR, iface));
	if (!time_u || time_u == 0) return 0;
	return get_uptime() - time_u;
}

// ── Family Helpers ───────────────────────────────────────────────────

function get_families(iface) {
	let families = uci_get_list(iface, 'family');
	if (!length(families)) return ['ipv4'];
	return families;
}

function foreach_family(iface, cb, ...extra) {
	let families = get_families(iface);
	for (let family in families)
		call(cb, null, iface, family, ...extra);
}

// ── Interface Helpers ────────────────────────────────────────────────

function get_true_iface(iface, family) {
	if (!family)
		family = uci_get(iface, 'family') || 'ipv4';
	let v = (family == 'ipv4') ? '4' : '6';
	let alt = sprintf('%s_%s', iface, v);
	let s = ubus_call(sprintf('network.interface.%s', alt), 'status');
	return s ? alt : iface;
}

function get_src_ip(iface, family) {
	if (!family) family = uci_get(iface, 'family') || 'ipv4';
	let true_iface = get_true_iface(iface, family);
	let src_ip = '';
	let device;

	if (family == 'ipv4') {
		src_ip = network_get_ipaddr(true_iface);
	} else {
		src_ip = network_get_ipaddr6(true_iface);
	}

	if (!src_ip && family == 'ipv6') {
		let pfx = network_get_prefix6(true_iface);
		if (pfx) {
			let prefix_part = replace(pfx, /:*\/.*$/, '');
			for (let line in cmd_lines('ip -6 address ls')) {
				let m = match(line, /inet6 ([0-9a-fA-F:]+)/);
				if (m && index(m[1], prefix_part) == 0) {
					src_ip = m[1];
					break;
				}
			}
		}
	}

	if (!src_ip) {
		device = network_get_device(true_iface);
		if (device) {
			let ip_cmd = (family == 'ipv4') ? 'ip -4' : 'ip -6';
			for (let line in cmd_lines(sprintf('%s address ls dev %s', ip_cmd, device))) {
				let m;
				if (family == 'ipv4')
					m = match(line, /inet ([^ \/]+)/);
				else
					m = match(line, /inet6 ([^ \/]+).* scope/);
				if (m) { src_ip = m[1]; break; }
			}
			if (src_ip)
				LOG('warn', sprintf("guessing src %s addr %s for '%s' dev '%s'", family, src_ip, true_iface, device));
			else
				LOG('warn', sprintf("no src %s addr for '%s' dev '%s'", family, true_iface, device));
		}
	}

	return src_ip || ((family == 'ipv4') ? '0.0.0.0' : '::');
}

// ── Track Status ─────────────────────────────────────────────────────

function get_mwan4track_status(iface, family) {
	let status_iface = family ? sprintf('%s_%s', iface, family) : iface;
	let track_ips = uci_get_list(iface, 'track_ip');
	if (!length(track_ips)) return 'disabled';

	let pid = read_str(sprintf('%s/%s/PID', TRACK_STATUS_DIR, status_iface));
	if (!pid) return 'down';

	let cmdline = read_str(sprintf('/proc/%s/cmdline', pid));
	if (!cmdline || index(cmdline, 'mwan4track') < 0 || index(cmdline, status_iface) < 0)
		return 'down';

	let started = read_str(sprintf('%s/%s/STARTED', TRACK_STATUS_DIR, status_iface));
	switch (started) {
		case '0': return 'paused';
		case '1': return 'active';
		default: return 'down';
	}
}

// ── Interface Table Mapping ──────────────────────────────────────────

function update_iface_to_table() {
	iface_tbl = {};
	let tid = 0;
	uci_foreach('interface', function(s) {
		tid++;
		iface_tbl[s['.name']] = tid;
	});
}

function update_dev_to_table() {
	dev_tbl = { ipv4: {}, ipv6: {} };
	let tid = 0;
	uci_foreach('interface', function(s) {
		tid++;
		if (!uci_bool(s.enabled)) return;
		let device = network_get_device(s['.name']);
		if (!device) return;
		for (let family in get_families(s['.name']))
			dev_tbl[family][device] = tid;
	});
}

function get_iface_id(iface) {
	if (!length(keys(iface_tbl))) update_iface_to_table();
	return iface_tbl[iface];
}

function route_line_dev(route_line, route_family) {
	let m = match(route_line, /dev ([^ ]+)/);
	if (!m) return null;
	return dev_tbl[route_family]?.[m[1]];
}

// ── Route Line Cleaning ──────────────────────────────────────────────

function clean_route_line(line) {
	line = replace(line, /offload/, '');
	line = replace(line, /linkdown /, '');
	line = replace(line, /expires [0-9]+sec/, '');
	line = replace(line, /error [0-9]+/, '');
	if (!source_routing)
		line = replace(line, /default(.*) from [^ ]*/, 'default$1');
	return trim(line);
}

function get_routes(family) {
	let ip_cmd = (family == 'ipv4') ? 'ip -4' : 'ip -6';
	let seen = {};
	let routes = [];

	let all_lines = cmd_lines(sprintf('%s route list table main', ip_cmd));
	let lookups = uci_get_list('globals', 'rt_table_lookup');
	for (let tbl_id in lookups)
		push(all_lines, ...cmd_lines(sprintf('%s route list table %s', ip_cmd, tbl_id)));

	for (let line in all_lines) {
		let cleaned = clean_route_line(line);
		if (length(cleaned) && !seen[cleaned]) {
			seen[cleaned] = true;
			push(routes, cleaned);
		}
	}
	return routes;
}

// ── Hotplug State ────────────────────────────────────────────────────

function set_iface_hotplug_state(iface, state) {
	write_str(sprintf('%s/iface_state/%s', STATUS_DIR, iface), state);
}

function get_iface_hotplug_state(iface) {
	return read_str(sprintf('%s/iface_state/%s', STATUS_DIR, iface)) || 'offline';
}

// ── Initialization ───────────────────────────────────────────────────

function init(name) {
	if (name) scriptname = name;

	// Check IPv6
	no_ipv6 = (system('ip -6 addr show >/dev/null 2>&1') == 0) ? 0 : 1;

	uci_ctx = cursor();
	uci_ctx.load('mwan4');

	ensure_dir(STATUS_DIR + '/iface_state');
	ensure_dir(STATUS_NFT_LOG_DIR);
	ensure_dir(TRACK_STATUS_DIR);

	let saved_mask = read_str(STATUS_DIR + '/mmx_mask');
	if (saved_mask) {
		mmx_mask = saved_mask;
		iface_max = read_int(STATUS_DIR + '/iface_max');
	}

	if (!mmx_mask) {
		mmx_mask = uci_get('globals', 'mmx_mask') || '0x3F00';
		mmx_mask = lc(mmx_mask);
		write_str(STATUS_DIR + '/mmx_mask', mmx_mask);
		LOG('debug', 'Using firewall mask', mmx_mask);

		let bitcnt = count_one_bits(mmx_mask);
		let mmdefault = (1 << bitcnt) - 1;
		iface_max = mmdefault - 3;
		write_str(STATUS_DIR + '/iface_max', '' + iface_max);
		LOG('debug', 'Max interface count is', '' + iface_max);
	}

	let bitcnt = count_one_bits(mmx_mask);
	let mmdefault = (1 << bitcnt) - 1;
	mm_blackhole = mmdefault - 2;
	mm_unreachable = mmdefault - 1;

	mmx_default = id2mask(mmdefault, mmx_mask);
	mmx_blackhole = id2mask(mm_blackhole, mmx_mask);
	mmx_unreachable = id2mask(mm_unreachable, mmx_mask);

	source_routing = uci_get_bool('globals', 'source_routing', false);
}

// ── nftables Set Accumulation ────────────────────────────────────────

function _accumulate_set_lines(lines) {
	if (!_sets_accumulate) return;
	for (let i = 1; i < length(lines) - 1; i++)
		push(_sets_nft_lines, lines[i]);
}

function begin_set_accumulation() {
	_sets_nft_lines = [];
	_sets_accumulate = true;
}

function install_sets_nftfile() {
	if (!length(_sets_nft_lines)) {
		_sets_accumulate = false;
		return;
	}
	let combined = [sprintf('table inet %s {', NFT_TABLE)];
	push(combined, ..._sets_nft_lines);
	push(combined, '}');
	let tmpfile = NFT_TEMP + '.sets_combined';
	writefile(tmpfile, join('\n', combined) + '\n');
	nft_file('install', tmpfile, NFT_SETS_FILE);
	rm(tmpfile);
	_sets_nft_lines = [];
	_sets_accumulate = false;
}

// ── General IP Rules ─────────────────────────────────────────────────

function set_general_rules() {
	for (let ip_ver in ['ip -4', 'ip -6']) {
		if (ip_ver == 'ip -6' && no_ipv6 != 0) continue;

		let rule_no = mm_blackhole + 2000;
		let existing = cmd_output(sprintf('%s rule list', ip_ver));
		if (index(existing, rule_no + ':') < 0)
			run(sprintf('%s rule add pref %d fwmark %s/%s blackhole', ip_ver, rule_no, mmx_blackhole, mmx_mask));

		rule_no = mm_unreachable + 2000;
		if (index(existing, rule_no + ':') < 0)
			run(sprintf('%s rule add pref %d fwmark %s/%s unreachable', ip_ver, rule_no, mmx_unreachable, mmx_mask));
	}
}

// ── nftables Base ────────────────────────────────────────────────────

function _nft_set_check_rules(family, zero_check) { // ucode-lsp disable
	let flag = (family == 'ipv4') ? NFT_IPV4 : NFT_IPV6;
	let mark_expr = zero_check
		? sprintf('meta mark & %s == 0', mmx_mask)
		: sprintf('meta mark & %s != %s', mmx_mask, mmx_default);
	let mark_set = sprintf('meta mark set (meta mark & ~%s) | %s', mmx_mask, mmx_default);

	let rules = [];
	for (let settype in ['custom', 'connected', 'dynamic'])
		push(rules, sprintf('\t\t%s %s daddr @%s_%s_%s %s',
			mark_expr, flag, NFT_PREFIX, settype, family, mark_set));
	return rules;
}

function set_general_nftables() {
	let L = [];

	push(L, sprintf('table inet %s {', NFT_TABLE));

	// Sets
	for (let fam in ['ipv4', 'ipv6']) {
		if (fam == 'ipv6' && no_ipv6 != 0) continue;
		let addr_type = (fam == 'ipv4') ? 'ipv4_addr' : 'ipv6_addr';
		for (let settype in ['connected', 'custom', 'dynamic']) {
			push(L, '',
				sprintf('\tset %s_%s_%s {', NFT_PREFIX, settype, fam),
				sprintf('\t\ttype %s', addr_type),
				'\t\tflags interval',
				'\t\tauto-merge',
				'\t}'
			);
		}
	}

	// Empty dispatch chains
	push(L, '',
		sprintf('\tchain %s_ifaces_in {', NFT_PREFIX),
		'\t}'
	);

	// Per-family rules chains (populated later by set_user_rules)
	push(L, '',
		sprintf('\tchain %s_rules_ipv4 {', NFT_PREFIX),
		'\t}'
	);
	if (no_ipv6 == 0) {
		push(L, '',
			sprintf('\tchain %s_rules_ipv6 {', NFT_PREFIX),
			'\t}'
		);
	}

	// Rules dispatch chain: jump to per-family rules chains
	let rules_lines = [
		'',
		sprintf('\tchain %s_rules {', NFT_PREFIX),
		sprintf('\t\t%s jump %s_rules_ipv4', NFT_IPV4, NFT_PREFIX),
	];
	if (no_ipv6 == 0)
		push(rules_lines, sprintf('\t\t%s jump %s_rules_ipv6', NFT_IPV6, NFT_PREFIX));
	push(rules_lines, '\t}');
	push(L, ...rules_lines);

	// RA exemption block (shared between prerouting and output)
	let ra_exempt = [
		'\t\tip6 nexthdr icmpv6 icmpv6 type {',
		'\t\t\tnd-router-solicit,',
		'\t\t\tnd-router-advert,',
		'\t\t\tnd-neighbor-solicit,',
		'\t\t\tnd-neighbor-advert,',
		'\t\t\tnd-redirect',
		'\t\t} return',
	];

	// Build prerouting and output chains (same logic, different hook)
	for (let chain_info in [
		[sprintf('%s_prerouting', NFT_PREFIX), 'type filter hook prerouting priority mangle; policy accept;'],
		[sprintf('%s_output', NFT_PREFIX), 'type route hook output priority mangle; policy accept;'],
	]) {
		push(L, '', sprintf('\tchain %s {', chain_info[0]),
			sprintf('\t\t%s', chain_info[1])
		);
		push(L, ...ra_exempt);

		// Restore mark from conntrack
		push(L, sprintf('\t\tct mark & %s != 0 meta mark set (meta mark & ~%s) | (ct mark & %s)', mmx_mask, mmx_mask, mmx_mask));
		// Interface input
		push(L, sprintf('\t\tmeta mark & %s == 0 jump %s_ifaces_in', mmx_mask, NFT_PREFIX));
		// Pre-rule set checks (mark == 0)
		push(L, ..._nft_set_check_rules('ipv4', true));
		if (no_ipv6 == 0)
			push(L, ..._nft_set_check_rules('ipv6', true));
		// User rules
		push(L, sprintf('\t\tmeta mark & %s == 0 jump %s_rules', mmx_mask, NFT_PREFIX));
		// Save to conntrack (preserve non-mwan4 bits)
		push(L, sprintf('\t\tct mark set (ct mark & ~%s) | (meta mark & %s)', mmx_mask, mmx_mask));
		// Post-rule set checks (mark != default)
		push(L, ..._nft_set_check_rules('ipv4', false));
		if (no_ipv6 == 0)
			push(L, ..._nft_set_check_rules('ipv6', false));

		push(L, '\t}');
	}

	push(L, '}');

	let tmpfile = NFT_TEMP + '.base';
	write_str(tmpfile, join('\n', L) + '\n');
	if (!nft_file('install', tmpfile, NFT_BASE_FILE))
		LOG('error', 'Failed to install base nftables structure');
	rm(tmpfile);
}

// ── nftables Sets ────────────────────────────────────────────────────

function set_custom_nftset() {
	let lines = [
		sprintf('table inet %s {', NFT_TABLE),
		sprintf('\tset %s_custom_ipv4 {', NFT_PREFIX),
		'\t\ttype ipv4_addr',
		'\t\tflags interval',
		'\t\tauto-merge',
		'\t\telements = {',
	];

	let has_v4 = false;
	let lookups = uci_get_list('globals', 'rt_table_lookup');
	for (let tbl_id in lookups) {
		for (let line in cmd_lines(sprintf('ip -4 route list table %s', tbl_id))) {
			let addr = split(line, ' ')[0];
			if (match(addr, IPv4_RE)) {
				push(lines, sprintf('\t\t\t%s,', addr));
				has_v4 = true;
			}
		}
	}
	if (!has_v4) push(lines, '\t\t\t127.0.0.1,');
	push(lines, '\t\t}', '\t}');

	if (no_ipv6 == 0) {
		push(lines,
			'',
			sprintf('\tset %s_custom_ipv6 {', NFT_PREFIX),
			'\t\ttype ipv6_addr',
			'\t\tflags interval',
			'\t\tauto-merge',
			'\t\telements = {'
		);
		let has_v6 = false;
		for (let tbl_id in lookups) {
			for (let line in cmd_lines(sprintf('ip -6 route list table %s', tbl_id))) {
				let addr = split(line, ' ')[0];
				if (match(addr, IPv6_RE)) {
					push(lines, sprintf('\t\t\t%s,', addr));
					has_v6 = true;
				}
			}
		}
		if (!has_v6) push(lines, '\t\t\t::1,');
		push(lines, '\t\t}', '\t}');
	}

	push(lines, '}');
	let tmpfile = NFT_TEMP + '.custom_sets';
	write_str(tmpfile, join('\n', lines) + '\n');
	nft_file('apply', tmpfile);
	_accumulate_set_lines(lines);
	rm(tmpfile);
}

function set_connected_ipv4() {
	let cidr_list = [], host_list = [];

	let all_lines = cmd_lines('ip -4 route');
	push(all_lines, ...cmd_lines('ip -4 route list table 0'));

	for (let line in all_lines) {
		let addr;
		// table 0 uses column 2
		if (index(line, 'table ') >= 0)
			addr = split(line, ' ')[1];
		else
			addr = split(line, ' ')[0];
		if (!match(addr, IPv4_RE)) continue;
		if (index(addr, '/') >= 0)
			push(cidr_list, addr);
		else
			push(host_list, addr);
	}

	let lines = [
		sprintf('table inet %s {', NFT_TABLE),
		sprintf('\tset %s_connected_ipv4 {', NFT_PREFIX),
		'\t\ttype ipv4_addr',
		'\t\tflags interval',
		'\t\tauto-merge',
		'\t\telements = {',
	];
	for (let addr in cidr_list) push(lines, sprintf('\t\t\t%s,', addr));
	for (let addr in host_list) push(lines, sprintf('\t\t\t%s,', addr));
	push(lines, '\t\t\t224.0.0.0/3');
	push(lines, '\t\t}', '\t}', '}');

	let tmpfile = NFT_TEMP + '.connected_v4';
	write_str(tmpfile, join('\n', lines) + '\n');
	nft_file('apply', tmpfile);
	_accumulate_set_lines(lines);
	rm(tmpfile);
}

function set_connected_ipv6() {
	if (no_ipv6 != 0) return;

	let lines = [
		sprintf('table inet %s {', NFT_TABLE),
		sprintf('\tset %s_connected_ipv6 {', NFT_PREFIX),
		'\t\ttype ipv6_addr',
		'\t\tflags interval',
		'\t\tauto-merge',
		'\t\telements = {',
	];

	let has = false;
	for (let line in cmd_lines('ip -6 route')) {
		let addr = split(line, ' ')[0];
		if (match(addr, IPv6_RE)) {
			push(lines, sprintf('\t\t\t%s,', addr));
			has = true;
		}
	}
	if (!has) push(lines, '\t\t\t::1,');
	push(lines, '\t\t}', '\t}', '}');

	let tmpfile = NFT_TEMP + '.connected_v6';
	write_str(tmpfile, join('\n', lines) + '\n');
	nft_file('apply', tmpfile);
	_accumulate_set_lines(lines);
	rm(tmpfile);
}

function set_dynamic_nftset() {
	let lines = [
		sprintf('table inet %s {', NFT_TABLE),
		sprintf('\tset %s_dynamic_ipv4 {', NFT_PREFIX),
		'\t\ttype ipv4_addr',
		'\t\tflags interval',
		'\t\tauto-merge',
		'\t}',
	];
	if (no_ipv6 == 0) {
		push(lines, '',
			sprintf('\tset %s_dynamic_ipv6 {', NFT_PREFIX),
			'\t\ttype ipv6_addr',
			'\t\tflags interval',
			'\t\tauto-merge',
			'\t}'
		);
	}
	push(lines, '}');

	let tmpfile = NFT_TEMP + '.dynamic_init';
	write_str(tmpfile, join('\n', lines) + '\n');
	nft_file('apply', tmpfile);
	_accumulate_set_lines(lines);
	rm(tmpfile);
}

// ── nftables Interfaces ──────────────────────────────────────────────

function rebuild_iface_nftfile() {
	let L = [sprintf('table inet %s {', NFT_TABLE)];
	let jump_rules = [];

	uci_foreach('interface', function(s) {
		let iface = s['.name'];
		if (!uci_bool(s.enabled)) return;
		let device = network_get_device(iface);
		if (!device) return;

		for (let family in get_families(iface)) {
			if (family == 'ipv6' && no_ipv6 != 0) continue;
			let nftflag = (family == 'ipv4') ? NFT_IPV4 : NFT_IPV6;
			let id = get_iface_id(iface);
			if (!id) return;
			let chain_name = sprintf('%s_iface_in_%s_%s', NFT_PREFIX, iface, family);
			let mark = id2mask(id, mmx_mask);

			push(L, '', sprintf('\tchain %s {', chain_name));
			for (let settype in ['custom', 'connected', 'dynamic'])
				push(L, sprintf('\t\tiifname "%s" %s saddr @%s_%s_%s meta mark & %s == 0 meta mark set %s comment "default"',
					device, nftflag, NFT_PREFIX, settype, family, mmx_mask, mmx_default));
			push(L, sprintf('\t\tiifname "%s" meta mark & %s == 0 meta mark set %s comment "%s"',
				device, mmx_mask, mark, iface));
			push(L, '\t}');

			push(jump_rules, sprintf('\t\tmeta mark & %s == 0 %s jump %s',
				mmx_mask, nftflag, chain_name));
		}
	});

	push(L, '', sprintf('\tchain %s_ifaces_in {', NFT_PREFIX));
	push(L, ...jump_rules);
	push(L, '\t}');

	push(L, '}');

	let tmpfile = NFT_TEMP + '.ifaces';
	write_str(tmpfile, join('\n', L) + '\n');
	nft_file('install', tmpfile, NFT_IFACE_FILE);
	rm(tmpfile);
}

// ── nftables Strategies ──────────────────────────────────────────────

function _create_strategy_chain(strategy_name, accumulator) { // ucode-lsp disable
	let last_resort = uci_get(strategy_name, 'last_resort') || 'unreachable';
	let last_resort_mark;

	if (length(strategy_name) > 15) {
		LOG('warn', sprintf('Strategy %s exceeds 15 chars, skipping', strategy_name));
		return;
	}

	switch (last_resort) {
		case 'blackhole': last_resort_mark = mmx_blackhole; break;
		case 'default':   last_resort_mark = mmx_default; break;
		default:          last_resort_mark = mmx_unreachable; break;
	}

	// Collect route info per family
	let route_names = uci_get_list(strategy_name, 'use_route');
	let family_routes = { ipv4: [], ipv6: [] };

	for (let route_name in route_names) {
		let iface = uci_get(route_name, 'interface');
		let metric = int(uci_get(route_name, 'metric') || '1');
		let weight = int(uci_get(route_name, 'weight') || '1');
		if (!iface) continue;
		if (metric > DEFAULT_LOWEST_METRIC) {
			LOG('warn', sprintf('Route %s metric >%d, skipping', route_name, DEFAULT_LOWEST_METRIC));
			continue;
		}

		let id = get_iface_id(iface);
		if (!id) continue;

		let device = network_get_device(iface);
		let is_online = (get_iface_hotplug_state(iface) == 'online');
		let mark = id2mask(id, mmx_mask);

		for (let family in get_families(iface)) {
			if (family == 'ipv6' && no_ipv6 != 0) continue;
			push(family_routes[family], { iface, metric, weight, mark, device, is_online });
		}
	}

	// Build nft chain lines
	let L = [];

	for (let family in ['ipv4', 'ipv6']) {
		if (family == 'ipv6' && no_ipv6 != 0) continue;

		push(L, sprintf('\tchain %s_strategy_%s_%s {', NFT_PREFIX, strategy_name, family));

		// Find routes at lowest metric that are online
		let routes = family_routes[family];
		let online = filter(routes, r => r.is_online);

		if (length(online)) {
			// Sort by metric, pick lowest
			sort(online, (a, b) => a.metric - b.metric);
			let lowest = online[0].metric;
			let active = filter(online, r => r.metric == lowest);
			let total_weight = 0;
			for (let r in active) total_weight += r.weight;

			// Generate load-balancing rules with correct probability
			let remaining = total_weight;
			for (let i = 0; i < length(active); i++) {
				let r = active[i];
				if (i == length(active) - 1) {
					// Last route: catch-all
					push(L, sprintf('\t\tmeta mark & %s == 0 meta mark set %s comment "%s %d %d"',
						mmx_mask, r.mark, r.iface, r.weight, total_weight));
				} else {
					// Probabilistic: weight/remaining chance
					push(L, sprintf('\t\tmeta mark & %s == 0 numgen random mod %d < %d meta mark set %s comment "%s %d %d"',
						mmx_mask, remaining, r.weight, r.mark, r.iface, r.weight, total_weight));
					remaining -= r.weight;
				}
			}
		} else {
			// All offline: add device-based defaults for any with devices
			let offline_with_dev = filter(routes, r => !r.is_online && r.device);
			for (let r in offline_with_dev)
				push(L, sprintf('\t\toifname "%s" meta mark & %s == 0 meta mark set %s comment "out %s %s"',
					r.device, mmx_mask, mmx_default, r.iface, r.device));
		}

		// Last resort fallback (always last in chain)
		push(L, sprintf('\t\tmeta mark & %s == 0 meta mark set %s comment "%s"',
			mmx_mask, last_resort_mark, last_resort));
		push(L, '\t}');
	}

	push(accumulator, ...L);
	return true;
}

function set_strategies_nftables() {
	let all_lines = [];
	uci_foreach('strategy', function(s) {
		_create_strategy_chain(s['.name'], all_lines);
	});

	if (!length(all_lines)) return;

	let combined = [sprintf('table inet %s {', NFT_TABLE)];
	push(combined, ...all_lines);
	push(combined, '}');

	let tmpfile = NFT_TEMP + '.strategies_all';
	write_str(tmpfile, join('\n', combined) + '\n');
	nft_file('install', tmpfile, NFT_STRATEGY_FILE);
	rm(tmpfile);
}

// ── nftables User Rules ──────────────────────────────────────────────

function _collect_sticky_ifaces(rule_name, family, strategy_name) { // ucode-lsp disable
	let route_names = uci_get_list(strategy_name, 'use_route');
	let sticky_ifaces = [];

	for (let route_name in route_names) {
		let iface = uci_get(route_name, 'interface');
		if (!iface) continue;
		if (!uci_bool(uci_get(iface, 'enabled'))) continue;

		let families = get_families(iface);
		let has_family = false;
		for (let f in families)
			if (f == family) { has_family = true; break; }
		if (!has_family) continue;

		let id = get_iface_id(iface);
		if (!id) continue;
		let mark = id2mask(id, mmx_mask);
		push(sticky_ifaces, { iface, mark });
	}

	return sticky_ifaces;
}

function _build_user_rule(s, family_flag) { // ucode-lsp disable
	if (family_flag == 'ipv6' && no_ipv6 != 0) return null;

	let rule = s['.name'];
	let sticky = int(s.sticky || '0');
	let timeout = int(s.timeout || '600');
	let proto = s.proto || 'all';
	let src_ip = s.src_ip || '';
	let src_iface = s.src_iface || '';
	let src_port = s.src_port || '';
	let dest_ip = s.dest_ip || '';
	let dest_port = s.dest_port || '';
	let use_strategy = s.use_strategy || '';
	let ipset = s.ipset || '';
	let rule_logging = int(s.logging || '0');

	// Family filter
	let family_list = uci_get_list(rule, 'family');
	if (length(family_list)) {
		let found = false;
		for (let f in family_list)
			if (f == family_flag) { found = true; break; }
		if (!found) return null;
	}

	// Fix malformed IPv6 addresses
	if (family_flag == 'ipv6') {
		if (dest_ip && substr(dest_ip, 0, 1) == '/')
			dest_ip = ':' + dest_ip;
		if (src_ip && substr(src_ip, 0, 1) == '/')
			src_ip = ':' + src_ip;
	}

	// Validate IP addresses don't cross families
	for (let addr in [src_ip, dest_ip]) {
		if (!addr) continue;
		if (family_flag == 'ipv4' && match(addr, /:/)) return null;
		if (family_flag == 'ipv6' && match(addr, /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) return null;
	}

	// Resolve src_iface to device
	let src_dev = '';
	if (src_iface) {
		src_dev = network_get_device(src_iface);
		if (!src_dev) {
			LOG('notice', sprintf('could not find device for src_iface %s in rule %s', src_iface, rule));
			return null;
		}
	}

	// Validate port/proto combination
	if (proto != 'tcp' && proto != 'udp') {
		src_port = '';
		dest_port = '';
	}

	if (length(rule) > 15) {
		LOG('warn', sprintf('Rule %s exceeds 15 chars, skipping', rule));
		return null;
	}
	if (!use_strategy) return null;

	let nftflag = (family_flag == 'ipv4') ? NFT_IPV4 : NFT_IPV6;

	// Build match criteria parts
	let parts = [];
	if (proto != 'all') push(parts, sprintf('meta l4proto %s', proto));
	if (src_ip) push(parts, sprintf('%s saddr %s', nftflag, src_ip));
	if (src_dev) push(parts, sprintf('iifname "%s"', src_dev));
	if (dest_ip) push(parts, sprintf('%s daddr %s', nftflag, dest_ip));
	if (ipset) push(parts, sprintf('%s daddr @%s', nftflag, ipset));
	if (src_port && dest_port)
		push(parts, sprintf('%s sport { %s } %s dport { %s }', proto, src_port, proto, dest_port));
	else if (src_port)
		push(parts, sprintf('%s sport { %s }', proto, src_port));
	else if (dest_port)
		push(parts, sprintf('%s dport { %s }', proto, dest_port));

	let match_str = join(' ', parts);

	// Determine action
	let mark_action;
	let is_strategy_jump = false;
	switch (use_strategy) {
		case 'default':     mark_action = sprintf('meta mark set %s', mmx_default); break;
		case 'unreachable': mark_action = sprintf('meta mark set %s', mmx_unreachable); break;
		case 'blackhole':   mark_action = sprintf('meta mark set %s', mmx_blackhole); break;
		default:
			is_strategy_jump = true;
			mark_action = sprintf('jump %s_strategy_%s_%s', NFT_PREFIX, use_strategy, family_flag);
			break;
	}

	return {
		rule, family_flag, match_str, mark_action,
		is_strategy_jump, sticky, timeout, use_strategy,
		rule_logging,
		global_logging: int(uci_get('globals', 'logging') || '0'),
		loglevel: uci_get('globals', 'loglevel') || 'notice',
	};
}

function set_user_rules() {
	// Collect all rules for both families
	let rule_data = { ipv4: [], ipv6: [] };
	let sticky_rules = {};
	let sticky_set_defs = {};

	uci_foreach('rule', function(s) {
		for (let fam in ['ipv4', 'ipv6']) {
			let rd = _build_user_rule(s, fam);
			if (!rd) continue;

			if (rd.is_strategy_jump && rd.sticky) {
				let sticky_ifaces = _collect_sticky_ifaces(rd.rule, fam, rd.use_strategy);
				if (length(sticky_ifaces)) {
					sticky_set_defs[rd.rule] = rd.timeout;
					sticky_rules[rd.rule + '_' + fam] = rd.use_strategy;
					rd.has_sticky = true;
				}
			}
			push(rule_data[fam], rd);
		}
	});

	// Build nft file: sticky set defs, sticky chains, then rule chains
	let L = [sprintf('table inet %s {', NFT_TABLE)];

	// Sticky map definitions (maps source address -> mark for session persistence)
	for (let rule_name in keys(sticky_set_defs)) {
		let timeout = sticky_set_defs[rule_name];
		push(L,
			sprintf('\tmap %s_rule_ipv4_%s {', NFT_PREFIX, rule_name),
			'\t\ttypeof ip saddr : meta mark',
			'\t\tflags timeout',
			sprintf('\t\ttimeout %ds', timeout),
			'\t}'
		);
		if (no_ipv6 == 0) {
			push(L,
				sprintf('\tmap %s_rule_ipv6_%s {', NFT_PREFIX, rule_name),
				'\t\ttypeof ip6 saddr : meta mark',
				'\t\tflags timeout',
				sprintf('\t\ttimeout %ds', timeout),
				'\t}'
			);
		}
	}

	// Sticky per-rule chains
	for (let key in keys(sticky_rules)) {
		let parts = match(key, /^(.+)_(ipv4|ipv6)$/);
		if (!parts) continue;
		let rule_name = parts[1], fam = parts[2];
		let strategy = sticky_rules[key];
		let saddr = (fam == 'ipv4') ? 'ip saddr' : 'ip6 saddr';

		push(L, sprintf('\tchain %s_rule_%s_%s {', NFT_PREFIX, rule_name, fam));
		// Sticky map lookup: restore mark from previous session
		push(L, sprintf('\t\tmeta mark & %s == 0 meta mark set %s map @%s_rule_%s_%s',
			mmx_mask, saddr, NFT_PREFIX, fam, rule_name));
		// No sticky hit: let strategy assign mark
		push(L, sprintf('\t\tmeta mark & %s == 0 jump %s_strategy_%s_%s',
			mmx_mask, NFT_PREFIX, strategy, fam));
		// Update sticky map with current assignment
		push(L, sprintf('\t\tmeta mark & %s != 0 meta mark & %s != %s update @%s_rule_%s_%s { %s : meta mark }',
			mmx_mask, mmx_mask, mmx_default, NFT_PREFIX, fam, rule_name, saddr));
		push(L, '\t}');
	}

	// Main rules chains per family
	for (let fam in ['ipv4', 'ipv6']) {
		if (fam == 'ipv6' && no_ipv6 != 0) continue;
		push(L, sprintf('\tchain %s_rules_%s {', NFT_PREFIX, fam));

		for (let rd in rule_data[fam]) {
			let prefix = sprintf('%s meta mark & %s == 0', rd.match_str, mmx_mask);

			if (rd.global_logging && rd.rule_logging)
				push(L, sprintf('\t\t%s log prefix "MWAN4(%s) " comment "%s"', prefix, rd.rule, rd.rule));

			if (rd.has_sticky)
				push(L, sprintf('\t\t%s jump %s_rule_%s_%s comment "%s"',
					prefix, NFT_PREFIX, rd.rule, fam, rd.rule));
			else
				push(L, sprintf('\t\t%s %s comment "%s"', prefix, rd.mark_action, rd.rule));
		}
		push(L, '\t}');
	}

	push(L, '}');

	let tmpfile = NFT_TEMP + '.rules';
	write_str(tmpfile, join('\n', L) + '\n');
	nft_file('install', tmpfile, NFT_RULES_FILE);
	rm(tmpfile);
}

// ── Interface Routes ─────────────────────────────────────────────────

function create_iface_route(iface) {
	foreach_family(iface, function(iface, family) {
		let id = get_iface_id(iface);
		if (!id) return;

		let ip_cmd = (family == 'ipv4') ? 'ip -4' : 'ip -6';
		if (family == 'ipv6' && no_ipv6 != 0) return;

		let existing = cmd_output(sprintf('%s route list table %d 2>/dev/null', ip_cmd, id));
		update_dev_to_table();

		for (let route_line in get_routes(family)) {
			let tid = route_line_dev(route_line, family);
			// Skip default/link-local routes belonging to other interfaces
			if ((index(route_line, 'default') == 0 || index(route_line, 'fe80::/64') == 0) && tid != id)
				continue;
			if (tid != null && tid != id)
				continue;
			// Skip if already in table
			if (length(existing) && index(existing, route_line) >= 0)
				continue;
			let rc = run(sprintf('%s route add table %d %s', ip_cmd, id, route_line));
			if (rc != 0)
				LOG('debug', sprintf("Route '%s' already in table %d", route_line, id));
		}
	});
}

function delete_iface_route(iface) {
	foreach_family(iface, function(iface, family) {
		let id = get_iface_id(iface);
		if (!id) return;
		if (family == 'ipv4')
			run(sprintf('ip -4 route flush table %d', id));
		else if (family == 'ipv6' && no_ipv6 == 0)
			run(sprintf('ip -6 route flush table %d', id));
	});
}

// ── Interface IP Rules ───────────────────────────────────────────────

function create_iface_rules(iface, device) {
	foreach_family(iface, function(iface, family, device) {
		let id = get_iface_id(iface);
		if (!id) return;

		let ip_cmd;
		if (family == 'ipv4')
			ip_cmd = 'ip -4';
		else if (family == 'ipv6' && no_ipv6 == 0)
			ip_cmd = 'ip -6';
		else
			return;

		// Delete existing rules first
		delete_iface_rules_family(iface, family);

		let mark = id2mask(id, mmx_mask);
		run(sprintf('%s rule add pref %d iif "%s" lookup %d', ip_cmd, id + 1000, device, id));
		run(sprintf('%s rule add pref %d fwmark %s/%s lookup %d', ip_cmd, id + 2000, mark, mmx_mask, id));
		run(sprintf('%s rule add pref %d fwmark %s/%s unreachable', ip_cmd, id + 3000, mark, mmx_mask));
	}, device);
}

function delete_iface_rules_family(iface, family) { // ucode-lsp disable
	let id = get_iface_id(iface);
	if (!id) return;

	let ip_cmd;
	if (family == 'ipv4')
		ip_cmd = 'ip -4';
	else if (family == 'ipv6' && no_ipv6 == 0)
		ip_cmd = 'ip -6';
	else
		return;

	for (let line in cmd_lines(sprintf('%s rule list', ip_cmd))) {
		let m = match(line, /^([0-9]+):/);
		if (!m) continue;
		let pref = int(m[1]);
		if (pref > 1000 && pref < 4000 && (pref % 1000) == id)
			run(sprintf('%s rule del pref %d', ip_cmd, pref));
	}
}

function delete_iface_rules(iface) {
	foreach_family(iface, function(iface, family) {
		delete_iface_rules_family(iface, family);
	});
}

// ── Reporting ────────────────────────────────────────────────────────

function report_iface_status() {
	let result = [];
	uci_foreach('interface', function(s) {
		let iface = s['.name'];
		foreach_family(iface, function(iface, family) {
			let id = get_iface_id(iface);
			let device = network_get_device(iface);
			let ip_cmd = (family == 'ipv4') ? 'ip -4' : 'ip -6';
			let status_iface = sprintf('%s_%s', iface, family);
			let status = read_str(sprintf('%s/%s/STATUS', TRACK_STATUS_DIR, status_iface)) || 'unknown';
			let tracking = get_mwan4track_status(iface, family);
			let detail;

			if (status == 'online') {
				let online = get_online_time(status_iface);
				let uptime = network_get_uptime(iface);
				let hotplug_state = get_iface_hotplug_state(iface);
				detail = sprintf('%s %02dh:%02dm:%02ds, uptime %02dh:%02dm:%02ds',
					hotplug_state,
					online / 3600, (online % 3600) / 60, online % 60,
					uptime / 3600, (uptime % 3600) / 60, uptime % 60);
			} else {
				let err = 0;
				let rules = cmd_output(sprintf('%s rule list', ip_cmd));
				if (id) {
					if (index(rules, (id + 1000) + ':') < 0) err += 1;
					if (index(rules, (id + 2000) + ':') < 0) err += 2;
					if (index(rules, (id + 3000) + ':') < 0) err += 4;
				}
				let chain_name = sprintf('%s_iface_in_%s_%s', NFT_PREFIX, iface, family);
				if (!length(nft_output(sprintf('list chain inet %s %s 2>/dev/null', NFT_TABLE, chain_name))))
					err += 8;
				if (id && device) {
					if (index(cmd_output(sprintf('%s route list table %d default dev %s 2>/dev/null', ip_cmd, id, device)), 'default') < 0)
						err += 16;
				}
				detail = err ? '' + err : '';
			}

			let msg;
			if (detail)
				msg = sprintf(' interface %s (%s) is %s and tracking is %s (%s)', iface, family, status, tracking, detail);
			else
				msg = sprintf(' interface %s (%s) is %s and tracking is %s', iface, family, status, tracking);
			push(result, msg);
		});
	});
	return result;
}

function get_strategies_data(family_suffix) {
	let strategies = {};
	let chains_out = nft_output(sprintf('list chains inet %s 2>/dev/null', NFT_TABLE));

	for (let line in split(chains_out, '\n')) {
		let m = match(line, /chain (mwan4_strategy_(.+)_(ipv4|ipv6))/);
		if (!m || m[3] != family_suffix) continue;

		let chain_name = m[1], strategy = m[2];
		strategies[strategy] = [];

		let chain_out = nft_output(sprintf('list chain inet %s %s 2>/dev/null', NFT_TABLE, chain_name));
		for (let cline in split(chain_out, '\n')) {
			if (index(cline, 'comment "out ') >= 0) continue;
			let cm = match(cline, /comment "([^ ]+) ([0-9]+) ([0-9]+)"/);
			if (cm) {
				push(strategies[strategy], {
					iface: cm[1],
					weight: int(cm[2]),
					total: int(cm[3]),
				});
			}
		}
	}
	return strategies;
}

function report_strategies(family_suffix) {
	let result = [];
	let strategies = get_strategies_data(family_suffix);
	for (let name in keys(strategies)) {
		push(result, name + ':');
		let entries = strategies[name];
		let total = length(entries) ? entries[0].total : 0;
		if (total > 0) {
			for (let e in entries)
				push(result, sprintf(' %s (%d%%)', e.iface, e.weight * 100 / total));
		} else if (length(entries)) {
			push(result, sprintf(' %s', entries[0].iface));
		}
	}
	return result;
}

function report_connected(family) {
	let setname = sprintf('%s_connected_%s', NFT_PREFIX, family);
	let out = nft_output(sprintf('list set inet %s %s 2>/dev/null', NFT_TABLE, setname));
	let result = [];
	let in_elements = false;
	for (let line in split(out, '\n')) {
		line = trim(line);
		if (match(line, /elements = \{/)) { in_elements = true; continue; }
		if (in_elements && match(line, /\}/)) break;
		if (in_elements && length(line)) {
			line = replace(line, /[,\s]+$/, '');
			if (length(line)) push(result, line);
		}
	}
	return result;
}

function report_rules(family) {
	let chain = sprintf('%s_rules_%s', NFT_PREFIX, family);
	let out = nft_output(sprintf('list chain inet %s %s 2>/dev/null', NFT_TABLE, chain));
	let result = [];
	for (let line in split(out, '\n')) {
		if (!match(line, /comment/)) continue;
		line = replace(line, /meta mark.*/, '');
		line = replace(line, NFT_PREFIX + '_strategy_', '- ');
		line = replace(line, NFT_PREFIX + '_rule_', 'S ');
		push(result, trim(line));
	}
	return result;
}

// ── Interface Lifecycle ──────────────────────────────────────────────

function interface_hotplug_shutdown(iface, ifdown) {
	let status = 'offline';
	for (let family in get_families(iface)) {
		let status_iface = sprintf('%s_%s', iface, family);
		let st = read_str(sprintf('%s/%s/STATUS', TRACK_STATUS_DIR, status_iface));
		if (st == 'online') { status = 'online'; break; }
	}

	if (status != 'online' && !ifdown) return;

	if (ifdown) {
		system(sprintf("env -i ACTION=ifdown INTERFACE=%s sh /etc/hotplug.d/iface/15-mwan4", iface));
	} else if (status == 'online') {
		system(sprintf("env -i MWAN4_SHUTDOWN=1 ACTION=disconnected INTERFACE=%s /sbin/hotplug-call iface", iface));
	}
}

// ── Track Cleanup ────────────────────────────────────────────────────

function track_clean(iface) {
	for (let family in get_families(iface)) {
		let status_iface = sprintf('%s_%s', iface, family);
		system(sprintf("rm -rf '%s/%s'", TRACK_STATUS_DIR, status_iface));
	}
	system(sprintf("rm -rf '%s/%s'", STATUS_DIR, iface));
}

// ── Conntrack ────────────────────────────────────────────────────────

function flush_conntrack(iface, action) {
	if (!file_exists(CONNTRACK_FILE)) return;
	let flush_list = uci_get_list(iface, 'flush_conntrack');
	for (let trigger in flush_list) {
		if (trigger == action) {
			writefile(CONNTRACK_FILE, 'f');
			LOG('info', sprintf("conntrack flushed for '%s' on '%s'", iface, action));
			break;
		}
	}
}

function interface_shutdown(iface) {
	interface_hotplug_shutdown(iface, false);
	track_clean(iface);
}

function ifup(iface, caller) {
	if (caller == 'cmd') {
		if (run('/etc/init.d/mwan4 running') != 0) {
			LOG('warn', 'mwan4 service is not running');
			return;
		}
		uci_ctx = cursor();
		uci_ctx.load('mwan4');
	}

	let true_iface = get_true_iface(iface);
	let status = ubus_call(sprintf('network.interface.%s', true_iface), 'status');
	if (!status?.up || !status?.l3_device) return;

	let l3_device = status.l3_device;
	let cmd_str = sprintf("env -i MWAN4_STARTUP=%s ACTION=ifup INTERFACE=%s DEVICE=%s sh /etc/hotplug.d/iface/15-mwan4",
		caller, iface, l3_device);
	system(cmd_str);
}

// ── Module Export ────────────────────────────────────────────────────

export default {
	// Constants
	STATUS_DIR,
	STATUS_NFT_LOG_DIR,
	TRACK_STATUS_DIR,
	CONNTRACK_FILE,
	DEFAULT_LOWEST_METRIC,
	NFT_TABLE,
	NFT_PREFIX,
	NFT_IPV4,
	NFT_IPV6,
	NFT_TEMP,
	NFT_BASE_FILE,
	NFT_SETS_FILE,
	NFT_IFACE_FILE,
	NFT_STRATEGY_FILE,
	NFT_RULES_FILE,
	IPv4_RE,
	IPv6_RE,

	// Core
	init,
	LOG,
	set_scriptname,
	read_str,
	read_int,
	cmd_lines,
	nft_file,
	nft_output,
	ubus_call,

	// UCI
	uci_bool,
	uci_get,
	uci_get_list,
	uci_foreach,

	// Getters
	get_families,
	foreach_family,
	get_true_iface,
	get_src_ip,
	get_iface_id,
	get_iface_hotplug_state,
	get_mwan4track_status,
	get_uptime,
	get_online_time,
	get_routes,

	// State accessors
	no_ipv6: () => no_ipv6,
	mmx_mask: () => mmx_mask,
	mmx_default: () => mmx_default,
	mmx_blackhole: () => mmx_blackhole,
	mmx_unreachable: () => mmx_unreachable,
	iface_max: () => iface_max,

	// Table mapping
	update_iface_to_table,
	update_dev_to_table,
	route_line_dev,

	// Hotplug state
	set_iface_hotplug_state,

	// nftables generation
	set_general_rules,
	set_general_nftables,
	set_custom_nftset,
	set_connected_ipv4,
	set_connected_ipv6,
	set_dynamic_nftset,
	begin_set_accumulation,
	install_sets_nftfile,
	rebuild_iface_nftfile,
	set_strategies_nftables,
	set_user_rules,

	// Interface management
	create_iface_route,
	delete_iface_route,
	create_iface_rules,
	delete_iface_rules,

	// Reload
	fw4_reload,
	file_exists,

	// Reporting
	report_iface_status,
	get_strategies_data,
	report_strategies,
	report_connected,
	report_rules,

	// Lifecycle
	interface_hotplug_shutdown,
	interface_shutdown,
	ifup,
	flush_conntrack,
	track_clean,
};
