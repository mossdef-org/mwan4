'use strict';
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 MOSSDeF, Stan Grishin (stangri@melmac.ca).
// Based on original mwan3 by Florian Eckert <fe@dev.tdt.de>

import { popen } from 'fs';
import m from 'mwan4';

m.set_scriptname('mwan4rtmon');
m.init();

let family = ARGV[0] || 'ipv4';
if (family == 'ipv6' && m.no_ipv6()) {
	m.LOG('warn', 'mwan4rtmon started for ipv6, but ipv6 not enabled on system');
	exit(1);
}

let ip = (family == 'ipv4') ? 'ip -4' : 'ip -6';

// ── Check if interface is active (nftables chain exists) ─────────────

function iface_active(iface, fam) { // ucode-lsp disable
	let chain = sprintf('%s_iface_in_%s_%s', m.NFT_PREFIX, iface, fam);
	return length(m.nft_output(sprintf('list chain inet %s %s 2>/dev/null', m.NFT_TABLE, chain))) > 0;
}

// ── Add all routes to active interface tables ────────────────────────

function add_all_routes() {
	m.update_dev_to_table();

	// Build list of active table IDs
	let active = {};
	m.uci_foreach('interface', function(s) {
		let iface = s['.name'];
		let id = m.get_iface_id(iface);
		if (!id) return;
		let iface_families = m.get_families(iface);
		for (let fam in iface_families) {
			if (fam != family) continue;
			if (iface_active(iface, fam))
				active[id] = true;
		}
	});

	if (!length(active)) return;

	let routes = m.get_routes(family);
	for (let route_line in routes) {
		let tid = m.route_line_dev(route_line, family);
		if (tid != null && active[tid]) {
			// Route maps to a known device table
			system(sprintf('%s route add table %d %s 2>/dev/null', ip, tid, route_line));
		} else if (!match(route_line, /^default/) && !match(route_line, /^fe80::\/64/)) {
			// Non-default route: add to all active tables
			for (let id in active) {
				let err = m.cmd_lines(sprintf('%s route add table %s %s 2>&1', ip, id, route_line));
				if (length(err))
					m.LOG('warn', 'failed to add', route_line, 'to table', id, '-', join(' ', err));
			}
		}
	}
}

// ── Handle a single route update event ──────────────────────────────

function handle_route(raw_line) {
	let is_delete = (index(raw_line, 'Deleted ') == 0);
	let route_line = is_delete ? substr(raw_line, 8) : raw_line;
	let action;

	if (!is_delete) {
		action = 'replace';
		// Add network prefix to connected set
		let prefix = split('' + route_line, ' ')[0];
		if (prefix)
			system(sprintf('nft add element inet %s %s_connected_%s { %s } 2>/dev/null',
				m.NFT_TABLE, m.NFT_PREFIX, family, prefix));
	} else {
		action = 'del';
		// Rebuild connected set
		if (family == 'ipv4')
			m.set_connected_ipv4();
		else
			m.set_connected_ipv6();
	}

	if (match(route_line, /linkdown/)) {
		m.LOG('debug', 'attempting to add route on down interface -', route_line);
	}

	// Clean route line (remove modifiers like offload, linkdown, expires, error)
	route_line = replace(route_line, 'offload', '');
	route_line = replace(route_line, 'linkdown ', '');
	route_line = replace(route_line, /expires [0-9]+sec/, '');
	route_line = replace(route_line, /error [0-9]+/, '');
	route_line = trim(replace(route_line, /  +/, ' '));

	// For delete: check route still exists in main table
	if (action == 'del') {
		let main_routes = m.get_routes(family);
		for (let r in main_routes) {
			if (r == route_line) {
				m.LOG('debug', 'deleted but route still exists -', route_line);
				return;
			}
		}
	}

	m.update_dev_to_table();
	let tid = m.route_line_dev(route_line, family);

	function apply_route(iface, tbl_id) {
		let track_status = m.get_mwan4track_status(iface, family);
		if (iface && track_status != 'active') {
			m.LOG('debug', 'interface', iface, 'is disabled - skipping', route_line);
			return;
		}

		// Check if action needed (table may already be flushed)
		if (action == 'del') {
			let tbl_content = m.cmd_lines(sprintf('%s route list table %d 2>/dev/null', ip, tbl_id));
			let found = false;
			for (let line in tbl_content) {
				if (line == route_line) { found = true; break; }
			}
			if (!found) {
				m.LOG('debug', 'skipping already deleted route in table', tbl_id);
				return;
			}
		}

		m.LOG('debug', sprintf('adjusting route: %s route %s table %d %s', ip, action, tbl_id, route_line));
		let err = m.cmd_lines(sprintf('%s route %s table %d %s 2>&1', ip, action, tbl_id, route_line));
		if (length(err))
			m.LOG('warn', sprintf("failed: '%s route %s table %d %s' - %s",
				ip, action, tbl_id, route_line, join(' ', err)));
	}

	if (tid != null) {
		// Route maps to known device
		apply_route(null, tid);
	} else if (!match(route_line, /^default/) && !match(route_line, /^fe80::\/64/)) {
		// Non-default, non-link-local: apply to all matching interface tables
		m.uci_foreach('interface', function(s) {
			let iface = s['.name'];
			let id = m.get_iface_id(iface);
			if (!id) return;
			let fams = m.get_families(iface);
			for (let f in fams) {
				if (f == family)
					apply_route(iface, id);
			}
		});
	}
}

// ── Main: initial setup then monitor ─────────────────────────────────

// Set connected set and populate routing tables
if (family == 'ipv4')
	m.set_connected_ipv4();
else
	m.set_connected_ipv6();

add_all_routes();

// Start monitoring route changes
let mon = popen(sprintf('%s monitor route', ip), 'r');
if (!mon) {
	m.LOG('err', 'Failed to start ip monitor route');
	exit(1);
}

let line;
while ((line = mon.read('line')) != null) {
	line = rtrim('' + line, '\n');
	if (!length(line) || index(line, 'table') >= 0) continue;
	m.LOG('debug', 'handling route update', family, line);
	handle_route(line);
}

mon.close();
