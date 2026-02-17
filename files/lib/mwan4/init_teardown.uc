'use strict';
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 MOSSDeF, Stan Grishin (stangri@melmac.ca).
// Based on original mwan3 by Florian Eckert <fe@dev.tdt.de>
//
// Called by init.d/mwan4 stop_service to tear down nftables, routes and rules.

import { unlink } from 'fs';
import m from 'mwan4';

m.set_scriptname('mwan4-init');
m.init();

// Shutdown all interfaces
m.uci_foreach('interface', function(s) {
	m.interface_shutdown(s['.name']);
});

// Flush routing tables and delete IP rules per family
for (let family in ['ipv4', 'ipv6']) {
	if (family == 'ipv6' && m.no_ipv6()) continue;
	let ip = (family == 'ipv4') ? 'ip -4' : 'ip -6';

	// Flush routing tables
	let table_lines = m.cmd_lines(ip + ' route list table all');
	let seen = {};
	for (let line in table_lines) {
		let tm = match(line, /table ([0-9]+)/);
		if (!tm) continue;
		let tid = int(tm[1]);
		if (tid > m.iface_max() || seen[tid]) continue;
		seen[tid] = true;
		system(sprintf('%s route flush table %d 2>/dev/null', ip, tid));
	}

	// Delete mwan4 IP rules (interface rules at id+1000/2000/3000, general rules)
	let rule_lines = m.cmd_lines(ip + ' rule list');
	for (let line in rule_lines) {
		let rm = match(line, /^([0-9]+):/);
		if (!rm) continue;
		let pref = int(rm[1]);
		let id = pref % 1000;
		if (pref > 1000 && pref < 4000 && id >= 1 && id <= m.iface_max() + 2)
			system(sprintf('%s rule del pref %d 2>/dev/null', ip, pref));
	}
}

// Remove nftables include and temp files (fw4 reload is triggered by service_stopped)
for (let f in [m.NFT_BASE_FILE, m.NFT_SETS_FILE, m.NFT_IFACE_FILE, m.NFT_STRATEGY_FILE, m.NFT_RULES_FILE])
	unlink(f);
system('rm -f /var/run/mwan4.nft*');

// Remove status directories
system('rm -rf /var/run/mwan4 /var/run/mwan4track');
