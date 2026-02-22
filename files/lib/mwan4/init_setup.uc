'use strict';
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 MOSSDeF, Stan Grishin (stangri@melmac.ca).
// Based on original mwan3 by Florian Eckert <fe@dev.tdt.de>
//
// Called by init.d/mwan4 start_service to set up nftables, routes and rules.
// Procd instance management (trackers, rtmon) stays in shell.

import m from 'mwan4';

m.set_scriptname('mwan4-init');
m.init();

m.update_iface_to_table();
m.set_general_rules();

// ifup all enabled interfaces (creates IP rules and sets hotplug state)
m.uci_foreach('interface', function(s) {
	m.ifup(s['.name'], 'init');
});

// Generate dynamic file (base structure + interfaces + strategies)
m.rebuild_dynamic();

// Generate rules file (sets + user rules)
m.nft_file('create', 'rules');
m.set_dynamic_nftset();
m.set_connected_ipv4();
m.set_connected_ipv6();
m.set_custom_nftset();
m.set_user_rules();

// Validate combined and install
m.nft_file('install', 'all');
m.fw4_reload();
