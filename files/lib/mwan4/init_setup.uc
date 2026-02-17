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

// Generate all nftables files
m.set_general_nftables();
m.begin_set_accumulation();
m.set_dynamic_nftset();
m.set_connected_ipv4();
m.set_connected_ipv6();
m.set_custom_nftset();
m.install_sets_nftfile();
m.rebuild_iface_nftfile();
m.set_strategies_nftables();
m.set_user_rules();

m.fw4_reload();
