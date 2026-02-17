'use strict';
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 MOSSDeF, Stan Grishin (stangri@melmac.ca).
// Based on original mwan3 by Florian Eckert <fe@dev.tdt.de>

import { readfile } from 'fs';
import m from 'mwan4';

m.set_scriptname('mwan4-hotplug');
m.init();

let ACTION = getenv('ACTION');
let INTERFACE = getenv('INTERFACE');
let DEVICE = getenv('DEVICE');
let MWAN4_STARTUP = getenv('MWAN4_STARTUP');

// Check if mwan4 has been set up (base nft file exists)
if (!m.file_exists(m.NFT_BASE_FILE)) {
	m.LOG('warn', 'hotplug called on', INTERFACE, 'before mwan4 has been set up');
	exit(0);
}

// Check interface enabled
let enabled = m.uci_bool(m.uci_get(INTERFACE, 'enabled'));
if (!enabled) {
	m.LOG('notice', 'mwan4 hotplug on', INTERFACE, 'not called because interface disabled');
	exit(0);
}

// Determine initial status
let status;
let initial_state = m.uci_get(INTERFACE, 'initial_state') || 'online';
if (initial_state == 'offline') {
	status = 'offline';
	let families = m.get_families(INTERFACE);
	for (let family in families) {
		let status_iface = INTERFACE + '_' + family;
		let fam_status = rtrim(readfile(sprintf('%s/%s/STATUS', m.TRACK_STATUS_DIR, status_iface)) || '', '\n');
		if (fam_status == 'online') {
			status = 'online';
			break;
		}
	}
} else {
	status = 'online';
}

m.LOG('notice', sprintf('Execute %s event on interface %s (%s)', ACTION, INTERFACE, DEVICE || 'unknown'));

function signal_trackers(signame) {
	let families = m.get_families(INTERFACE);
	let svc = m.ubus_call('service', 'list', { name: 'mwan4' });
	if (!svc?.mwan4?.instances) return;

	for (let family in families) {
		let instance = 'track_' + INTERFACE + '_' + family;
		let pid = svc.mwan4.instances?.[instance]?.pid;
		if (pid)
			system(sprintf('kill -%s %d 2>/dev/null', signame, pid));
	}
}

switch (ACTION) {
case 'connected':
	m.set_iface_hotplug_state(INTERFACE, 'online');
	m.set_strategies_nftables();
	m.fw4_reload();
	break;

case 'ifup':
	m.create_iface_rules(INTERFACE, DEVICE);
	m.create_iface_route(INTERFACE);
	m.set_iface_hotplug_state(INTERFACE, status);
	if (MWAN4_STARTUP != 'init') {
		m.set_general_rules();
		m.rebuild_iface_nftfile();
		m.set_strategies_nftables();
		m.set_user_rules();
		m.fw4_reload();
	}
	signal_trackers('USR2');
	break;

case 'disconnected':
	m.set_iface_hotplug_state(INTERFACE, 'offline');
	m.set_strategies_nftables();
	m.fw4_reload();
	break;

case 'ifdown':
	m.set_iface_hotplug_state(INTERFACE, 'offline');
	m.delete_iface_rules(INTERFACE);
	m.delete_iface_route(INTERFACE);
	signal_trackers('USR1');
	m.rebuild_iface_nftfile();
	m.set_strategies_nftables();
	m.set_user_rules();
	m.fw4_reload();
	break;
}

m.flush_conntrack(INTERFACE, ACTION);
