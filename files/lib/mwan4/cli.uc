'use strict';
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 MOSSDeF, Stan Grishin (stangri@melmac.ca).
// Based on original mwan3 by Florian Eckert <fe@dev.tdt.de>

import { popen, readfile } from 'fs';
import m from 'mwan4';

function println(s) { print(s + '\n'); }

function command_help(cmd, help) {
	printf("%-25s%s\n", cmd, help);
}

function cmd_help() {
	println('Syntax: mwan4 [command]');
	println('');
	println('Available commands:');
	command_help('start',            'Load nft rules, ip rules and ip routes');
	command_help('stop',             'Unload nft rules, ip rules and ip routes');
	command_help('restart',          'Reload nft rules, ip rules and ip routes');
	command_help('ifup <iface>',     'Load rules and routes for specific interface');
	command_help('ifdown <iface>',   'Unload rules and routes for specific interface');
	command_help('interfaces',       'Show interfaces status');
	command_help('strategies',       'Show currently active strategy');
	command_help('connected',        'Show directly connected networks');
	command_help('rules',            'Show active rules');
	command_help('status',           'Show all status');
	command_help('internal <ipv4|ipv6>', 'Show internal configuration <default: ipv4>');
	command_help('use <iface> <cmd>', 'Run a command bound to <iface> and avoid mwan4 rules');
}

function cmd_ifdown(args) {
	if (!length(args)) {
		println('Error: Expecting interface. Usage: mwan4 ifdown <interface>');
		return;
	}
	if (length(args) > 1) {
		println('Error: Too many arguments. Usage: mwan4 ifdown <interface>');
		return;
	}
	m.interface_hotplug_shutdown(args[0], true);
}

function cmd_ifup(args) {
	if (!length(args)) {
		println('Error: Expecting interface. Usage: mwan4 ifup <interface>');
		return;
	}
	if (length(args) > 1) {
		println('Error: Too many arguments. Usage: mwan4 ifup <interface>');
		return;
	}
	m.ifup(args[0], 'cmd');
}

function cmd_interfaces() {
	println('Interface status:');
	for (let line in m.report_iface_status())
		println(line);
	println('');
}

function cmd_strategies() {
	println('Current ipv4 strategies:');
	for (let line in m.report_strategies('ipv4'))
		println(line);
	println('');
	if (!m.no_ipv6()) {
		println('Current ipv6 strategies:');
		for (let line in m.report_strategies('ipv6'))
			println(line);
		println('');
	}
}

function cmd_connected() {
	println('Directly connected ipv4 networks:');
	for (let line in m.report_connected('ipv4'))
		println(line);
	println('');
	if (!m.no_ipv6()) {
		println('Directly connected ipv6 networks:');
		for (let line in m.report_connected('ipv6'))
			println(line);
		println('');
	}
}

function cmd_rules() {
	println('Active ipv4 user rules:');
	for (let line in m.report_rules('ipv4'))
		println(line);
	println('');
	if (!m.no_ipv6()) {
		println('Active ipv6 user rules:');
		for (let line in m.report_rules('ipv6'))
			println(line);
		println('');
	}
}

function cmd_status() {
	cmd_interfaces();
	cmd_strategies();
	cmd_connected();
	cmd_rules();
}

function run_cmd(c) {
	let p = popen(c, 'r');
	if (!p) return '';
	let out = p.read('all') || '';
	p.close();
	return out;
}

function cmd_internal(args) {
	let family = args?.[0] || 'ipv4';
	let dash = '-------------------------------------------------';

	let release = 'unknown';
	let rdata = readfile('/etc/openwrt_release') || '';
	let m_rel = match(rdata, /DISTRIB_RELEASE='([^']+)'/);
	if (m_rel) release = m_rel[1];

	let ip = (family == 'ipv6') ? 'ip -6' : 'ip -4';

	println('Software-Version');
	println(dash);
	println('OpenWrt - ' + release);

	// ip addresses
	println('');
	println('Output of "' + ip + ' a show"');
	println(dash);
	let output = rtrim(run_cmd(ip + ' a show'));
	println(length(output) ? output : 'No data found');

	// ip routes
	println('');
	println('Output of "' + ip + ' route show"');
	println(dash);
	output = rtrim(run_cmd(ip + ' route show'));
	println(length(output) ? output : 'No data found');

	// ip rules
	println('');
	println('Output of "' + ip + ' rule show"');
	println(dash);
	output = rtrim(run_cmd(ip + ' rule show'));
	println(length(output) ? output : 'No data found');

	// routing tables 1-250
	println('');
	println('Output of "' + ip + ' route list table 1-250"');
	println(dash);
	let dump = false;
	for (let i = 1; i <= 250; i++) {
		output = rtrim(run_cmd(sprintf('%s route list table %d 2>/dev/null', ip, i)));
		if (length(output)) {
			dump = true;
			println('Routing table ' + i + ':');
			println(output);
			println('');
		}
	}
	if (!dump) {
		println('No data found');
		println('');
	}

	// nftables (replaces iptables which was never used with nftables-based mwan4)
	println('Output of "nft list table inet ' + m.NFT_TABLE + '"');
	println(dash);
	output = rtrim(run_cmd('nft list table inet ' + m.NFT_TABLE + ' 2>/dev/null'));
	println(length(output) ? output : 'No data found');
}

function shell_quote(s) {
	return "'" + replace(s, "'", "'\\''") + "'";
}

function cmd_use(args) {
	if (length(args) < 2) {
		println('Error: Usage: mwan4 use <interface> <command> [args...]');
		return 1;
	}
	let iface = shift(args);
	let st = m.ubus_call('network.interface.' + iface, 'status');
	let device = st?.l3_device || st?.device;
	if (!device) {
		warn(sprintf('could not find device for %s\n', iface));
		return 1;
	}
	let src_ip = m.get_src_ip(iface);
	if (!src_ip) {
		warn(sprintf('could not find src_ip for %s\n', iface));
		return 1;
	}
	let family = m.uci_get(iface, 'family') || 'ipv4';
	let fwmark = m.mmx_default();

	let quoted_args = map(args, shell_quote);
	let cmd = sprintf(
		'FAMILY=%s DEVICE=%s SRCIP=%s FWMARK=%s LD_PRELOAD=/lib/mwan4/libwrap_mwan4_sockopt.so.1.0 %s',
		family, device, src_ip, fwmark, join(' ', quoted_args));

	warn(sprintf("Running '%s' with DEVICE=%s SRCIP=%s FWMARK=%s FAMILY=%s\n",
		join(' ', args), device, src_ip, fwmark, family));
	return system(cmd);
}

function cmd_start() {
	system('/etc/init.d/mwan4 enable');
	system('/etc/init.d/mwan4 start');
}

function cmd_stop() {
	system('/etc/init.d/mwan4 disable');
	system('/etc/init.d/mwan4 stop');
}

function cmd_restart() {
	system('/etc/init.d/mwan4 enable');
	system('/etc/init.d/mwan4 stop');
	system('/etc/init.d/mwan4 start');
}

// ── Main ─────────────────────────────────────────────────────────────

m.set_scriptname('mwan4');

let args = ARGV;
let cmd = shift(args);

switch (cmd) {
case 'use':
case 'ifup':
case 'ifdown':
case 'interfaces':
case 'strategies':
case 'connected':
case 'rules':
case 'status':
case 'start':
case 'stop':
case 'restart':
case 'internal':
	m.init();
	switch (cmd) {
	case 'use':         exit(cmd_use(args)); break;
	case 'ifup':        cmd_ifup(args); break;
	case 'ifdown':      cmd_ifdown(args); break;
	case 'interfaces':  cmd_interfaces(); break;
	case 'strategies':  cmd_strategies(); break;
	case 'connected':   cmd_connected(); break;
	case 'rules':       cmd_rules(); break;
	case 'status':      cmd_status(); break;
	case 'start':       cmd_start(); break;
	case 'stop':        cmd_stop(); break;
	case 'restart':     cmd_restart(); break;
	case 'internal':    cmd_internal(args); break;
	}
	break;

default:
	cmd_help();
	break;
}
