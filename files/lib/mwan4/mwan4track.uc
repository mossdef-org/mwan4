'use strict';
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 MOSSDeF, Stan Grishin (stangri@melmac.ca).
// Based on original mwan3 by Florian Eckert <fe@dev.tdt.de>

import { popen, readfile, writefile, stat, mkdir } from 'fs';
import m from 'mwan4';

let uloop = require('uloop');

// ── Signal number resolution ─────────────────────────────────────────

function signum(name) {
	let sp = popen('kill -l ' + name, 'r');
	if (!sp) return null;
	let s = trim(sp.read('all') || '');
	sp.close();
	return int(s) || null;
}

// ── PID ──────────────────────────────────────────────────────────────

function getpid() {
	let data = readfile('/proc/self/stat') || '';
	return int(split(data, ' ')[0]) || 0;
}

// ── Arguments ────────────────────────────────────────────────────────

let INTERFACE = ARGV[0];
let FAMILY = ARGV[1] || 'ipv4';
let status_iface = INTERFACE + '_' + FAMILY;
let status_dir = m.TRACK_STATUS_DIR + '/' + status_iface;

// ── State ────────────────────────────────────────────────────────────

let DEVICE = '';
let SRC_IP = '';
let STATUS = '';
let STARTED = false;
let ifdown_event = false; // ucode-lsp disable
let ifup_event = false; // ucode-lsp disable
let PING = '';

let score, host_up_count, lost, turn;
let sleep_time; // ucode-lsp disable

// ── Config (loaded in main) ──────────────────────────────────────────

let track_method, httping_ssl, reliability, count, timeout_val, interval_val;
let down, up, pkt_size, max_ttl;
let failure_interval, keep_failure_interval, recovery_interval;
let check_quality, failure_latency, recovery_latency, failure_loss, recovery_loss;
let track_ips;

// ── Timer ────────────────────────────────────────────────────────────

let cycle_timer = null;
let track_cycle;  // forward declaration

function schedule(ms) {
	if (cycle_timer) cycle_timer.cancel();
	cycle_timer = uloop.timer(ms, track_cycle);
}

// ── Helpers ──────────────────────────────────────────────────────────

function ws(file, value) {
	writefile(status_dir + '/' + file, '' + value + '\n');
}

function hotplug(action, extra) {
	let cmd = sprintf('env -i ACTION=%s INTERFACE=%s DEVICE=%s',
		action, INTERFACE, DEVICE);
	if (extra) cmd += ' ' + extra;
	cmd += ' /sbin/hotplug-call iface';
	system(cmd);
}

function wrap(cmd) {
	return system(sprintf(
		'FAMILY=%s DEVICE=%s SRCIP=%s FWMARK=%s LD_PRELOAD=/lib/mwan4/libwrap_mwan4_sockopt.so.1.0 %s',
		FAMILY, DEVICE, SRC_IP, m.mmx_default(), cmd));
}

function wrap_output(cmd) {
	let full = sprintf(
		'FAMILY=%s DEVICE=%s SRCIP=%s FWMARK=%s LD_PRELOAD=/lib/mwan4/libwrap_mwan4_sockopt.so.1.0 %s',
		FAMILY, DEVICE, SRC_IP, m.mmx_default(), cmd);
	let p = popen(full + ' 2>/dev/null', 'r');
	if (!p) return { rc: 1, out: '' };
	let out = p.read('all') || '';
	let rc = p.close();
	return { rc, out };
}

// ── State Transitions ────────────────────────────────────────────────

function stopped() {
	STARTED = false;
	ws('STARTED', '0');
}

function started() {
	STARTED = true;
	ws('STARTED', '1');
}

function disconnected(first) {
	let prev = rtrim(readfile(status_dir + '/STATUS') || '', '\n');

	STATUS = 'offline';
	ws('STATUS', 'offline');
	ws('OFFLINE', m.get_uptime());
	ws('ONLINE', '0');
	score = 0;
	if (first) return;

	if (prev == 'online' || prev == 'disconnecting') {
		m.LOG('notice', 'Interface', INTERFACE, '(' + DEVICE + ') is offline');
		hotplug('disconnected');
	} else {
		m.LOG('notice', 'Skip disconnected event for', INTERFACE, '(' + DEVICE + ')');
	}
}

function connected(first) {
	STATUS = 'online';
	ws('STATUS', 'online');
	ws('OFFLINE', '0');
	ws('ONLINE', m.get_uptime());
	score = down + up;
	host_up_count = 0;
	lost = 0;
	turn = 0;
	m.LOG('notice', 'Interface', INTERFACE, '(' + DEVICE + ') is online');
	hotplug('connected', first ? 'FIRSTCONNECT=1' : null);
}

function disconnecting() { // ucode-lsp disable
	if (STATUS != 'disconnecting') {
		STATUS = 'disconnecting';
		ws('STATUS', 'disconnecting');
		m.LOG('notice', 'Interface', INTERFACE, '(' + DEVICE + ') is disconnecting');
		hotplug('disconnecting');
	}
}

function connecting() { // ucode-lsp disable
	if (STATUS != 'connecting') {
		STATUS = 'connecting';
		ws('STATUS', 'connecting');
		m.LOG('notice', 'Interface', INTERFACE, '(' + DEVICE + ') is connecting');
		hotplug('connecting');
	}
}

function disabled() {
	STATUS = 'disabled';
	ws('STATUS', 'disabled');
	stopped();
}

function update_track(ip, st, lat, loss_v) { // ucode-lsp disable
	writefile(status_dir + '/TRACK_' + ip, st + '\n');
	if (lat != null) {
		writefile(status_dir + '/LATENCY_' + ip, lat + '\n');
		writefile(status_dir + '/LOSS_' + ip, loss_v + '\n');
	}
}

// ── Ping Command Detection ──────────────────────────────────────────

function get_ping_command() {
	let flag = (FAMILY == 'ipv6') ? '-6' : '-4';
	let host = (FAMILY == 'ipv6') ? '::1' : '127.0.0.1';

	if (stat('/usr/bin/ping')?.type == 'file' &&
	    system(sprintf('/usr/bin/ping %s -c1 -q %s >/dev/null 2>&1', flag, host)) == 0)
		return '/usr/bin/ping ' + flag;

	if (FAMILY == 'ipv6' && stat('/usr/bin/ping6')?.type == 'file')
		return '/usr/bin/ping6';

	if (FAMILY == 'ipv4' && stat('/usr/bin/ping')?.type == 'file')
		return '/usr/bin/ping';

	if (stat('/bin/ping')?.type == 'file')
		return '/bin/ping ' + flag;

	return null;
}

function has_cmd(name) {
	return system('command -v ' + name + ' >/dev/null 2>&1') == 0;
}

function validate_track_method(method) {
	switch (method) {
	case 'ping':
		PING = get_ping_command();
		if (!PING) {
			m.LOG('warn', 'Missing ping. Please enable BUSYBOX_DEFAULT_PING and recompile busybox or install iputils-ping package.');
			return false;
		}
		return true;
	case 'arping':
		if (!has_cmd('arping')) { m.LOG('warn', 'Missing arping. Please install iputils-arping package.'); return false; }
		return true;
	case 'httping':
		if (!has_cmd('httping')) { m.LOG('warn', 'Missing httping. Please install httping package.'); return false; }
		return true;
	case 'nslookup':
		if (!has_cmd('nslookup')) { m.LOG('warn', 'Missing nslookup. Please install busybox package.'); return false; }
		return true;
	default:
		if (match(method, /^nping-/)) {
			if (!has_cmd('nping')) { m.LOG('warn', 'Missing nping. Please install nping package.'); return false; }
			return true;
		}
		m.LOG('warn', 'Unsupported tracking method:', method);
		return false;
	}
}

// ── First Connect ───────────────────────────────────────────────────

function firstconnect() {
	let true_iface = m.get_true_iface(INTERFACE, FAMILY);
	let st = m.ubus_call('network.interface.' + true_iface, 'status');
	DEVICE = st?.l3_device || st?.device || '';

	if (STATUS != 'online')
		STATUS = m.uci_get(INTERFACE, 'initial_state') || 'online';

	if (!st?.up || !DEVICE) {
		disabled();
		return;
	}

	SRC_IP = m.get_src_ip(INTERFACE, FAMILY);
	m.LOG('debug', sprintf('firstconnect: %s/%s (%s) status=%s src=%s',
		INTERFACE, true_iface, DEVICE, STATUS, SRC_IP));

	started();
	if (STATUS == 'offline')
		disconnected(true);
	else
		connected(true);
}

// ── Run Probe ───────────────────────────────────────────────────────

function run_probe(track_ip) { // ucode-lsp disable
	let result = 1, latency = 0, probe_loss = 0;

	switch (track_method) {
	case 'ping':
		if (!check_quality) {
			result = wrap(sprintf('%s -n -c %d -W %d -s %d -t %d -q %s >/dev/null 2>&1',
				PING, count, timeout_val, pkt_size, max_ttl, track_ip));
		} else {
			let r = wrap_output(sprintf('%s -n -c %d -W %d -s %d -t %d -q %s',
				PING, count, timeout_val, pkt_size, max_ttl, track_ip));
			let lm = match(r.out, /(\d+)% packet loss/);
			probe_loss = lm ? int(lm[1]) : 100;
			if (r.rc != 0 || probe_loss == 100) {
				latency = 999999; probe_loss = 100;
			} else {
				let lat = match(r.out, /(rtt|round-trip).* = [^\/]*\/(\d+)/);
				latency = lat ? int(lat[2]) : 999999;
			}
		}
		break;

	case 'arping':
		result = wrap(sprintf('arping -I %s -c %d -w %d -q %s >/dev/null 2>&1',
			DEVICE, count, timeout_val, track_ip));
		break;

	case 'httping': {
		let scheme = httping_ssl ? 'https' : 'http';
		if (!check_quality) {
			result = wrap(sprintf('httping -c %d -t %d -q "%s://%s" >/dev/null 2>&1',
				count, timeout_val, scheme, track_ip));
		} else {
			let r = wrap_output(sprintf('httping -c %d -t %d "%s://%s"',
				count, timeout_val, scheme, track_ip));
			let lm = match(r.out, /(\d+).*% failed/);
			probe_loss = lm ? int(lm[1]) : 100;
			if (r.rc != 0 || probe_loss == 100) {
				latency = 999999; probe_loss = 100;
			} else {
				let lat = match(r.out, /(rtt|round-trip).* = [^\/]*\/(\d+)/);
				latency = lat ? int(lat[2]) : 999999;
			}
		}
		break;
	}

	case 'nslookup':
		result = wrap(sprintf('nslookup www.google.com %s >/dev/null 2>&1', track_ip));
		break;

	default:
		if (match(track_method, /^nping-/)) {
			let proto = substr(track_method, 6);
			let flag = (FAMILY == 'ipv6') ? '-6' : '-4';
			let r = wrap_output(sprintf('nping %s -c %d %s --%s', flag, count, track_ip, proto));
			let lm = match(r.out, /Lost.*?(\d+)/);
			result = lm ? int(lm[1]) : 1;
		}
		break;
	}

	return { result, latency, loss: probe_loss };
}

// ── Tracking Cycle ──────────────────────────────────────────────────

track_cycle = function() {
	// Handle pending signal events
	if (ifdown_event) {
		ifdown_event = false;
		m.LOG('info', 'Detect ifdown event on interface', INTERFACE, '(' + DEVICE + ')');
		disconnected();
		disabled();
		return;  // stay disabled until ifup signal
	}
	if (ifup_event) {
		ifup_event = false;
		m.LOG('info', 'Detect ifup event on interface', INTERFACE, '(' + DEVICE + ')');
		firstconnect();
		if (STARTED)
			schedule(interval_val * 1000);
		return;
	}

	if (!STARTED) return;

	sleep_time = interval_val;
	host_up_count = 0;

	// Run probes
	for (let track_ip in track_ips) {
		if (host_up_count >= reliability) {
			writefile(status_dir + '/TRACK_' + track_ip, 'skipped\n');
			continue;
		}

		let p = run_probe(track_ip);
		let do_log = '';

		if (!check_quality) {
			if (p.result == 0) {
				host_up_count++;
				update_track(track_ip, 'up');
				if (score <= up) do_log = 'success';
			} else {
				lost++;
				update_track(track_ip, 'down');
				if (score > up) do_log = 'failed';
			}
			if (do_log)
				m.LOG('info', sprintf('Check (%s) %s for target "%s" on interface %s (%s). Score: %d',
					track_method, do_log, track_ip, INTERFACE, DEVICE, score));
		} else {
			if (p.loss >= failure_loss || p.latency >= failure_latency) {
				lost++;
				update_track(track_ip, 'down', p.latency, p.loss);
				if (score > up) do_log = 'failed';
			} else if (p.loss <= recovery_loss && p.latency <= recovery_latency) {
				host_up_count++;
				update_track(track_ip, 'up', p.latency, p.loss);
				if (score <= up) do_log = 'success';
			} else {
				writefile(status_dir + '/TRACK_' + track_ip, 'skipped\n');
			}
			if (do_log)
				m.LOG('info', sprintf('Check (%s: latency=%dms loss=%d%%) %s for target "%s" on %s (%s). Score: %d',
					track_method, p.latency, p.loss, do_log, track_ip, INTERFACE, DEVICE, score));
		}
	}

	// Evaluate score
	if (host_up_count < reliability) {
		score--;
		if (score < up) {
			score = 0;
			if (keep_failure_interval) sleep_time = failure_interval;
		} else if (score == up) {
			disconnecting();
			sleep_time = failure_interval;
			disconnected();
		} else {
			disconnecting();
			sleep_time = failure_interval;
		}
	} else {
		if (score < (down + up) && lost > 0)
			m.LOG('info', sprintf('Lost %d ping(s) on interface %s (%s). Score: %d',
				lost * count, INTERFACE, DEVICE, score));

		score++;
		lost = 0;

		if (score < up) {
			connecting();
			sleep_time = recovery_interval;
		} else if (score == up) {
			connecting();
			sleep_time = recovery_interval;
			connected();
		} else {
			ws('STATUS', 'online');
			score = down + up;
		}
	}

	turn++;
	ws('LOST', lost);
	ws('SCORE', score);
	ws('TURN', turn);
	ws('TIME', m.get_uptime());

	schedule(sleep_time * 1000);
};

// ── Clean Up ────────────────────────────────────────────────────────

function clean_up() {
	m.LOG('notice', sprintf('Stopping mwan4track for interface "%s". Status was "%s"',
		INTERFACE, STATUS));
	uloop.done();
}

// ── Main ────────────────────────────────────────────────────────────

m.set_scriptname('mwan4track');
m.init();

// Set up status directory
mkdir(status_dir);
writefile(status_dir + '/PID', '' + getpid() + '\n');
stopped();

// Load config
track_method = m.uci_get(INTERFACE, 'track_method') || 'ping';
httping_ssl = m.uci_bool(m.uci_get(INTERFACE, 'httping_ssl'));
if (!validate_track_method(track_method)) {
	track_method = 'ping';
	if (validate_track_method(track_method))
		m.LOG('warn', 'Using ping to track interface', INTERFACE, 'availability');
	else {
		m.LOG('err', 'No track method available');
		exit(1);
	}
}

reliability    = int(m.uci_get(INTERFACE, 'reliability'))     || 1;
count          = int(m.uci_get(INTERFACE, 'count'))           || 1;
timeout_val    = int(m.uci_get(INTERFACE, 'timeout'))         || 4;
interval_val   = int(m.uci_get(INTERFACE, 'interval'))        || 10;
down           = int(m.uci_get(INTERFACE, 'down'))            || 5;
up             = int(m.uci_get(INTERFACE, 'up'))              || 5;
pkt_size       = int(m.uci_get(INTERFACE, 'size'))            || 56;
max_ttl        = int(m.uci_get(INTERFACE, 'max_ttl'))         || 60;
failure_interval  = int(m.uci_get(INTERFACE, 'failure_interval'))  || interval_val;
keep_failure_interval = m.uci_bool(m.uci_get(INTERFACE, 'keep_failure_interval'));
recovery_interval = int(m.uci_get(INTERFACE, 'recovery_interval')) || interval_val;
check_quality  = m.uci_bool(m.uci_get(INTERFACE, 'check_quality'));
failure_latency   = int(m.uci_get(INTERFACE, 'failure_latency'))   || 1000;
recovery_latency  = int(m.uci_get(INTERFACE, 'recovery_latency'))  || 500;
failure_loss      = int(m.uci_get(INTERFACE, 'failure_loss'))      || 40;
recovery_loss     = int(m.uci_get(INTERFACE, 'recovery_loss'))     || 10;

track_ips = m.uci_get_list(INTERFACE, 'track_ip') || [];

score = down + up;
host_up_count = 0;
lost = 0;
turn = 0;

// Initialize uloop
uloop.init();

// Register signal handlers
let sig_usr1 = signum('USR1');
let sig_usr2 = signum('USR2');
let sig_term = signum('TERM');

if (sig_usr1) uloop.signal(sig_usr1, () => {
	ifdown_event = true;
	if (cycle_timer) { cycle_timer.cancel(); cycle_timer = null; }
	schedule(1);  // process immediately
});

if (sig_usr2) uloop.signal(sig_usr2, () => {
	ifup_event = true;
	if (cycle_timer) { cycle_timer.cancel(); cycle_timer = null; }
	schedule(1);  // process immediately
});

if (sig_term) uloop.signal(sig_term, clean_up);

// Initial connect and start tracking
firstconnect();
if (STARTED)
	schedule(interval_val * 1000);

uloop.run();
