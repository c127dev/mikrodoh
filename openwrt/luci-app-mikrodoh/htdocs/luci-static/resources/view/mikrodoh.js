// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Johan Alvarado
'use strict';
'require form';
'require poll';
'require rpc';
'require view';

const callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: [ 'name' ],
	expect: { '': {} }
});

function isRunning() {
	return L.resolveDefault(callServiceList('mikrodoh'), {}).then(function(res) {
		const instances = res?.mikrodoh?.instances || {};
		return Object.values(instances).some(function(i) { return i.running; });
	});
}

function renderStatus(running) {
	const color = running ? 'green' : 'red';
	const text = running ? _('Running') : _('Not running');
	return E('em', { style: 'color:' + color }, text);
}

function positive(min) {
	return function(section_id, value) {
		if (value == null || value === '')
			return true;
		if (!/^\d+$/.test(value) || +value < min)
			return _('Expecting a whole number of at least %d').format(min);
		return true;
	};
}

return view.extend({
	render: function() {
		const m = new form.Map('mikrodoh', _('MikroDoH'),
			_('DNS-over-HTTPS proxy. Plain DNS on UDP and TCP is forwarded, encrypted, to a DoH resolver.'));

		let s = m.section(form.TypedSection);
		s.anonymous = true;
		s.render = function() {
			poll.add(function() {
				return isRunning().then(function(running) {
					const el = document.getElementById('mikrodoh_status');
					if (el)
						el.replaceChildren(renderStatus(running));
				});
			});
			return E('div', { class: 'cbi-section' }, [
				E('p', {}, [ _('Service status') + ': ',
					E('span', { id: 'mikrodoh_status' }, E('em', {}, _('Collecting data...'))) ])
			]);
		};

		s = m.section(form.NamedSection, 'main', 'mikrodoh');
		s.addremove = false;
		s.tab('general', _('General'));
		s.tab('upstream', _('Resolvers'));
		s.tab('cache', _('Cache'));
		s.tab('limits', _('Limits'));

		let o = s.taboption('general', form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('general', form.Value, 'listen_addr', _('Listen address'),
			_('IPv4 or IPv6 literal. 127.0.0.1 keeps it behind dnsmasq.'));
		o.datatype = 'ipaddr';
		o.placeholder = '0.0.0.0';

		o = s.taboption('general', form.Value, 'listen_port', _('Listen port'));
		o.datatype = 'port';
		o.placeholder = '53';

		o = s.taboption('general', form.Value, 'run_as_user', _('Run as user'));
		o.placeholder = 'nobody';

		o = s.taboption('upstream', form.Value, 'doh_url', _('Resolver URL'));
		o.placeholder = 'https://1.1.1.1/dns-query';
		o.validate = function(section_id, value) {
			if (value && !/^https:\/\/[^\s]+$/.test(value))
				return _('Expecting an https:// URL');
			return true;
		};

		o = s.taboption('upstream', form.DynamicList, 'doh_failover_url', _('Backup resolvers'),
			_('Tried in order when the main resolver fails.'));
		o.placeholder = 'https://9.9.9.9/dns-query';

		o = s.taboption('upstream', form.Value, 'doh_bootstrap', _('Bootstrap addresses'),
			_('host=address pairs, comma separated, for resolvers given by name.'));
		o.placeholder = 'dns.google=8.8.8.8,dns.google=8.8.4.4';

		o = s.taboption('upstream', form.ListValue, 'cipher', _('Cipher'));
		o.value('', _('Automatic'));
		o.value('chacha', 'ChaCha20-Poly1305');
		o.value('aes', 'AES-GCM');

		o = s.taboption('cache', form.Value, 'cache', _('Cache lifetime'),
			_('Seconds. 0 turns the cache off.'));
		o.validate = positive(0);
		o.placeholder = '0';

		o = s.taboption('cache', form.Value, 'serve_stale', _('Serve stale'),
			_('Seconds an expired answer is still served when every resolver is down. 0 turns it off.'));
		o.validate = positive(0);
		o.placeholder = '86400';

		o = s.taboption('cache', form.Flag, 'prefetch', _('Prefetch'),
			_('Refresh popular entries before they expire.'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('limits', form.Value, 'rate_limit_qps', _('Queries per second per client'),
			_('0 turns the limit off.'));
		o.validate = positive(0);
		o.placeholder = '0';

		o = s.taboption('limits', form.Value, 'max_inflight', _('Max queries in flight'));
		o.validate = positive(1);
		o.placeholder = '512';

		o = s.taboption('limits', form.Flag, 'refuse_any', _('Refuse ANY'),
			_('Answer ANY queries with a minimal HINFO record (RFC 8482).'));
		o.default = '1';
		o.rmempty = false;

		return m.render();
	}
});
