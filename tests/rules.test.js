const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const { test } = require('node:test');
const express = require('express');
const { normalizeRule, normalizeRules, emptyRules, RuleValidationError } = require('../server/rule-validation');

test('IP rules normalize hosts and IPv4/IPv6 CIDR networks', () => {
    const cases = [
        [' 192.168.1.8 ', '192.168.1.8'],
        ['192.168.1.129/24', '192.168.1.0/24'],
        ['192.168.1.129/25', '192.168.1.128/25'],
        ['192.168.1.8/32', '192.168.1.8'],
        ['203.0.113.1/0', '0.0.0.0/0'],
        ['2001:0DB8:0000:0000:0000:0000:0000:0001', '2001:db8::1'],
        ['2001:db8:abcd:1234::1/48', '2001:db8:abcd::/48'],
        ['2001:db8:0:0:8000::1/65', '2001:db8:0:0:8000::/65'],
        ['2001:db8::1/128', '2001:db8::1'],
        ['ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0', '::/0'],
        ['::ffff:192.0.2.128', '::ffff:c000:280'],
        ['0:0:1:0:0:1:0:0', '::1:0:0:1:0:0'],
        ['::1', '::1'],
    ];
    for (const [input, expected] of cases) assert.equal(normalizeRule('ip', input), expected, input);
    for (const invalid of ['192.168.1.256', '127.1', '1.2.3', '01.2.3.4', '1.2.3.4/', '1.2.3.4/33', '1.2.3.4/-1', '1.2.3.4/1.5', '1.2.3.4/24/1', '2001:db8::/129', '2001:::1', '[::1]', 'fe80::1%eth0', '::ffff:300.0.0.1']) {
        assert.throws(() => normalizeRule('ip', invalid), RuleValidationError, invalid);
    }
});

test('domain rules preserve boundary and wildcard intent while canonicalizing DNS names', () => {
    assert.equal(normalizeRule('domain', ' EXAMPLE.com. '), 'example.com');
    assert.equal(normalizeRule('domain', '*.Example.COM'), '*.example.com');
    assert.notEqual(normalizeRule('domain', '*.example.com'), normalizeRule('domain', 'example.com'));
    assert.equal(normalizeRule('domain', 'notexample.com'), 'notexample.com');
    assert.equal(normalizeRule('domain', 'bücher.example'), 'xn--bcher-kva.example');
    for (const invalid of ['https://example.com', 'example.com/path', 'example.com:443', 'user@example.com', 'example..com', '-example.com', 'example-.com', '*example.com', 'foo.*.com', '*', '127.0.0.1', '::1', 'example.com?query', 'example%2ecom', 'example\\com', 'a'.repeat(64) + '.com']) {
        assert.throws(() => normalizeRule('domain', invalid), RuleValidationError, invalid);
    }
});

test('port, protocol, and application rule values have canonical allowlisted forms', () => {
    for (const [input, expected] of [['443', '443'], ['TCP:00080-00080', 'tcp:80'], ['udp:53', 'udp:53'], ['tcp:8000-8080', 'tcp:8000-8080'], ['1-65535', '1-65535']]) {
        assert.equal(normalizeRule('port', input), expected);
    }
    for (const invalid of ['0', '65536', '-1', '100-50', 'tcp:0-80', 'udp:1-65536', 'icmp:80', '80,443', '80-90-100', 'tcp: 80', '80/tcp', '1.5']) {
        assert.throws(() => normalizeRule('port', invalid), RuleValidationError, invalid);
    }
    for (const protocol of ['tcp', 'udp', 'icmp', 'icmpv6', 'arp']) {
        assert.equal(normalizeRule('protocol', protocol.toUpperCase()), protocol);
    }
    for (const invalid of ['other', 'https', 'all', '6']) assert.throws(() => normalizeRule('protocol', invalid), RuleValidationError);
    assert.equal(normalizeRule('app', 'youtube'), 'YouTube');
    assert.equal(normalizeRule('app', 'twitter'), 'Twitter/X');
    assert.equal(normalizeRule('app', 'twitter/x'), 'Twitter/X');
    assert.equal(normalizeRule('app', 'UNKNOWN'), 'Unknown');
    assert.throws(() => normalizeRule('app', 'UnrecognizedApp'), RuleValidationError);
    for (const invalid of ['', '  ', null, undefined, 80, false, [], {}]) {
        assert.throws(() => normalizeRule('ip', invalid), RuleValidationError);
    }
    for (const type of ['unknown', '__proto__', 'constructor']) assert.throws(() => normalizeRule(type, 'anything'), RuleValidationError);
});

test('legacy policy loading adds new arrays and removes canonical duplicates', () => {
    assert.deepEqual(normalizeRules({ blockedIPs: ['192.168.1.4/24', '192.168.1.0/24'], blockedApps: ['Twitter', 'twitter/x'], blockedDomains: ['EXAMPLE.COM'] }), {
        blockedIPs: ['192.168.1.0/24'], blockedApps: ['Twitter/X'], blockedDomains: ['example.com'], blockedPorts: [], blockedProtocols: [],
    });
    assert.deepEqual(normalizeRules({}), emptyRules());
    assert.throws(() => normalizeRules({ blockedIPs: 'not-an-array' }), RuleValidationError);
    assert.throws(() => normalizeRules({ blockedPorts: ['65536'] }), RuleValidationError);
    assert.throws(() => normalizeRules(null), RuleValidationError);
});

test('rules API validates, persists, and returns isolated policy snapshots', async t => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'dpi-rules-tests-'));
    const rulesPath = path.join(temporaryRoot, 'rules.json');
    const configPath = require.resolve('../server/config');
    const managerPath = require.resolve('../server/rules-manager');
    const routerPath = require.resolve('../server/routes/rules');
    const originals = new Map([configPath, managerPath, routerPath].map(filename => [filename, require.cache[filename]]));
    let server;
    t.after(async () => {
        if (server?.listening) await new Promise(resolve => server.close(resolve));
        for (const [filename, original] of originals) {
            if (original) require.cache[filename] = original;
            else delete require.cache[filename];
        }
        const resolvedRoot = path.resolve(temporaryRoot);
        assert.equal(path.dirname(resolvedRoot), path.resolve(os.tmpdir()));
        assert.ok(path.basename(resolvedRoot).startsWith('dpi-rules-tests-'));
        fs.rmSync(resolvedRoot, { recursive: true, force: true });
    });

    require.cache[configPath] = { id: configPath, filename: configPath, loaded: true, exports: { RULES_PATH: rulesPath } };
    delete require.cache[managerPath];
    delete require.cache[routerPath];
    const manager = require('../server/rules-manager');
    const app = express();
    app.use(express.json());
    app.use('/api/rules', require(routerPath));
    server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const base = `http://127.0.0.1:${server.address().port}/api/rules`;
    const request = async (method, suffix = '', body) => {
        const response = await fetch(base + suffix, {
            method,
            headers: { 'Content-Type': 'application/json', Connection: 'close' },
            ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        });
        return { status: response.status, body: await response.json() };
    };

    await t.test('new policy is empty without touching a runtime data file', async () => {
        assert.deepEqual((await request('GET')).body, emptyRules());
        assert.equal(fs.existsSync(rulesPath), false);
    });
    await t.test('all five types normalize and persist', async () => {
        for (const [type, value, key, canonical] of [
            ['ip', '2001:db8::1234/64', 'blockedIPs', '2001:db8::/64'],
            ['app', 'twitter', 'blockedApps', 'Twitter/X'],
            ['domain', '*.EXAMPLE.COM.', 'blockedDomains', '*.example.com'],
            ['port', 'TCP:00443-00443', 'blockedPorts', 'tcp:443'],
            ['protocol', 'ICMPv6', 'blockedProtocols', 'icmpv6'],
        ]) {
            const result = await request('POST', '/' + type, { [type]: value });
            assert.equal(result.status, 200);
            assert.ok(result.body[key].includes(canonical));
            assert.deepEqual(JSON.parse(fs.readFileSync(rulesPath, 'utf8')), result.body);
        }
    });
    await t.test('equivalent networks and case variants do not create duplicates', async () => {
        const before = manager.getRules();
        await request('POST', '/ip', { ip: '2001:0db8:0:0:ffff::/64' });
        await request('POST', '/app', { app: 'TWITTER/X' });
        assert.deepEqual(manager.getRules(), before);
    });
    await t.test('invalid and missing values return 400 without changing memory or disk', async () => {
        const before = manager.getRules();
        const beforeFile = fs.readFileSync(rulesPath, 'utf8');
        for (const [suffix, body] of [
            ['/ip', { ip: '999.2.3.4' }], ['/ip', {}], ['/ip', { ip: 123 }],
            ['/app', { app: 'NotAnApplication' }], ['/domain', { domain: 'https://example.com' }],
            ['/port', { port: '80-2' }], ['/protocol', { protocol: 'other' }],
            ['/unknown', { unknown: 'x' }], ['/constructor', { constructor: 'x' }],
            ['/ip', []], ['', { ip: '192.0.2.1' }],
        ]) {
            const result = await request('POST', suffix, body);
            assert.equal(result.status, 400, suffix);
            assert.equal(typeof result.body.error, 'string');
            assert.deepEqual(manager.getRules(), before);
            assert.equal(fs.readFileSync(rulesPath, 'utf8'), beforeFile);
        }
        assert.equal((await request('DELETE', '/ip')).status, 400);
        assert.equal((await request('DELETE', '/unknown/value')).status, 400);
    });
    await t.test('encoded CIDR and slash-containing applications can be removed', async () => {
        const cidr = await request('DELETE', '/ip/' + encodeURIComponent('2001:db8::abcd/64'));
        assert.equal(cidr.status, 200);
        assert.deepEqual(cidr.body.blockedIPs, []);
        const appResult = await request('DELETE', '/app/' + encodeURIComponent('Twitter/X'));
        assert.equal(appResult.status, 200);
        assert.deepEqual(appResult.body.blockedApps, []);
    });
    await t.test('callers cannot mutate the saved policy through returned snapshots', () => {
        const snapshot = manager.getRules();
        snapshot.blockedDomains.push('accidental.example');
        assert.ok(!manager.getRules().blockedDomains.includes('accidental.example'));
    });
    await t.test('failed writes return 500 and leave the previous policy intact', async () => {
        const before = manager.getRules();
        const beforeFile = fs.readFileSync(rulesPath, 'utf8');
        const blockedDestination = path.join(temporaryRoot, 'not-a-file');
        fs.mkdirSync(blockedDestination);
        manager.filePath = blockedDestination;
        try {
            const failedAdd = await request('POST', '/port', { port: '8080' });
            assert.equal(failedAdd.status, 500);
            assert.match(failedAdd.body.error, /could not be saved/);
            assert.deepEqual(manager.getRules(), before);
            const failedDelete = await request('DELETE', '/domain/' + encodeURIComponent('*.example.com'));
            assert.equal(failedDelete.status, 500);
            assert.deepEqual(manager.getRules(), before);
            assert.equal((await request('DELETE')).status, 500);
            assert.deepEqual(manager.getRules(), before);
            assert.equal(fs.readFileSync(rulesPath, 'utf8'), beforeFile);
            assert.deepEqual(fs.readdirSync(temporaryRoot).filter(name => name.endsWith('.tmp')), []);
        } finally {
            manager.filePath = rulesPath;
        }
    });
    await t.test('invalid saved rules fail visibly instead of silently allowing traffic', () => {
        const corruptPath = path.join(temporaryRoot, 'invalid-rules.json');
        fs.writeFileSync(corruptPath, JSON.stringify({ blockedIPs: ['not-an-address'] }));
        const invalidManager = new manager.RulesManager(corruptPath);
        assert.throws(() => invalidManager.getRules(), /could not be loaded/);
        assert.throws(() => invalidManager.addPort('443'), /could not be loaded/);
        assert.deepEqual(JSON.parse(fs.readFileSync(corruptPath, 'utf8')), { blockedIPs: ['not-an-address'] });
    });
    await t.test('clear resets all five rule families and persists the result', async () => {
        const result = await request('DELETE');
        assert.equal(result.status, 200);
        assert.deepEqual(result.body, emptyRules());
        assert.deepEqual(JSON.parse(fs.readFileSync(rulesPath, 'utf8')), emptyRules());
    });
});
