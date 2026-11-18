const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');

const root = path.resolve(__dirname, '..');
const executableName = process.platform === 'win32' ? 'packet_analyzer.exe' : 'packet_analyzer';
const executable = [process.env.DPI_TEST_ENGINE,
    path.join(root, 'build', 'Release', executableName),
    path.join(root, 'build', executableName),
].find((candidate) => candidate && fs.existsSync(candidate));
const bytes = (value) => Buffer.isBuffer(value) ? value : Buffer.from(value || []);
const u16 = (value) => { const buffer = Buffer.alloc(2); buffer.writeUInt16BE(value); return buffer; };
const ipv4Address = (address) => Buffer.from(address.split('.').map(Number));
function ipv6Address(address) {
    const [left, right] = address.split('::');
    const first = left ? left.split(':') : [];
    const last = right ? right.split(':') : [];
    const groups = address.includes('::') ? [...first, ...Array(8 - first.length - last.length).fill('0'), ...last] : first;
    assert.equal(groups.length, 8);
    const result = Buffer.alloc(16);
    groups.forEach((group, index) => result.writeUInt16BE(parseInt(group, 16), index * 2));
    return result;
}
function checksum(buffer) {
    let sum = 0;
    for (let i = 0; i < buffer.length; i += 2) sum += (buffer[i] << 8) | (buffer[i + 1] || 0);
    while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
    return (~sum) & 0xffff;
}
function ethernet(type, payload) {
    const header = Buffer.from('00112233445566778899aabb0000', 'hex');
    header.writeUInt16BE(type, 12);
    return Buffer.concat([header, bytes(payload)]);
}
function ip4(protocol, payload, { src = '192.0.2.1', dst = '198.51.100.2', id = 1, fragment = 0 } = {}) {
    const body = bytes(payload);
    const header = Buffer.alloc(20);
    header[0] = 0x45; header[8] = 64; header[9] = protocol;
    header.writeUInt16BE(20 + body.length, 2); header.writeUInt16BE(id, 4); header.writeUInt16BE(fragment, 6);
    ipv4Address(src).copy(header, 12); ipv4Address(dst).copy(header, 16);
    header.writeUInt16BE(checksum(header), 10);
    return Buffer.concat([header, body]);
}
function ip6(protocol, payload, { src = '2001:db8::1', dst = '2001:db8::2' } = {}) {
    const body = bytes(payload);
    const header = Buffer.alloc(40);
    header[0] = 0x60; header[6] = protocol; header[7] = 64;
    header.writeUInt16BE(body.length, 4);
    ipv6Address(src).copy(header, 8); ipv6Address(dst).copy(header, 24);
    return Buffer.concat([header, body]);
}
function tcp({ sport = 41000, dport = 80, seq = 100, ack = 0, flags = 0x18, payload = Buffer.alloc(0) } = {}) {
    const header = Buffer.alloc(20);
    header.writeUInt16BE(sport, 0); header.writeUInt16BE(dport, 2);
    header.writeUInt32BE(seq >>> 0, 4); header.writeUInt32BE(ack >>> 0, 8);
    header[12] = 0x50; header[13] = flags; header.writeUInt16BE(32768, 14);
    return Buffer.concat([header, bytes(payload)]);
}
function tcpFrame(options = {}) {
    return ethernet(options.v6 ? 0x86dd : 0x0800, (options.v6 ? ip6 : ip4)(6, tcp(options), options));
}
function udp(payload = [], { sport = 53000, dport = 53 } = {}) {
    const body = bytes(payload);
    const header = Buffer.alloc(8);
    header.writeUInt16BE(sport, 0); header.writeUInt16BE(dport, 2); header.writeUInt16BE(8 + body.length, 4);
    return Buffer.concat([header, body]);
}
function udpFrame(payload = [], options = {}) {
    return ethernet(options.v6 ? 0x86dd : 0x0800, (options.v6 ? ip6 : ip4)(17, udp(payload, options), options));
}
function arp() {
    const payload = Buffer.alloc(28);
    payload.writeUInt16BE(1, 0); payload.writeUInt16BE(0x0800, 2); payload[4] = 6; payload[5] = 4; payload.writeUInt16BE(1, 6);
    Buffer.from('66778899aabb', 'hex').copy(payload, 8);
    ipv4Address('192.0.2.1').copy(payload, 14); ipv4Address('192.0.2.2').copy(payload, 24);
    return ethernet(0x0806, payload);
}
function dns(host, response = false, id = 1) {
    const header = Buffer.alloc(12);
    header.writeUInt16BE(id, 0); header.writeUInt16BE(response ? 0x8180 : 0x0100, 2); header.writeUInt16BE(1, 4);
    const labels = host.split('.').flatMap((label) => [Buffer.from([label.length]), Buffer.from(label)]);
    return Buffer.concat([header, ...labels, Buffer.from([0, 0, 1, 0, 1])]);
}
function clientHello(host) {
    const name = Buffer.from(host);
    const entry = Buffer.concat([Buffer.from([0]), u16(name.length), name]);
    const list = Buffer.concat([u16(entry.length), entry]);
    const extension = Buffer.concat([u16(0), u16(list.length), list]);
    const body = Buffer.concat([Buffer.from([3, 3]), Buffer.alloc(32, 0x42), Buffer.from([0]), u16(2), Buffer.from([0x13, 1, 1, 0]), u16(extension.length), extension]);
    const handshake = Buffer.alloc(4); handshake[0] = 1; handshake.writeUIntBE(body.length, 1, 3);
    const record = Buffer.from([22, 3, 3, 0, 0]); record.writeUInt16BE(handshake.length + body.length, 3);
    return Buffer.concat([record, handshake, body]);
}
function http(host) { return Buffer.from(`GET /resource HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: fixture\r\n\r\n`); }
function record(frame, index, origLen = frame.length) {
    const header = Buffer.alloc(16);
    header.writeUInt32LE(1700000000 + index, 0); header.writeUInt32LE((index * 137) % 1000000, 4);
    header.writeUInt32LE(frame.length, 8); header.writeUInt32LE(origLen, 12);
    return Buffer.concat([header, frame]);
}
function capture(frames, options = {}) {
    const header = Buffer.alloc(24);
    header.writeUInt32LE(0xa1b2c3d4, 0); header.writeUInt16LE(2, 4); header.writeUInt16LE(4, 6);
    header.writeUInt32LE(65535, 16); header.writeUInt32LE(options.linkType ?? 1, 20);
    return Buffer.concat([header, ...frames.map((frame, index) => record(frame.data || frame, index, frame.origLen ?? (frame.data || frame).length))]);
}
function records(buffer) {
    assert.ok(buffer.length >= 24, 'Missing output capture header');
    assert.equal(buffer.readUInt32LE(0), 0xa1b2c3d4, 'Unexpected output capture format');
    const result = [];
    for (let offset = 24; offset < buffer.length;) {
        assert.ok(offset + 16 <= buffer.length, 'Partial record header');
        const end = offset + 16 + buffer.readUInt32LE(offset + 8);
        assert.ok(end <= buffer.length, 'Partial record payload');
        result.push(buffer.subarray(offset, end)); offset = end;
    }
    return result;
}
function stat(stdout, name) {
    const match = stdout.match(new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*:\\s*(\\d+)`, 'm'));
    assert.ok(match, `Missing ${name} in engine report:\n${stdout}`);
    return Number(match[1]);
}
function fullFlow(payload, { sport = 41000, dport = 80, split = false, outOfOrder = false } = {}) {
    const client = { sport, dport };
    const server = { src: '198.51.100.2', dst: '192.0.2.1', sport: dport, dport: sport };
    const frames = [tcpFrame({ ...client, flags: 2, seq: 100 }), tcpFrame({ ...server, flags: 0x12, seq: 900, ack: 101 }), tcpFrame({ ...client, flags: 0x10, seq: 101, ack: 901 })];
    if (split) {
        const cut = Math.floor(payload.length / 2);
        const first = tcpFrame({ ...client, seq: 101, ack: 901, payload: payload.subarray(0, cut) });
        const second = tcpFrame({ ...client, seq: 101 + cut, ack: 901, payload: payload.subarray(cut) });
        frames.push(...(outOfOrder ? [second, second, first] : [first, first, second]));
        frames.push(tcpFrame({ ...client, seq: 101 + cut - 4, payload: payload.subarray(cut - 4) }));
    } else frames.push(tcpFrame({ ...client, seq: 101, ack: 901, payload }));
    frames.push(tcpFrame({ ...server, seq: 901, ack: 101 + payload.length, payload: Buffer.from('reply') }));
    return frames;
}

test('native engine end-to-end capture filtering', { timeout: 120000 }, async (t) => {
    assert.ok(executable, 'Build the engine first with npm run build:engine.');
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'dpi-engine-tests-'));
    let sequence = 0;
    t.after(() => {
        const resolved = path.resolve(temporaryRoot);
        assert.equal(path.dirname(resolved), path.resolve(os.tmpdir()));
        assert.ok(path.basename(resolved).startsWith('dpi-engine-tests-'));
        fs.rmSync(resolved, { recursive: true, force: true });
    });
    const invoke = (inputBytes, args = [], expectedSuccess = true) => {
        const id = ++sequence;
        const input = path.join(temporaryRoot, `${id}-input.pcap`);
        const output = path.join(temporaryRoot, `${id}-output.pcap`);
        fs.writeFileSync(input, inputBytes);
        const processResult = spawnSync(executable, [input, output, ...args], { encoding: 'utf8', timeout: 45000, maxBuffer: 8 * 1024 * 1024 });
        assert.ifError(processResult.error);
        if (expectedSuccess) assert.equal(processResult.status, 0, processResult.stderr || processResult.stdout);
        else assert.notEqual(processResult.status, 0, 'Invalid input unexpectedly succeeded');
        return { ...processResult, input, output, bytes: fs.existsSync(output) ? fs.readFileSync(output) : null };
    };
    const expectFiltered = (frames, args, keptIndices) => {
        const input = capture(frames);
        const result = invoke(input, args);
        const inputRecords = records(input);
        assert.deepEqual(records(result.bytes), keptIndices.map((index) => inputRecords[index]), 'Filtered bytes, order, timestamps or wire lengths changed');
        assert.equal(stat(result.stdout, 'Total Packets'), frames.length);
        assert.equal(stat(result.stdout, 'Forwarded'), keptIndices.length);
        assert.equal(stat(result.stdout, 'Dropped'), frames.length - keptIndices.length);
        return result;
    };

    await t.test('preserves all frame types, timestamps, original lengths and order', () => {
        const truncated = tcpFrame({ payload: Buffer.from('truncated') });
        const frames = [arp(), ethernet(0x0800, ip4(1, [8, 0, 0, 0, 0, 1, 0, 1])),
            udpFrame([1, 2, 3], { v6: true, dport: 9000 }), ethernet(0x86dd, ip6(58, [128, 0, 0, 0, 0, 1, 0, 1])),
            ethernet(0x88cc, Buffer.from('unknown link payload')), ethernet(0x0800, ip4(99, [1, 2, 3])),
            { data: truncated.subarray(0, truncated.length - 3), origLen: truncated.length }];
        const input = capture(frames);
        const result = invoke(input);
        assert.deepEqual(result.bytes, input);
        assert.equal(stat(result.stdout, 'Forwarded'), frames.length);
        assert.equal(stat(result.stdout, 'ARP Packets'), 1);
        assert.equal(stat(result.stdout, 'ICMP Packets'), 1);
        assert.equal(stat(result.stdout, 'ICMPv6 Packets'), 1);
        assert.equal(stat(result.stdout, 'Unsupported'), 1);
        assert.equal(stat(result.stdout, 'Truncated'), 1);
    });
    await t.test('IPv4 exact and CIDR rules match source and destination endpoints', () => {
        const frames = [udpFrame([], { src: '10.1.2.3', dport: 9000 }), udpFrame([], { dst: '10.1.2.9', dport: 9000 }), udpFrame([], { src: '203.0.113.4', dport: 9000 })];
        expectFiltered(frames, ['--block-ip', '10.1.2.0/24'], [2]);
        expectFiltered(frames, ['--block-ip', '10.1.2.9'], [0, 2]);
    });
    await t.test('IPv6 CIDR rules match both endpoint directions', () => {
        const frames = [udpFrame([], { v6: true, src: '2001:db8:1::1', dport: 9000 }), udpFrame([], { v6: true, dst: '2001:db8:1::2', dport: 9000 }), udpFrame([], { v6: true, src: '2001:db8:2::1', dport: 9000 })];
        expectFiltered(frames, ['--block-ip', '2001:db8:1::/48'], [2]);
        expectFiltered(frames, ['--block-ip', '2001:db8:1::2'], [0, 2]);
    });
    await t.test('port ranges and protocol rules apply without guessing transport', () => {
        const frames = [tcpFrame({ sport: 40000, dport: 8080 }), tcpFrame({ sport: 8081, dport: 40001 }), udpFrame([], { dport: 8080 }), arp(), ethernet(0x0800, ip4(1, [8, 0, 0, 0])), ethernet(0x86dd, ip6(58, [128, 0, 0, 0]))];
        expectFiltered(frames, ['--block-port', 'tcp:8080-8081'], [2, 3, 4, 5]);
        expectFiltered(frames, ['--block-protocol', 'udp', '--block-protocol', 'arp', '--block-protocol', 'icmp', '--block-protocol', 'icmpv6'], [0, 1]);
    });
    await t.test('hostname blocking removes full bidirectional flow including earlier handshake', () => {
        const blocked = fullFlow(http('blocked.example'));
        const allowed = udpFrame([], { dport: 9999 });
        expectFiltered([...blocked, allowed], ['--block-domain', 'blocked.example'], [blocked.length]);
    });
    for (const [name, payload, dport] of [['HTTP', http('blocked.example'), 80], ['TLS', clientHello('blocked.example'), 443]]) {
        for (const outOfOrder of [false, true]) {
            await t.test(`${name} reassembly handles split segments, retransmission and ${outOfOrder ? 'out-of-order' : 'ordered'} arrival`, () => {
                const frames = fullFlow(payload, { dport, split: true, outOfOrder });
                const result = expectFiltered(frames, ['--block-domain', 'blocked.example'], []);
                assert.match(result.stdout, /blocked\.example ->/);
                const unblocked = invoke(capture(frames), ['--block-domain', 'unrelated.example']);
                assert.deepEqual(unblocked.bytes, capture(frames));
            });
        }
    }
    await t.test('domain rules respect label boundaries and wildcard excludes apex', () => {
        const hosts = ['example.com', 'sub.example.com', 'notexample.com', 'example.com.evil'];
        const frames = hosts.map((host, index) => udpFrame(dns(host, false, index + 1)));
        expectFiltered(frames, ['--block-domain', '*.example.com'], [0, 2, 3]);
        expectFiltered(frames, ['--block-domain', 'example.com'], [2, 3]);
    });
    await t.test('DNS query and response filtering is not sticky across a reused UDP socket', () => {
        const reverse = { src: '198.51.100.2', dst: '192.0.2.1', sport: 53, dport: 53000 };
        const frames = [udpFrame(dns('blocked.example', false, 1)), udpFrame(dns('blocked.example', true, 1), reverse), udpFrame(dns('allowed.example', false, 2)), udpFrame(dns('allowed.example', true, 2), reverse)];
        expectFiltered(frames, ['--block-domain', 'blocked.example'], [2, 3]);
    });
    for (const port of [9000, 53]) {
        await t.test(`later IPv4 fragments inherit first-fragment UDP port ${port} rule even when captured first`, () => {
            const datagram = udp(Buffer.alloc(24, 0x61), { dport: port });
            const first = ethernet(0x0800, ip4(17, datagram.subarray(0, 16), { id: 0x2233, fragment: 0x2000 }));
            const later = ethernet(0x0800, ip4(17, datagram.subarray(16), { id: 0x2233, fragment: 2 }));
            const allowed = udpFrame([], { dport: 9999 });
            expectFiltered([later, allowed, first], ['--block-port', `udp:${port}`], [1]);
        });
    }
    await t.test('reused fragment IDs keep distinct datagrams and their ports', () => {
        const split = (dport) => {
            const datagram = udp(Buffer.alloc(24, 0x61), { dport });
            return [ethernet(0x0800, ip4(17, datagram.subarray(0, 16), { id: 17, fragment: 0x2000 })),
                ethernet(0x0800, ip4(17, datagram.subarray(16), { id: 17, fragment: 2 }))];
        };
        const allowed = split(12345);
        const blocked = split(9000);
        expectFiltered([...allowed, blocked[1], blocked[0]], ['--block-port', 'udp:9000'], [0, 1]);
    });
    await t.test('Unknown rule uses finalized classification on nonstandard ports', () => {
        const known = fullFlow(http('github.com'), { dport: 11080 });
        const unknown = tcpFrame({ dport: 23456, payload: 'opaque' });
        expectFiltered([...known, unknown], ['--block-app', 'Unknown'], known.map((_, i) => i));
    });
    await t.test('incomplete streams cannot permanently exhaust the inspection budget', () => {
        const partial = Array.from({length: 300}, (_, i) => tcpFrame({sport: 42000 + i, payload: 'GET /'}));
        const known = fullFlow(http('blocked.example'), {sport: 50000});
        const result = expectFiltered([...partial, ...known], ['--block-domain', 'blocked.example', '--lbs', '1', '--fps', '1'], partial.map((_, i) => i));
        assert.ok(stat(result.stdout, 'Inspection limited') > 0);
    });
    await t.test('Netflix and Microsoft domains do not classify as Twitter', () => {
        const frames = [...fullFlow(clientHello('www.netflix.com'), { dport: 443, sport: 41001 }), ...fullFlow(clientHello('update.windows.com'), { dport: 443, sport: 41002 })];
        const result = expectFiltered(frames, ['--block-app', 'Twitter'], frames.map((_, index) => index));
        assert.match(result.stdout, /www\.netflix\.com -> Netflix/);
        assert.match(result.stdout, /update\.windows\.com -> Microsoft/);
        const netflixFrames = fullFlow(clientHello('www.netflix.com'), { dport: 443, sport: 41001 });
        expectFiltered(frames, ['--block-app', 'Netflix'], frames.map((_, index) => index).slice(netflixFrames.length));
    });
    await t.test('more than 10000 packets drain all queues without loss or reordering', () => {
        const count = 12037;
        const frame = udpFrame(Buffer.from('queue-drain-test'), { dport: 9000 });
        const input = capture(Array.from({ length: count }, () => frame));
        const result = invoke(input, ['--lbs', '4', '--fps', '2']);
        assert.deepEqual(result.bytes, input);
        assert.equal(stat(result.stdout, 'Total Packets'), count);
        assert.equal(stat(result.stdout, 'Forwarded'), count);
        const processed = [...result.stdout.matchAll(/^FP\d+ processed\s*:\s*(\d+)/gm)].reduce((sum, match) => sum + Number(match[1]), 0);
        assert.equal(processed, count, 'Worker accounting did not drain the input');
    });
    await t.test('malformed capture files fail without a successful partial output', () => {
        const valid = capture([arp()]);
        const cases = [Buffer.alloc(10), Buffer.concat([Buffer.alloc(24), Buffer.from('invalid magic')]), valid.subarray(0, valid.length - 1), Buffer.concat([valid, Buffer.from([1])])];
        for (const input of cases) {
            const result = invoke(input, [], false);
            assert.match(result.stderr, /Analysis failed:/);
            assert.equal(result.bytes, null, 'Malformed first pass created an output capture');
        }
    });
    await t.test('invalid CLI rules and unsafe output paths fail explicitly', () => {
        for (const args of [
            ['--block-ip', '999.1.2.3'], ['--block-ip', '192.0.2.1::1'], ['--block-ip', '2001:db8::/129'],
            ['--block-domain', 'bad..example'], ['--block-app', 'not-an-application'], ['--block-port', '0'],
            ['--block-port', '70000'], ['--block-port', 'tcp:90-80'], ['--block-protocol', 'ssh'],
            ['--lbs', '0'], ['--fps', '17'], ['--unknown', 'value'], ['--block-ip'],
        ]) {
            const result = invoke(capture([arp()]), args, false);
            assert.equal(result.bytes, null, `Invalid arguments created output: ${args.join(' ')}`);
        }
        const input = path.join(temporaryRoot, 'same-file.pcap');
        const original = capture([arp()]); fs.writeFileSync(input, original);
        const same = spawnSync(executable, [input, input], { encoding: 'utf8' });
        assert.notEqual(same.status, 0); assert.deepEqual(fs.readFileSync(input), original);
        const output = path.join(temporaryRoot, 'existing.pcap'); fs.writeFileSync(output, Buffer.from('keep me'));
        const existing = spawnSync(executable, [input, output], { encoding: 'utf8' });
        assert.notEqual(existing.status, 0); assert.equal(fs.readFileSync(output, 'utf8'), 'keep me');
        assert.equal(spawnSync(executable, ['--help'], { encoding: 'utf8' }).status, 0);
    });
});
