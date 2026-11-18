const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { CaptureManager, parseInterfaces } = require('../server/capture-manager');

function block(type, body) {
    const result = Buffer.alloc(12 + body.length);
    result.writeUInt32LE(type);
    result.writeUInt32LE(result.length, 4);
    body.copy(result, 8);
    result.writeUInt32LE(result.length, result.length - 4);
    return result;
}

function fixture() {
    const shb = Buffer.alloc(16);
    shb.writeUInt32LE(0x1a2b3c4d);
    shb.writeUInt16LE(1, 4);
    shb.writeBigInt64LE(-1n, 8);
    const idb = Buffer.alloc(8);
    idb.writeUInt16LE(1);
    idb.writeUInt32LE(65535, 4);
    const epb = Buffer.alloc(20);
    return Buffer.concat([block(0x0a0d0d0a, shb), block(1, idb), block(6, epb)]);
}

function setup(t, overrides = {}) {
    const storagePath = fs.mkdtempSync(path.join(os.tmpdir(), 'dpi-capture-unit-'));
    const calls = [];
    const child = new EventEmitter();
    child.stderr = new PassThrough();
    child.kill = signal => { calls.push(signal); return true; };
    const options = {
        platform: 'linux', executable: 'fixture-dumpcap', storagePath,
        networkInterfaces: () => ({ lo: [] }),
        execFile: (_cmd, args, _options, callback) => {
            assert.deepEqual(args, ['-D']);
            callback(null, '1. lo (Loopback)\n2. rpcap://example\n3. sshdump', '');
        },
        spawn: (exe, args, spawnOptions) => {
            calls.push({ exe, args, spawnOptions });
            process.nextTick(() => child.emit('spawn'));
            return child;
        },
        ...overrides,
    };
    const manager = new CaptureManager(options);
    t.after(() => {
        manager.dispose();
        for (const file of fs.readdirSync(storagePath)) fs.unlinkSync(path.join(storagePath, file));
        fs.rmdirSync(storagePath);
    });
    return { manager, calls, child, storagePath, settings: { interfaceId: '1', interfaceName: 'lo', duration: 5, packetLimit: 3 } };
}

test('local adapter discovery excludes external helpers and remote sources', () => {
    const output = '1. \\Device\\NPF_Loopback (Loopback)\n2. sshdump\n3. TCP@remote:9000\n4. \\Device\\NPF_{12345678-1234-1234-1234-123456789abc} (Wi-Fi)';
    assert.deepEqual(parseInterfaces(output, 'win32', new Set()).map(i => i.id), ['1', '4']);
    assert.deepEqual(parseInterfaces('1. eth0\n2. any\n3. sshdump\n4. rpcap://remote/eth0', 'linux', new Set(['eth0'])).map(i => i.name), ['eth0','any']);
});

test('start enforces duration, packet and size limits; completion publishes actual records', async t => {
    const { manager, calls, child, settings, storagePath } = setup(t);
    const started = await manager.start(settings);
    assert.equal(started.state, 'capturing');
    const { args, exe, spawnOptions } = calls[0];
    assert.equal(exe, 'fixture-dumpcap');
    assert.equal(spawnOptions.shell, false);
    assert.equal(args[args.indexOf('-i') + 1], 'lo');
    assert.equal(args.includes('-f'), false);
    assert.ok(args.includes('duration:5'));
    assert.ok(args.some(value => /^filesize:\d+$/.test(value)));
    assert.equal(args[args.indexOf('-c') + 1], '3');
    const partial = args[args.indexOf('-w') + 1];
    assert.equal(path.dirname(partial), storagePath);
    assert.ok(partial.endsWith('.pcapng.partial'));
    await assert.rejects(manager.start(settings), { statusCode: 409 });
    const data = fixture();
    fs.writeFileSync(partial, data);
    child.emit('close', 0, null);
    const { state, result } = manager.getStatus();
    assert.equal(state, 'complete');
    assert.equal(result.packetCount, 1);
    assert.equal(result.size, data.length);
    assert.deepEqual(fs.readFileSync(result.path), data);
    assert.equal(fs.existsSync(partial), false);
    assert.equal(manager.stop().state, 'complete');
});

test('stop is idempotent and saves only complete blocks after forced shutdown', async t => {
    const { manager, calls, child, settings } = setup(t);
    await manager.start({ ...settings, filter: 'udp and port 54321' });
    const args = calls[0].args;
    assert.equal(args[args.indexOf('-f') + 1], 'udp and port 54321');
    const data = fixture();
    fs.writeFileSync(args[args.indexOf('-w') + 1], Buffer.concat([data, Buffer.alloc(7)]));
    assert.equal(manager.stop().state, 'stopping');
    assert.equal(manager.stop().state, 'stopping');
    assert.equal(calls.filter(x => x === 'SIGINT').length, 1);
    child.emit('close', null, 'SIGINT');
    const { result } = manager.getStatus();
    assert.equal(result.stopped, true);
    assert.equal(result.recoveredTail, true);
    assert.deepEqual(fs.readFileSync(result.path), data);
});

test('driver failure discards partial output and preserves diagnostics', async t => {
    const { manager, calls, child, settings, storagePath } = setup(t);
    await manager.start(settings);
    fs.writeFileSync(calls[0].args[calls[0].args.indexOf('-w') + 1], fixture());
    child.stderr.write('permission denied');
    child.emit('close', 1, null);
    assert.equal(manager.getStatus().state, 'error');
    assert.match(manager.getStatus().error, /permission denied/);
    assert.deepEqual(fs.readdirSync(storagePath), []);
});

test('unexpected malformed final block is rejected even on a clean driver exit', async t => {
    const { manager, calls, child, settings, storagePath } = setup(t);
    await manager.start(settings);
    const data = fixture();
    data.writeUInt32LE(0, data.length - 4);
    fs.writeFileSync(calls[0].args[calls[0].args.indexOf('-w') + 1], data);
    child.emit('close', 0, null);
    assert.equal(manager.getStatus().state, 'error');
    assert.equal(manager.getStatus().result, null);
    assert.deepEqual(fs.readdirSync(storagePath), []);
});

test('invalid capture requests and changed adapter selections never start a process', async t => {
    const { manager, calls, settings } = setup(t);
    for (const invalid of [{duration:301}, {duration:0}, {packetLimit:1.5}, {packetLimit:1000001}, {filter:'invalid\nfilter'}, {interfaceId:'sshdump'}, {interfaceId:'3'}, {interfaceName:'wrong-device'}]) {
        await assert.rejects(manager.start({ ...settings, ...invalid }));
    }
    assert.equal(calls.length, 0);
});

test('missing dumpcap returns install guidance and a 503 start error', async t => {
    const { manager, settings } = setup(t, { execFile: (_cmd, _args, _options, cb) => cb(Object.assign(new Error('missing'), {code:'ENOENT'})) });
    const status = await manager.listInterfaces();
    assert.equal(status.available, false);
    assert.match(status.error, /DUMPCAP_PATH/);
    await assert.rejects(manager.start(settings), { statusCode: 503 });
});
