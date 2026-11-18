const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const express = require('express');

function block(type, body) {
    const length = 12 + Math.ceil(body.length / 4) * 4;
    const result = Buffer.alloc(length);
    result.writeUInt32LE(type);
    result.writeUInt32LE(length, 4);
    body.copy(result, 8);
    result.writeUInt32LE(length, length - 4);
    return result;
}

function packet(frame, timestamp) {
    const header = Buffer.alloc(20);
    header.writeUInt32LE(timestamp, 8);
    header.writeUInt32LE(frame.length, 12);
    header.writeUInt32LE(frame.length, 16);
    return block(6, Buffer.concat([header, frame]));
}

test('upload, filter and download a PCAPNG through the workspace API', async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dpi-workspace-'));
    process.env.PCAP_STORAGE_PATH = root;
    process.env.PCAP_OUTPUT_PATH = path.join(root, 'outputs');
    process.env.HISTORY_PATH = path.join(root, 'history.json');
    process.env.RULES_PATH = path.join(root, 'rules.json');
    const app = express();
    app.use(express.json());
    for (const name of ['files', 'engine', 'rules', 'results', 'firewall']) {
        app.use('/api/' + name, require('../server/routes/' + name));
    }
    const server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(async () => {
        await new Promise(resolve => server.close(resolve));
        assert.equal(path.dirname(root), path.resolve(os.tmpdir()));
        assert.ok(path.basename(root).startsWith('dpi-workspace-'));
        fs.rmSync(root, { recursive: true, force: true });
    });
    const url = 'http://127.0.0.1:' + server.address().port + '/api/';
    async function json(route, body) {
        const response = await fetch(url + route, body ? {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
        } : {});
        const data = await response.json();
        assert.equal(response.ok, true, JSON.stringify(data)); return data;
    }
    const shb = block(0x0a0d0d0a, Buffer.from('4d3c2b1a01000000ffffffffffffffff', 'hex'));
    const idb = block(1, Buffer.from('01000000ffff0000', 'hex'));
    const arp = Buffer.from('ffffffffffff02000000000108060001080006040001020000000001c0000201000000000000c0000202', 'hex');
    const other = Buffer.from('00000000000202000000000188b5', 'hex');
    const first = packet(Buffer.concat([other, Buffer.from([1])]), 101);
    const blocked = packet(arp, 102);
    const last = packet(Buffer.concat([other, Buffer.from([2])]), 103);
    const form = new FormData();
    form.append('pcap', new Blob([shb, idb, first, blocked, last]), 'mixed.pcapng');
    const upload = await fetch(url + 'files/upload', { method: 'POST', body: form });
    assert.equal(upload.status, 200);
    const saved = await upload.json();
    assert.equal(saved.format, 'pcapng');
    assert.equal((await json('files/list'))[0].path, saved.path);
    await json('rules/protocol', { protocol: 'arp' });
    const preview = await json('firewall/preview', { directions: ['outbound'] });
    assert.equal(preview.nativeRuleCount, 0);
    assert.equal(preview.unsupported[0].value, 'arp');
    await json('engine/start', { inputFile: saved.path, outputFile: 'filtered.pcap', config: { numLbs: 1, fpsPerLb: 2 } });
    const deadline = Date.now() + 15000;
    let status;
    do {
        status = await json('engine/status');
        if (status.state !== 'processing') break;
        await new Promise(resolve => setTimeout(resolve, 30));
    } while (Date.now() < deadline);
    assert.equal(status.state, 'complete', status.errorMessage);
    const report = await json('results/latest');
    assert.equal(report.packetStats.totalPackets, 3);
    assert.equal(report.packetStats.arpPackets, 1);
    assert.equal(report.filteringStats.dropped, 1);
    assert.deepEqual(report.blockingReasons, [{ reason: 'Protocol', count: 1 }]);
    assert.equal(report.filteringStats.forwarded, 2);
    assert.equal((await json('results/history'))[0].id, report.id);
    assert.equal(path.extname(report.outputFile), '.pcapng');
    const download = await fetch(url + 'files/download/' + report.outputFile);
    assert.equal(download.status, 200);
    assert.deepEqual(Buffer.from(await download.arrayBuffer()), Buffer.concat([shb, idb, first, last]));
});
