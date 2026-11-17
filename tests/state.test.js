const assert = require('node:assert/strict');
const { test } = require('node:test');

// Exercise the frontend's real API adapter without a browser or running server.
const stateModule = import('../frontend/js/state.js');
const flushRequests = () => new Promise(resolve => setImmediate(resolve));
const response = body => ({ ok: true, json: async () => structuredClone(body) });
const rules = { blockedIPs: [], blockedApps: [], blockedDomains: [] };
const run = (id, packets = 12) => ({ id, inputFile: `${id}.pcap`, packetStats: { totalPackets: packets } });

async function createHarness(t) {
    const { StateManager } = await stateModule;
    const streams = [];
    const requests = [];
    const pendingResponses = new Map();
    const unexpectedRequests = [];
    const originalEventSource = Object.getOwnPropertyDescriptor(globalThis, 'EventSource');

    class FakeEventSource {
        constructor(url) {
            this.url = url;
            this.closed = false;
            streams.push(this);
        }
        open() { this.onopen?.(); }
        fail() { this.onerror?.(); }
        send(type, data) { this.onmessage?.({ data: JSON.stringify({ type, data }) }); }
        close() { this.closed = true; }
    }

    Object.defineProperty(globalThis, 'EventSource', { configurable: true, writable: true, value: FakeEventSource });
    t.mock.method(globalThis, 'fetch', async url => {
        requests.push(url);
        const next = pendingResponses.get(url)?.shift();
        if (!next) {
            unexpectedRequests.push(url);
            throw new Error(`Unexpected request: ${url}`);
        }
        return next();
    });
    const state = new StateManager();
    t.after(() => {
        clearTimeout(state._heartbeatTimer);
        clearTimeout(state._reconnectTimer);
        streams.forEach(stream => stream.close());
        if (originalEventSource) Object.defineProperty(globalThis, 'EventSource', originalEventSource);
        else delete globalThis.EventSource;
        assert.deepEqual(unexpectedRequests, [], 'All network requests must be explicitly stubbed');
        for (const [url, queued] of pendingResponses) {
            assert.equal(queued.length, 0, `Expected request was not made: ${url}`);
        }
    });

    const queue = (url, next) => {
        if (!pendingResponses.has(url)) pendingResponses.set(url, []);
        pendingResponses.get(url).push(next);
    };
    return {
        state,
        streams,
        requests,
        json(url, body) { queue(url, () => response(body)); },
        fail(url) { queue(url, () => { throw new Error('Server unavailable'); }); },
        defer(url) {
            let resolve;
            const promise = new Promise(done => { resolve = done; });
            queue(url, () => promise);
            return body => resolve(response(body));
        },
    };
}

test('opens the live stream at the same API base and announces a connected server', async t => {
    const { state, streams, requests } = await createHarness(t);
    const changes = [];
    state.on('connection', connection => changes.push(connection.state));

    assert.equal(streams.length, 1);
    assert.equal(streams[0].url, '/api/engine/stream');
    assert.equal(state.connection.state, 'connecting');
    streams[0].open();

    assert.equal(state.connection.state, 'connected');
    assert.deepEqual(changes, ['connected']);
    assert.deepEqual(requests, []);
});

test('reconnects after a lost stream and refreshes status, history, and rules', async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const harness = await createHarness(t);
    const { state, streams } = harness;
    const changes = [];
    state.on('connection', connection => changes.push(connection.state));
    streams[0].open();
    streams[0].fail();

    assert.equal(streams[0].closed, true);
    assert.equal(state.connection.state, 'reconnecting');
    t.mock.timers.runAll();
    assert.equal(streams.length, 2);
    assert.equal(streams[1].url, '/api/engine/stream');

    const completed = run('reconnected');
    const currentRules = { ...rules, blockedApps: ['DNS'] };
    harness.json('/api/engine/status', { state: 'complete' });
    harness.json('/api/results/history', [completed]);
    harness.json('/api/rules', currentRules);
    streams[1].open();
    await flushRequests();

    assert.deepEqual(changes, ['connected', 'reconnecting', 'connected']);
    assert.equal(state.status.state, 'complete');
    assert.deepEqual(state.latestResults, completed);
    assert.deepEqual(state.history, [completed]);
    assert.deepEqual(state.rules, currentRules);
    assert.deepEqual([...state.dataErrors], []);
});

test('a silently disconnected stream becomes reconnecting after 30 seconds', async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const { state, streams } = await createHarness(t);
    const changes = [];
    state.on('connection', connection => changes.push(connection.state));
    streams[0].open();

    t.mock.timers.tick(29999);
    assert.equal(state.connection.state, 'connected');
    assert.equal(streams[0].closed, false);

    t.mock.timers.tick(1);
    assert.equal(state.connection.state, 'reconnecting');
    assert.equal(streams[0].closed, true);
    assert.deepEqual(changes, ['connected', 'reconnecting']);
});

test('server heartbeats keep an idle connection alive and extend its silence deadline', async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const { state, streams, requests } = await createHarness(t);
    const output = [];
    state.on('output', text => output.push(text));
    streams[0].open();

    // An idle engine stays connected across several original timeout windows.
    for (let beat = 0; beat < 6; beat++) {
        t.mock.timers.tick(10000);
        streams[0].send('heartbeat');
        assert.equal(state.connection.state, 'connected');
    }
    assert.equal(streams.length, 1);
    assert.deepEqual(output, [], 'Heartbeats must not appear in the engine console');
    assert.deepEqual(requests, []);

    t.mock.timers.tick(29999);
    assert.equal(state.connection.state, 'connected');
    t.mock.timers.tick(1);
    assert.equal(state.connection.state, 'reconnecting');
    assert.equal(streams[0].closed, true);
});

test('routes live status, normal output, stderr, replayed output, and engine errors', async t => {
    const { state, streams } = await createHarness(t);
    const output = [];
    const replay = [];
    const errors = [];
    const statuses = [];
    state.on('output', (text, isError) => output.push({ text, isError }));
    state.on('output-history', text => replay.push(text));
    state.on('error', text => errors.push(text));
    state.on('status', status => statuses.push(status));

    streams[0].send('status', { state: 'processing', currentFile: 'capture.pcap' });
    streams[0].send('output', 'Processing packets\n');
    streams[0].send('error-output', 'Invalid packet\n');
    streams[0].send('output-history', 'Earlier output\n');
    streams[0].send('error', 'Analysis failed');

    assert.deepEqual(output, [
        { text: 'Processing packets\n', isError: false },
        { text: 'Invalid packet\n', isError: true },
    ]);
    assert.deepEqual(replay, ['Earlier output\n']);
    assert.deepEqual(errors, ['Analysis failed']);
    assert.deepEqual(statuses, [{ state: 'processing', currentFile: 'capture.pcap' }]);
    assert.deepEqual(state.status, statuses[0]);
});

test('an empty latest-results response produces an empty view rather than a fake result', async t => {
    const harness = await createHarness(t);
    const updates = [];
    harness.state.on('results', result => updates.push(result));
    harness.json('/api/results/latest', {});

    await harness.state.refreshResults();

    assert.equal(harness.state.latestResults, null);
    assert.deepEqual(updates, [null]);
    assert.deepEqual([...harness.state.dataErrors], []);
});

test('saved history restores the latest completed analysis after a page reload', async t => {
    const harness = await createHarness(t);
    const old = run('earlier');
    const latest = run('latest', 25);
    const historyUpdates = [];
    const resultUpdates = [];
    harness.state.on('history', history => historyUpdates.push(history));
    harness.state.on('results', result => resultUpdates.push(result));
    harness.json('/api/results/history', [old, latest]);

    await harness.state.refreshHistory();

    assert.deepEqual(harness.state.history, [old, latest]);
    assert.deepEqual(harness.state.latestResults, latest);
    assert.deepEqual(historyUpdates, [[old, latest]]);
    assert.deepEqual(resultUpdates, [latest]);
});

test('reports failed data sources independently and clears only the source that recovers', async t => {
    const harness = await createHarness(t);
    const updates = [];
    harness.state.on('data-errors', errors => updates.push(errors));
    harness.fail('/api/rules');
    harness.fail('/api/results/history');

    await harness.state.refreshRules();
    await harness.state.refreshHistory();
    assert.deepEqual(new Set(updates.at(-1)), new Set(['blocking rules', 'saved analyses']));

    const recoveredRules = { ...rules, blockedDomains: ['example.com'] };
    harness.json('/api/rules', recoveredRules);
    await harness.state.refreshRules();
    assert.deepEqual(harness.state.rules, recoveredRules);
    assert.deepEqual(updates.at(-1), ['saved analyses']);

    harness.json('/api/results/history', []);
    await harness.state.refreshHistory();
    assert.deepEqual(updates.at(-1), []);
    assert.deepEqual([...harness.state.dataErrors], []);
});

test('failed status and results refreshes keep the last known data until recovery', async t => {
    const harness = await createHarness(t);
    const completed = run('existing');
    harness.json('/api/engine/status', { state: 'complete' });
    harness.json('/api/results/latest', completed);
    await harness.state.refreshStatus();
    await harness.state.refreshResults();

    harness.fail('/api/engine/status');
    harness.fail('/api/results/latest');
    await harness.state.refreshStatus();
    await harness.state.refreshResults();
    assert.equal(harness.state.status.state, 'complete');
    assert.deepEqual(harness.state.latestResults, completed);
    assert.deepEqual(harness.state.dataErrors, new Set(['engine status', 'latest results']));

    harness.json('/api/engine/status', { state: 'idle' });
    harness.json('/api/results/latest', {});
    await harness.state.refreshStatus();
    await harness.state.refreshResults();
    assert.equal(harness.state.status.state, 'idle');
    assert.equal(harness.state.latestResults, null);
    assert.deepEqual([...harness.state.dataErrors], []);
});

test('a slow history request cannot replace a newer report delivered over the live stream', async t => {
    const harness = await createHarness(t);
    const old = run('old');
    const latest = run('new', 42);
    const finishOldRequest = harness.defer('/api/results/history');
    const oldRequest = harness.state.refreshHistory();

    harness.json('/api/results/history', [old, latest]);
    harness.streams[0].send('results', latest);
    await flushRequests();
    assert.deepEqual(harness.state.latestResults, latest);

    finishOldRequest([old]);
    await oldRequest;
    assert.deepEqual(harness.state.latestResults, latest);
    assert.deepEqual(harness.state.history, [old, latest]);
});

test('an empty latest-results request started earlier cannot erase a newly completed run', async t => {
    const harness = await createHarness(t);
    const completed = run('just-completed');
    const finishEmptyRequest = harness.defer('/api/results/latest');
    const earlierRequest = harness.state.refreshResults();

    harness.json('/api/results/history', [completed]);
    harness.streams[0].send('results', completed);
    await flushRequests();
    finishEmptyRequest({});
    await earlierRequest;

    assert.deepEqual(harness.state.latestResults, completed);
    assert.deepEqual(harness.state.history, [completed]);
});

test('a delayed status snapshot cannot unlock a run reported as processing by the live stream', async t => {
    const harness = await createHarness(t);
    const finishStatusRequest = harness.defer('/api/engine/status');
    const earlierRequest = harness.state.refreshStatus();
    harness.streams[0].send('status', { state: 'processing', currentFile: 'running.pcap' });
    finishStatusRequest({ state: 'idle' });
    await earlierRequest;

    assert.equal(harness.state.status.state, 'processing');
    assert.equal(harness.state.status.currentFile, 'running.pcap');
});

test('a pending rules refresh cannot undo a rule saved by the user', async t => {
    const harness = await createHarness(t);
    const finishRulesRequest = harness.defer('/api/rules');
    const earlierRequest = harness.state.refreshRules();
    const savedRules = { ...rules, blockedIPs: ['192.168.1.50'] };
    // RulesPanel publishes the server's mutation response into the shared state.
    harness.state.rules = savedRules;
    harness.state.notify('rules', savedRules);
    finishRulesRequest(rules);
    await earlierRequest;

    assert.deepEqual(harness.state.rules, savedRules);
});
