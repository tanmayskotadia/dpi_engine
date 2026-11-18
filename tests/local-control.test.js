const test = require('node:test');
const assert = require('node:assert/strict');
const { localControl } = require('../server/local-control');

function request(overrides = {}) {
    const req = { method: 'POST', socket: { remoteAddress: '127.0.0.1' }, headers: { host: 'localhost:3000', origin: 'http://localhost:3000' }, is: value => value === 'application/json', ...overrides };
    let status = 200, body, next = false;
    const res = { status(code) { status = code; return this; }, json(value) { body = value; return this; }, setHeader() {} };
    localControl(req, res, () => { next = true; });
    return { status, body, next };
}
test('local controls accept same-origin localhost JSON and local Vite', () => {
    assert.equal(request().next, true);
    assert.equal(request({ headers: { host: 'localhost:3000', origin: 'http://localhost:5173' } }).next, true);
    assert.equal(request({ headers: { host: '[::1]:3000', origin: 'http://[::1]:3000' }, socket: { remoteAddress: '::1' } }).next, true);
});
test('local controls reject remote clients, forwarded IP spoofing and DNS rebinding', () => {
    assert.equal(request({ socket: { remoteAddress: '192.168.1.10' }, headers: { host: 'localhost:3000', 'x-forwarded-for': '127.0.0.1' } }).status, 403);
    assert.equal(request({ headers: { host: 'evil.example:3000', origin: 'http://evil.example:3000' } }).status, 403);
});
test('local controls reject foreign origins, cross-site requests and simple forms', () => {
    for (const origin of ['https://evil.example', 'null', 'http://localhost:9999', 'file://localhost']) {
        assert.equal(request({ headers: { host: 'localhost:3000', origin } }).status, 403);
    }
    assert.equal(request({ headers: { host: 'localhost:3000', 'sec-fetch-site': 'cross-site' } }).status, 403);
    assert.equal(request({ is: () => false }).status, 415);
    assert.equal(request({ method: 'DELETE', is: () => false }).status, 415);
});
