const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter, once } = require('node:events');
const { PassThrough, Writable } = require('node:stream');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const express = require('express');
const { FirewallManager, FirewallError, buildFirewallPlan, runPowerShell, MANAGED_GROUP } = require('../server/firewall-manager');
const { emptyRules } = require('../server/rule-validation');
const sample = () => ({ ...emptyRules(), blockedIPs: ['192.0.2.42/24'], blockedPorts: ['443', 'udp:53'], blockedProtocols: ['icmpv6', 'arp'], blockedApps: ['YouTube'], blockedDomains: ['*.example.com'] });
const nativeStatus = (extra = {}) => ({ supported: true, available: true, statusKnown: true, elevated: true, installedCount: 0, enabledCount: 0, activeCount: 0, profiles: [{ name: 'Public', enabled: true }], rules: [], ...extra });

test('firewall preview maps explicit native scopes and exposes every unsupported rule', () => {
    const plan = buildFirewallPlan(sample(), ['inbound', 'outbound']);
    assert.equal(plan.nativeRuleCount, 10);
    assert.equal(plan.group, MANAGED_GROUP);
    assert.equal(plan.entries.find(entry => entry.kind === 'ip').remoteAddress, '192.0.2.0/24');
    assert.deepEqual(plan.entries.filter(entry => entry.value === '443').map(entry => [entry.direction, entry.protocol, entry.localPort, entry.remotePort]), [
        ['Inbound', 'TCP', '443', undefined], ['Inbound', 'UDP', '443', undefined],
        ['Outbound', 'TCP', undefined, '443'], ['Outbound', 'UDP', undefined, '443'],
    ]);
    assert.ok(plan.entries.some(entry => entry.protocol === 'ICMPv6'));
    assert.deepEqual(plan.unsupported.map(item => item.type + ':' + item.value), ['app:YouTube', 'domain:*.example.com', 'protocol:arp']);
    assert.ok(plan.entries.every(entry => !entry.label.includes('example.com') && !entry.label.includes('YouTube')));
    assert.equal(buildFirewallPlan(sample(), ['outbound', 'outbound']).nativeRuleCount, 5);
    for (const directions of [undefined, [], ['any'], ['Inbound'], 'outbound']) {
        assert.throws(() => buildFirewallPlan(sample(), directions), /traffic directions/);
    }
    assert.throws(() => buildFirewallPlan({ ...emptyRules(), blockedPorts: Array.from({ length: 129 }, (_, index) => String(index + 1)) }, ['inbound', 'outbound']), /at most 256/);
});

test('firewall mutations require an exact reviewed immutable and unexpired token', async () => {
    let now = 1000;
    const calls = [];
    const manager = new FirewallManager({ platform: 'win32', now: () => now, run: async payload => {
        calls.push(structuredClone(payload));
        return nativeStatus({ installedCount: payload.action === 'apply' ? payload.plan.nativeRuleCount : 0 });
    } });
    const rules = sample();
    const preview = manager.preview(rules, ['outbound']);
    rules.blockedIPs.push('203.0.113.1');
    preview.entries[0].remoteAddress = '0.0.0.0/0';
    const applied = await manager.apply(preview.token);
    assert.equal(applied.installedCount, 5);
    assert.equal(calls[1].plan.entries[0].remoteAddress, '192.0.2.0/24');
    assert.equal(calls[1].plan.nativeRuleCount, 5);
    assert.equal(calls.length, 2);
    await assert.rejects(manager.apply(preview.token), error => error.status === 409);
    const expired = manager.preview(sample(), ['outbound']);
    now += 300001;
    await assert.rejects(manager.apply(expired.token), /expired/);
    await assert.rejects(manager.apply('arbitrary-token'), /missing or expired/);
    assert.equal(calls.length, 2);
});

test('unsupported platforms, missing elevation, and capture-only policies never mutate native rules', async () => {
    const nonWindows = new FirewallManager({ platform: 'linux', run: () => { throw new Error('Native process must not run'); } });
    assert.equal((await nonWindows.status()).supported, false);
    await assert.rejects(nonWindows.apply('x'), /Windows/);
    await assert.rejects(nonWindows.remove(), /Windows/);
    const actions = [];
    const noAdmin = new FirewallManager({ platform: 'win32', run: async payload => { actions.push(payload.action); return nativeStatus({ elevated: false }); } });
    const preview = noAdmin.preview(sample(), ['outbound']);
    await assert.rejects(noAdmin.apply(preview.token), error => error.status === 403);
    await assert.rejects(noAdmin.remove(), error => error.status === 403);
    assert.deepEqual(actions, ['status', 'status']);
    const empty = noAdmin.preview({ ...emptyRules(), blockedApps: ['YouTube'], blockedDomains: ['example.com'], blockedProtocols: ['arp'] }, ['outbound']);
    await assert.rejects(noAdmin.apply(empty.token), /no supported native/);
    assert.deepEqual(actions, ['status', 'status']);
});

test('concurrent changes are serialized and native rollback failures remain explicit', async () => {
    let release;
    let called;
    const started = new Promise(resolve => { called = resolve; });
    const manager = new FirewallManager({ platform: 'win32', run: async payload => {
        if (payload.action === 'status') return nativeStatus();
        called();
        return new Promise(resolve => { release = resolve; });
    } });
    const preview = manager.preview(sample(), ['outbound']);
    const pending = manager.apply(preview.token);
    await started;
    await assert.rejects(manager.remove(), error => error.status === 409);
    await assert.rejects(manager.apply(preview.token), error => error.status === 409);
    release(nativeStatus({ installedCount: 5 }));
    await pending;
    assert.equal(manager.busy, false);

    const failure = new FirewallError('Rollback was incomplete.', 500, { rollbackSucceeded: false, stateUnconfirmed: true });
    const failing = new FirewallManager({ platform: 'win32', run: async payload => {
        if (payload.action === 'status') return nativeStatus();
        throw failure;
    } });
    await assert.rejects(failing.apply(failing.preview(sample(), ['outbound']).token), error => error.rollbackSucceeded === false && error.stateUnconfirmed === true);
    assert.equal(failing.busy, false);
});

function mockProcess(result, code = 0) {
    let invocation;
    let input = '';
    return {
        get invocation() { return invocation; },
        get input() { return input; },
        spawn(executable, args, options) {
            invocation = { executable, args, options };
            const child = new EventEmitter();
            child.stdout = new PassThrough();
            child.stderr = new PassThrough();
            child.kill = () => {};
            child.stdin = new Writable({ write(chunk, _encoding, callback) { input += chunk; callback(); } });
            child.stdin.on('finish', () => process.nextTick(() => {
                child.stdout.end(typeof result === 'string' ? result : JSON.stringify(result));
                child.emit('close', code);
            }));
            return child;
        },
    };
}

test('PowerShell adapter passes structured JSON over stdin with no shell interpolation', async () => {
    const mock = mockProcess({ ok: true, status: nativeStatus({ installedCount: 4 }) });
    const payload = { action: 'apply', plan: { entries: [{ value: 'untrusted ; $(command)' }] } };
    const result = await runPowerShell(payload, { spawnProcess: mock.spawn });
    assert.equal(result.installedCount, 4);
    assert.deepEqual(JSON.parse(mock.input), payload);
    assert.equal(mock.invocation.options.shell, false);
    assert.equal(mock.invocation.options.windowsHide, true);
    assert.ok(mock.invocation.args.includes('-NonInteractive'));
    assert.ok(!mock.invocation.args.some(argument => argument.includes('untrusted')));
    assert.equal(mock.invocation.args.at(-2), '-File');
    assert.equal(path.basename(mock.invocation.args.at(-1)), 'firewall.ps1');
});

test('PowerShell adapter surfaces permission, invalid-output, and incomplete-rollback failures', async () => {
    let mock = mockProcess({ ok: false, code: 'NOT_ADMIN', error: 'Administrator required' }, 1);
    await assert.rejects(runPowerShell({ action: 'apply' }, { spawnProcess: mock.spawn }), error => error.status === 403);
    mock = mockProcess({ ok: false, error: 'Rollback incomplete', rollbackSucceeded: false, stateUnconfirmed: true }, 1);
    await assert.rejects(runPowerShell({ action: 'apply' }, { spawnProcess: mock.spawn }), error => error.rollbackSucceeded === false && error.stateUnconfirmed === true);
    mock = mockProcess('not JSON', 0);
    await assert.rejects(runPowerShell({ action: 'status' }, { spawnProcess: mock.spawn }), /valid firewall status/);
});

test('firewall routes require preview tokens and use saved rules rather than submitted native commands', async t => {
    const firewallPath = require.resolve('../server/firewall-manager');
    const rulesPath = require.resolve('../server/rules-manager');
    const routerPath = require.resolve('../server/routes/firewall');
    const originals = new Map([firewallPath, rulesPath, routerPath].map(filename => [filename, require.cache[filename]]));
    const calls = [];
    const manager = new FirewallManager({ platform: 'win32', run: async payload => {
        calls.push(payload);
        return nativeStatus({ installedCount: payload.action === 'apply' ? payload.plan.nativeRuleCount : 0 });
    } });
    let server;
    t.after(async () => {
        if (server?.listening) await new Promise(resolve => server.close(resolve));
        for (const [filename, original] of originals) {
            if (original) require.cache[filename] = original; else delete require.cache[filename];
        }
    });
    require.cache[firewallPath] = { id: firewallPath, filename: firewallPath, loaded: true, exports: manager };
    require.cache[rulesPath] = { id: rulesPath, filename: rulesPath, loaded: true, exports: { getRules: sample } };
    delete require.cache[routerPath];
    const app = express();
    app.use(express.json());
    app.use('/api/firewall', require(routerPath));
    server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const base = `http://127.0.0.1:${server.address().port}/api/firewall`;
    const request = async (suffix, method = 'GET', body) => {
        const result = await fetch(base + suffix, { method, headers: { 'Content-Type': 'application/json', Connection: 'close' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
        return { status: result.status, body: await result.json() };
    };
    assert.equal((await request('/apply', 'POST', { entries: [] })).status, 409);
    assert.equal(calls.length, 0);
    const preview = await request('/preview', 'POST', { directions: ['outbound'], rules: { blockedIPs: ['0.0.0.0/0'] } });
    assert.equal(preview.status, 200);
    assert.equal(preview.body.entries[0].remoteAddress, '192.0.2.0/24');
    assert.equal(calls.length, 0);
    const apply = await request('/apply', 'POST', { token: preview.body.token });
    assert.equal(apply.status, 200);
    assert.equal(apply.body.installedCount, 5);
    assert.deepEqual(calls.map(item => item.action), ['status', 'apply']);
    assert.equal((await request('', 'DELETE', {})).status, 200);
    assert.deepEqual(calls.map(item => item.action), ['status', 'apply', 'status', 'remove']);
});

test('PowerShell native replacement and rollback use mocked firewall commands only', { skip: process.platform !== 'win32' }, () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'dpi-firewall-mocks-'));
    const adapter = fs.readFileSync(path.join(__dirname, '..', 'scripts', 'firewall.ps1'), 'utf8').replace(/\r\n/g, '\n');
    const executable = path.win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    try {
        for (const scenario of ['success', 'createFailure', 'removeFailure', 'rollbackFailure', 'removeOnly']) {
            // Function mocks shadow every native cmdlet. Import-Module is also mocked;
            // no real NetSecurity cmdlet is imported or invoked in this process.
            const mocks = `
$script:Scenario = '${scenario}'
$script:MockRules = @{}
$script:HasFailed = $false
$script:NewCount = 0
foreach ($name in @('DPIEngine-Managed-old1','DPIEngine-Managed-old2')) {
    $script:MockRules[$name] = [pscustomobject]@{ Name=$name; DisplayName=$name; Description='Previous policy'; Group='DPIEngine.ManagedBlocking.v1'; Direction='Outbound'; Enabled='True'; Action='Block'; Profile='Any'; Protocol='TCP'; LocalPort='Any'; RemotePort='80'; LocalAddress='Any'; RemoteAddress='Any' }
}
$script:MockRules['Unrelated-rule'] = [pscustomobject]@{ Name='Unrelated-rule'; DisplayName='Unrelated'; Group='Other'; Direction='Inbound'; Enabled='True'; Action='Allow'; Profile='Any' }
function Import-Module { param($Name, $ErrorAction) }
function Get-NetFirewallRule { [CmdletBinding()]param($PolicyStore) return @($script:MockRules.Values | Sort-Object Name) }
function Get-NetFirewallProfile { [CmdletBinding()]param($PolicyStore) return [pscustomobject]@{Name='Public'; Enabled='True'} }
function Get-NetFirewallPortFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject) process { [pscustomobject]@{Protocol=$InputObject.Protocol; LocalPort=@($InputObject.LocalPort); RemotePort=@($InputObject.RemotePort)} } }
function Get-NetFirewallAddressFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject) process { [pscustomobject]@{LocalAddress=@($InputObject.LocalAddress); RemoteAddress=@($InputObject.RemoteAddress)} } }
function New-NetFirewallRule {
    [CmdletBinding()]param($Name,$DisplayName,$Description,$Group,$Direction,$Action,$Enabled,$Profile,$PolicyStore,$Protocol,$LocalAddress='Any',$RemoteAddress='Any',$LocalPort='Any',$RemotePort='Any')
    if ($script:Scenario -eq 'createFailure' -and $Name -notlike '*-old*') {
        $script:NewCount++
        if ($script:NewCount -eq 2) { throw 'Simulated second create failure' }
    }
    if ($script:Scenario -eq 'rollbackFailure' -and $Name -eq 'DPIEngine-Managed-old1' -and $script:HasFailed) { throw 'Simulated restore failure' }
    $script:MockRules[$Name] = [pscustomobject]@{Name=$Name;DisplayName=$DisplayName;Description=$Description;Group=$Group;Direction=$Direction;Action=$Action;Enabled=$Enabled;Profile=$Profile;Protocol=$Protocol;LocalAddress=$LocalAddress;RemoteAddress=$RemoteAddress;LocalPort=$LocalPort;RemotePort=$RemotePort}
    $script:MockRules[$Name]
}
function Set-NetFirewallRule { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject,$Enabled) process { $script:MockRules[$InputObject.Name].Enabled=[string]$Enabled } }
function Remove-NetFirewallRule {
    [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject)
    process {
        if ($null -eq $InputObject) { return }
        if ($script:Scenario -in @('removeFailure', 'rollbackFailure') -and $InputObject.Name -eq 'DPIEngine-Managed-old2' -and -not $script:HasFailed) { $script:HasFailed=$true; throw 'Simulated remove failure' }
        $script:MockRules.Remove($InputObject.Name)
    }
}
`;
            let isolated = adapter.replace('try {\n    $request =', 'function Get-IsAdministrator { return $true }\ntry {\n    $request =');
            assert.notEqual(isolated, adapter, 'Administrator override must be inserted in the isolated mock copy');
            // Record final mock state even when the production script exits on failure.
            isolated = isolated.replace('if ($null -ne $mutex) { $mutex.Dispose() }', 'if ($null -ne $mutex) { $mutex.Dispose() }; [IO.File]::WriteAllText($env:DPI_MOCK_STATE, (ConvertTo-Json -InputObject @($script:MockRules.Values) -Depth 6 -Compress))');
            const harness = path.join(temporaryRoot, scenario + '.ps1');
            const snapshot = path.join(temporaryRoot, scenario + '.json');
            fs.writeFileSync(harness, mocks + isolated, 'utf8');
            const plan = buildFirewallPlan({ ...emptyRules(), blockedPorts: ['443'] }, ['outbound']);
            const result = spawnSync(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', harness], {
                input: JSON.stringify({ action: scenario === 'removeOnly' ? 'remove' : 'apply', plan }),
                encoding: 'utf8', windowsHide: true, timeout: 30000, env: { ...process.env, DPI_MOCK_STATE: snapshot },
            });
            assert.equal(result.error, undefined, result.error?.message);
            const report = JSON.parse(result.stdout.trim());
            const finalRules = JSON.parse(fs.readFileSync(snapshot, 'utf8'));
            assert.ok(finalRules.some(rule => rule.Name === 'Unrelated-rule'), scenario + ': unrelated rule preserved');
            const owned = finalRules.filter(rule => rule.Group === MANAGED_GROUP);
            if (scenario === 'success') {
                assert.equal(result.status, 0, result.stderr);
                assert.equal(report.status.installedCount, 2);
                assert.ok(owned.every(rule => !rule.Name.includes('-old') && rule.Enabled === 'True'));
            } else if (scenario === 'removeOnly') {
                assert.equal(result.status, 0, result.stderr);
                assert.equal(owned.length, 0);
            } else if (scenario === 'rollbackFailure') {
                assert.equal(result.status, 1);
                assert.equal(report.rollbackSucceeded, false);
                assert.equal(report.stateUnconfirmed, true);
                assert.deepEqual(owned.map(rule => rule.Name), ['DPIEngine-Managed-old2']);
            } else {
                assert.equal(result.status, 1);
                assert.equal(report.rollbackSucceeded, true, report.error);
                assert.deepEqual(owned.map(rule => rule.Name).sort(), ['DPIEngine-Managed-old1', 'DPIEngine-Managed-old2']);
                assert.ok(owned.every(rule => rule.Enabled === 'True'));
            }
        }
    } finally {
        const resolved = path.resolve(temporaryRoot);
        assert.equal(path.dirname(resolved), path.resolve(os.tmpdir()));
        assert.ok(path.basename(resolved).startsWith('dpi-firewall-mocks-'));
        fs.rmSync(resolved, { recursive: true, force: true });
    }
});
