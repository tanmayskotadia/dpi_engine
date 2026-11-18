const path = require('node:path');
const { spawn } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { normalizeRules, RuleValidationError } = require('./rule-validation');

const MANAGED_GROUP = 'DPIEngine.ManagedBlocking.v1';
const RULE_NAME_PREFIX = 'DPIEngine-Managed-';
const PREVIEW_TTL_MS = 5 * 60 * 1000;
const MAX_NATIVE_RULES = 256;

class FirewallError extends Error {
    constructor(message, status = 500, details = {}) {
        super(message);
        this.name = 'FirewallError';
        this.status = status;
        Object.assign(this, details);
    }
}

function buildFirewallPlan(savedRules, directions) {
    const rules = normalizeRules(savedRules);
    if (!Array.isArray(directions) || !directions.length || directions.some(value => !['inbound', 'outbound'].includes(value))) {
        throw new RuleValidationError('Select inbound, outbound, or both traffic directions.');
    }
    const selected = [...new Set(directions)];
    const unsupported = [
        ...rules.blockedApps.map(value => ({ type: 'app', value, reason: 'Application classifications cannot be enforced as native Windows application rules.' })),
        ...rules.blockedDomains.map(value => ({ type: 'domain', value, reason: 'Domain patterns are capture-only; no hostname-to-IP resolution is performed.' })),
        ...rules.blockedProtocols.filter(value => value === 'arp').map(value => ({ type: 'protocol', value, reason: 'Windows Defender Firewall does not filter ARP at this layer.' })),
    ];
    const entries = [];
    for (const direction of selected) {
        const nativeDirection = direction === 'inbound' ? 'Inbound' : 'Outbound';
        for (const value of rules.blockedIPs) {
            entries.push({ kind: 'ip', value, direction: nativeDirection, protocol: 'Any', remoteAddress: value, label: `Remote address ${value}` });
        }
        for (const value of rules.blockedPorts) {
            const [scope, port] = value.includes(':') ? value.split(':') : [null, value];
            for (const protocol of scope ? [scope.toUpperCase()] : ['TCP', 'UDP']) {
                const portField = direction === 'inbound' ? 'localPort' : 'remotePort';
                entries.push({ kind: 'port', value, direction: nativeDirection, protocol, [portField]: port, label: `${protocol} ${direction === 'inbound' ? 'local' : 'remote'} port ${port}` });
            }
        }
        for (const value of rules.blockedProtocols.filter(value => value !== 'arp')) {
            const protocol = ({ tcp: 'TCP', udp: 'UDP', icmp: 'ICMPv4', icmpv6: 'ICMPv6' })[value];
            entries.push({ kind: 'protocol', value, direction: nativeDirection, protocol, label: `All ${protocol} traffic` });
        }
    }
    if (entries.length > MAX_NATIVE_RULES) throw new RuleValidationError(`This selection creates ${entries.length} native rules. Reduce it to at most ${MAX_NATIVE_RULES} native rules.`);
    return {
        group: MANAGED_GROUP,
        directions: selected,
        sourceRuleCount: Object.values(rules).reduce((sum, values) => sum + values.length, 0),
        nativeRuleCount: entries.length,
        entries,
        unsupported,
        scope: 'IP rules match remote addresses. Inbound ports are local ports; outbound ports are remote ports. Each rule blocks independently on all Windows firewall profiles.',
    };
}

function runPowerShell(payload, { spawnProcess = spawn, scriptPath = path.resolve(__dirname, '..', 'scripts', 'firewall.ps1') } = {}) {
    return new Promise((resolve, reject) => {
        // User values are sent as JSON over stdin, never interpolated into a command.
        const executable = path.win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
        const child = spawnProcess(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptPath], {
            shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
        });
        let stdout = '';
        let stderr = '';
        let settled = false;
        const finish = (error, value) => {
            if (settled) return;
            settled = true;
            clearTimeout(timeout);
            if (error) reject(error); else resolve(value);
        };
        const timeout = setTimeout(() => {
            child.kill();
            finish(new FirewallError('The firewall operation timed out. Its final state is unconfirmed; refresh native status before retrying.', 500, { stateUnconfirmed: true }));
        }, payload.action === 'status' ? 20000 : 120000);
        timeout.unref?.();
        child.stdout.on('data', chunk => {
            stdout += chunk.toString('utf8');
            if (stdout.length > 2 * 1024 * 1024) {
                child.kill();
                finish(new FirewallError('The firewall response exceeded its limit. Refresh native status before retrying.', 500, { stateUnconfirmed: true }));
            }
        });
        child.stderr.on('data', chunk => { stderr = (stderr + chunk.toString('utf8')).slice(-8192); });
        child.on('error', error => finish(new FirewallError('Windows PowerShell could not be started. Check that Windows Defender Firewall is installed.', 503, { cause: error })));
        child.stdin.on('error', error => {
            if (error.code !== 'EPIPE') finish(new FirewallError('Could not send the policy to Windows PowerShell.', 503, { cause: error }));
        });
        child.on('close', code => {
            let result;
            try { result = JSON.parse(stdout.replace(/^\uFEFF/, '').trim()); } catch {
                finish(new FirewallError('Windows did not return a valid firewall status. Check server permissions and refresh.', 503));
                return;
            }
            if (code !== 0 || result.ok === false) {
                finish(new FirewallError(result.error || 'Windows could not complete the firewall operation.', result.code === 'NOT_ADMIN' ? 403 : 500, {
                    rollbackSucceeded: result.rollbackSucceeded,
                    stateUnconfirmed: result.stateUnconfirmed,
                }));
                return;
            }
            finish(null, result.status || result);
        });
        child.stdin.end(JSON.stringify(payload));
    });
}

class FirewallManager {
    constructor({ platform = process.platform, run = runPowerShell, now = Date.now } = {}) {
        this.platform = platform;
        this.run = run;
        this.now = now;
        this.previews = new Map();
        this.busy = false;
        this.statusRequest = null;
    }

    async status() {
        if (this.platform !== 'win32') {
            return { supported: false, available: false, elevated: false, installedCount: 0, enabledCount: 0, activeCount: 0, rules: [], profiles: [], group: MANAGED_GROUP, message: 'Live enforcement is available only on the Windows computer running this server.' };
        }
        if (!this.statusRequest) {
            this.statusRequest = this.run({ action: 'status' }).finally(() => { this.statusRequest = null; });
        }
        return { ...(await this.statusRequest), group: MANAGED_GROUP, busy: this.busy };
    }

    preview(rules, directions) {
        for (const [token, saved] of this.previews) if (saved.expiresAt <= this.now()) this.previews.delete(token);
        if (this.previews.size >= 20) this.previews.delete(this.previews.keys().next().value);
        const plan = buildFirewallPlan(rules, directions);
        const token = randomUUID();
        const expiresAt = this.now() + PREVIEW_TTL_MS;
        this.previews.set(token, { plan: structuredClone(plan), expiresAt });
        return { ...plan, token, expiresAt: new Date(expiresAt).toISOString() };
    }

    async apply(token) {
        if (this.busy) throw new FirewallError('Another firewall change is in progress.', 409);
        if (this.platform !== 'win32') throw new FirewallError('Live enforcement requires a Windows server.', 400);
        const reviewed = typeof token === 'string' ? this.previews.get(token) : null;
        if (!reviewed || reviewed.expiresAt <= this.now()) {
            if (token) this.previews.delete(token);
            throw new FirewallError('The preview is missing or expired. Review a fresh preview before applying.', 409);
        }
        if (!reviewed.plan.nativeRuleCount) throw new FirewallError('There are no supported native firewall rules in this selection.', 400);
        this.busy = true;
        try {
            const status = await this.run({ action: 'status' });
            if (!status.elevated) throw new FirewallError('Restart this server as Administrator to change Windows Defender Firewall.', 403);
            if (!status.available) throw new FirewallError('Windows Defender Firewall is not available on this server.', 503);
            this.previews.delete(token);
            const installed = await this.run({ action: 'apply', plan: reviewed.plan });
            return { ...installed, appliedRuleCount: reviewed.plan.nativeRuleCount, unsupported: reviewed.plan.unsupported };
        } finally {
            this.busy = false;
        }
    }

    async remove() {
        if (this.busy) throw new FirewallError('Another firewall change is in progress.', 409);
        if (this.platform !== 'win32') throw new FirewallError('Live enforcement requires a Windows server.', 400);
        this.busy = true;
        try {
            const status = await this.run({ action: 'status' });
            if (!status.elevated) throw new FirewallError('Restart this server as Administrator to remove managed firewall rules.', 403);
            if (!status.available) throw new FirewallError('Windows Defender Firewall is not available on this server.', 503);
            return await this.run({ action: 'remove' });
        } finally {
            this.busy = false;
        }
    }
}

module.exports = new FirewallManager();
module.exports.FirewallManager = FirewallManager;
module.exports.FirewallError = FirewallError;
module.exports.buildFirewallPlan = buildFirewallPlan;
module.exports.runPowerShell = runPowerShell;
module.exports.MANAGED_GROUP = MANAGED_GROUP;
module.exports.RULE_NAME_PREFIX = RULE_NAME_PREFIX;
