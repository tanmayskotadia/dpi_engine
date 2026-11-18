const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const config = require('./config');
const { RULE_KEYS, emptyRules, normalizeRule, normalizeRules } = require('./rule-validation');

class RulesManager {
    constructor(filePath = config.RULES_PATH || process.env.RULES_PATH || path.join(__dirname, 'data', 'rules.json')) {
        this.filePath = path.resolve(filePath);
        this.rules = emptyRules();
        this.loadError = null;
        this.loadRules();
    }

    loadRules() {
        try {
            this.rules = normalizeRules(JSON.parse(fs.readFileSync(this.filePath, 'utf8')));
            this.loadError = null;
        } catch (error) {
            if (error.code === 'ENOENT') {
                this.rules = emptyRules();
                this.loadError = null;
            } else {
                // Never silently treat unreadable or invalid rules as an empty policy.
                this.loadError = new Error('Saved blocking rules could not be loaded. Correct the rules file and restart the server before starting an analysis.', { cause: error });
            }
        }
    }

    assertReady() {
        if (this.loadError) throw this.loadError;
    }

    saveRules(nextRules = this.rules) {
        const directory = path.dirname(this.filePath);
        const temporaryPath = path.join(directory, `.${path.basename(this.filePath)}.${process.pid}.${randomUUID()}.tmp`);
        try {
            fs.mkdirSync(directory, { recursive: true });
            fs.writeFileSync(temporaryPath, JSON.stringify(nextRules, null, 2) + '\n', { encoding: 'utf8', mode: 0o600, flag: 'wx' });
            fs.renameSync(temporaryPath, this.filePath);
        } catch (error) {
            try { fs.unlinkSync(temporaryPath); } catch { /* The temporary file may not have been created. */ }
            throw new Error('Blocking rules could not be saved. Check the server storage permissions and try again.', { cause: error });
        }
        // Publish only after the new policy has been persisted successfully.
        this.rules = nextRules;
        this.loadError = null;
    }

    getRules() {
        this.assertReady();
        return structuredClone(this.rules);
    }

    addRule(type, value) {
        const canonical = normalizeRule(type, value);
        this.assertReady();
        const key = RULE_KEYS[type];
        if (!this.rules[key].includes(canonical)) {
            this.saveRules({ ...this.rules, [key]: [...this.rules[key], canonical] });
        }
        return this.getRules();
    }

    removeRule(type, value) {
        const canonical = normalizeRule(type, value);
        this.assertReady();
        const key = RULE_KEYS[type];
        if (this.rules[key].includes(canonical)) {
            this.saveRules({ ...this.rules, [key]: this.rules[key].filter(item => item !== canonical) });
        }
        return this.getRules();
    }

    // Retain the existing manager API for integrations.
    addIP(value) { return this.addRule('ip', value); }
    removeIP(value) { return this.removeRule('ip', value); }
    addApp(value) { return this.addRule('app', value); }
    removeApp(value) { return this.removeRule('app', value); }
    addDomain(value) { return this.addRule('domain', value); }
    removeDomain(value) { return this.removeRule('domain', value); }
    addPort(value) { return this.addRule('port', value); }
    removePort(value) { return this.removeRule('port', value); }
    addProtocol(value) { return this.addRule('protocol', value); }
    removeProtocol(value) { return this.removeRule('protocol', value); }

    clearAll() {
        this.saveRules(emptyRules());
        return this.getRules();
    }
}

const rulesManager = new RulesManager();
module.exports = rulesManager;
module.exports.RulesManager = RulesManager;
