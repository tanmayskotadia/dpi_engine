const fs = require('fs');
const path = require('path');

const rulesFilePath = path.join(__dirname, 'data', 'rules.json');

class RulesManager {
    constructor() {
        this.rules = {
            blockedIPs: [],
            blockedApps: [],
            blockedDomains: []
        };
        
        this.loadRules();
    }
    
    loadRules() {
        if (fs.existsSync(rulesFilePath)) {
            try {
                const data = fs.readFileSync(rulesFilePath, 'utf8');
                this.rules = JSON.parse(data);
            } catch (err) {
                console.error("Failed to load rules:", err);
            }
        } else {
            this.saveRules(); // Create initial file
        }
    }
    
    saveRules() {
        // Ensure directory exists
        if (!fs.existsSync(path.dirname(rulesFilePath))) {
            fs.mkdirSync(path.dirname(rulesFilePath), { recursive: true });
        }
        
        try {
            fs.writeFileSync(rulesFilePath, JSON.stringify(this.rules, null, 2));
        } catch (err) {
            console.error("Failed to save rules:", err);
        }
    }
    
    getRules() {
        return this.rules;
    }
    
    addIP(ip) {
        if (!this.rules.blockedIPs.includes(ip)) {
            this.rules.blockedIPs.push(ip);
            this.saveRules();
        }
    }
    
    removeIP(ip) {
        this.rules.blockedIPs = this.rules.blockedIPs.filter(i => i !== ip);
        this.saveRules();
    }
    
    addApp(app) {
        if (!this.rules.blockedApps.includes(app)) {
            this.rules.blockedApps.push(app);
            this.saveRules();
        }
    }
    
    removeApp(app) {
        this.rules.blockedApps = this.rules.blockedApps.filter(a => a !== app);
        this.saveRules();
    }
    
    addDomain(domain) {
        if (!this.rules.blockedDomains.includes(domain)) {
            this.rules.blockedDomains.push(domain);
            this.saveRules();
        }
    }
    
    removeDomain(domain) {
        this.rules.blockedDomains = this.rules.blockedDomains.filter(d => d !== domain);
        this.saveRules();
    }
    
    clearAll() {
        this.rules = {
            blockedIPs: [],
            blockedApps: [],
            blockedDomains: []
        };
        this.saveRules();
    }
}

const rulesManager = new RulesManager();
module.exports = rulesManager;
