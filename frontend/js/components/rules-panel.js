import { api } from '../api.js';
import { icon, escapeHtml } from '../ui.js';

const RULE_TYPES = [
    { type: 'ip', key: 'blockedIPs', title: 'IP addresses', label: 'Source IPv4 address', icon: 'server', placeholder: '192.168.1.50', help: 'Blocks traffic from this source address.', empty: 'No IP addresses blocked.' },
    { type: 'app', key: 'blockedApps', title: 'Applications', label: 'Application or protocol', icon: 'shield', help: 'Blocks traffic classified as this application.', empty: 'No applications blocked.' },
    { type: 'domain', key: 'blockedDomains', title: 'Domains', label: 'Domain name', icon: 'globe', placeholder: 'example.com', help: 'Matches text within detected domain names. No wildcards.', empty: 'No domains blocked.' },
];

// These values must match appTypeToString in the C++ engine.
const APPLICATIONS = ['Amazon', 'Apple', 'Cloudflare', 'Discord', 'Facebook', 'GitHub', 'Google', 'Instagram', 'Microsoft', 'Netflix', 'Spotify', 'Telegram', 'TikTok', 'Twitter/X', 'WhatsApp', 'YouTube', 'Zoom'];
const PROTOCOLS = ['DNS', 'HTTP', 'HTTPS', 'QUIC', 'TLS', 'Unknown'];

export class RulesPanel {
    constructor(state) {
        this.state = state;
        this.container = document.getElementById('engine-rules-container');
        this.busy = false;
        this.render();
        this.bindEvents();
        this.updateData(this.state.rules);
        this.state.on('rules', rules => this.updateData(rules));
    }

    render() {
        this.container.innerHTML = `
            <div class="section-heading">
                <div>
                    <h2 id="blocking-rules-heading">Blocking rules <span class="badge badge-neutral" id="rules-total-count">0 rules</span></h2>
                    <p class="help-text">Changes apply to your next analysis. Captures are processed using the rules saved when a run starts.</p>
                </div>
            </div>
            <div class="grid grid-cols-3" aria-labelledby="blocking-rules-heading">
                ${RULE_TYPES.map(rule => `
                    <section class="card" aria-labelledby="rule-${rule.type}-heading">
                        <div class="card-header">
                            <h3 class="card-title" id="rule-${rule.type}-heading">${icon(rule.icon)} ${rule.title}</h3>
                            <span class="badge badge-neutral" id="rule-${rule.type}-count" aria-label="0 saved rules">0</span>
                        </div>
                        <div class="card-body">
                            <form id="rule-${rule.type}-form" data-rule-type="${rule.type}" novalidate>
                                <div class="form-group">
                                    <label class="form-label" for="rule-${rule.type}-input">${rule.label}</label>
                                    <div class="rule-input-row">
                                        ${this.renderInput(rule)}
                                        <button type="submit" id="rule-${rule.type}-add" class="btn btn-secondary" aria-label="Add ${rule.type === 'ip' ? 'IP address' : rule.type} rule">${icon('plus')} Add</button>
                                    </div>
                                    <p class="help-text" id="rule-${rule.type}-help">${rule.help}</p>
                                </div>
                            </form>
                            <div id="rule-${rule.type}-notice" class="notice notice-error" role="status" aria-live="polite" aria-atomic="true" hidden></div>
                            <ul class="rule-list" id="rule-${rule.type}-list" aria-label="Blocked ${rule.title.toLowerCase()}"></ul>
                        </div>
                    </section>
                `).join('')}
            </div>
        `;
    }

    renderInput(rule) {
        const attributes = `id="rule-${rule.type}-input" class="form-control" required aria-describedby="rule-${rule.type}-help rule-${rule.type}-notice"`;
        if (rule.type === 'app') {
            const options = values => values.map(value => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join('');
            return `<select ${attributes}>
                <option value="">Select application</option>
                <optgroup label="Applications">${options(APPLICATIONS)}</optgroup>
                <optgroup label="Protocols and other traffic">${options(PROTOCOLS)}</optgroup>
            </select>`;
        }
        return `<input ${attributes} type="text" placeholder="${rule.placeholder}" maxlength="${rule.type === 'ip' ? 15 : 253}" autocomplete="off" autocapitalize="none" spellcheck="false"${rule.type === 'ip' ? ' inputmode="decimal"' : ''}>`;
    }

    bindEvents() {
        RULE_TYPES.forEach(rule => {
            document.getElementById(`rule-${rule.type}-form`).addEventListener('submit', event => {
                event.preventDefault();
                this.addRule(rule);
            });
            document.getElementById(`rule-${rule.type}-input`).addEventListener('input', event => {
                event.target.removeAttribute('aria-invalid');
                this.hideNotice(rule.type);
            });
        });

        this.container.addEventListener('click', event => {
            const button = event.target.closest('button[data-remove-rule]');
            if (button && !this.busy) this.removeRule(button);
        });
    }

    validate(rule, value) {
        if (!value) return rule.type === 'app' ? 'Choose an application or protocol.' : `Enter ${rule.type === 'ip' ? 'an IPv4 address' : 'a domain name'}.`;
        if (rule.type === 'ip') {
            const octets = value.split('.');
            if (octets.length !== 4 || octets.some(part => !/^\d{1,3}$/.test(part) || Number(part) > 255)) {
                return 'Enter a valid IPv4 address, such as 192.168.1.50.';
            }
        }
        if (rule.type === 'domain') {
            const valid = value.length <= 253 && value.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
            if (!valid) return 'Enter a domain such as example.com, without a URL, path, or wildcard.';
        }
        if (rule.type === 'app' && ![...APPLICATIONS, ...PROTOCOLS].includes(value)) return 'Choose an application from the list.';
        return null;
    }

    async addRule(rule) {
        if (this.busy) return;
        const input = document.getElementById(`rule-${rule.type}-input`);
        let value = input.value.trim();
        const error = this.validate(rule, value);
        if (error) {
            input.setAttribute('aria-invalid', 'true');
            this.showNotice(rule.type, error, 'error');
            input.focus();
            return;
        }
        if (rule.type === 'ip') value = value.split('.').map(Number).join('.');
        if (rule.type === 'domain') value = value.toLowerCase();
        if ((this.state.rules?.[rule.key] || []).includes(value)) {
            this.showNotice(rule.type, 'This rule is already saved.', 'info');
            input.focus();
            return;
        }

        const button = document.getElementById(`rule-${rule.type}-add`);
        this.setBusy(true);
        this.hideNotice(rule.type);
        button.textContent = 'Adding…';
        try {
            const rules = await api.addRule(rule.type, value);
            this.publishRules(rules);
            input.value = '';
            this.showNotice(rule.type, `Added ${value}. Applies to the next analysis.`, 'success');
        } catch (error) {
            this.showNotice(rule.type, `Could not add this rule. ${error.message}`, 'error');
        } finally {
            button.innerHTML = `${icon('plus')} Add`;
            this.setBusy(false);
            input.focus();
        }
    }

    async removeRule(button) {
        const { type, value } = button.dataset;
        const list = document.getElementById(`rule-${type}-list`);
        const index = [...list.querySelectorAll('button')].indexOf(button);
        this.setBusy(true);
        this.hideNotice(type);
        button.setAttribute('aria-label', `Removing ${value}`);
        try {
            const rules = await api.removeRule(type, value);
            this.publishRules(rules);
            this.showNotice(type, `Removed ${value}. Applies to the next analysis.`, 'success');
        } catch (error) {
            this.showNotice(type, `Could not remove this rule. ${error.message}`, 'error');
            button.setAttribute('aria-label', `Remove rule for ${value}`);
        } finally {
            this.setBusy(false);
            const remaining = list.querySelectorAll('button');
            (remaining[Math.min(index, remaining.length - 1)] || document.getElementById(`rule-${type}-input`)).focus();
        }
    }

    publishRules(rules) {
        this.state.rules = rules;
        this.state.notify('rules', rules);
    }

    setBusy(busy) {
        this.busy = busy;
        this.container.querySelectorAll('input, select, button').forEach(control => { control.disabled = busy; });
        this.container.setAttribute('aria-busy', String(busy));
    }

    showNotice(type, message, kind) {
        const notice = document.getElementById(`rule-${type}-notice`);
        notice.className = `notice notice-${kind}`;
        notice.setAttribute('aria-live', kind === 'error' ? 'assertive' : 'polite');
        notice.textContent = message;
        notice.hidden = false;
    }

    hideNotice(type) {
        const notice = document.getElementById(`rule-${type}-notice`);
        notice.hidden = true;
        notice.textContent = '';
    }

    updateData(rules) {
        let total = 0;
        RULE_TYPES.forEach(rule => {
            const items = Array.isArray(rules?.[rule.key]) ? rules[rule.key] : [];
            total += items.length;
            const count = document.getElementById(`rule-${rule.type}-count`);
            count.textContent = items.length;
            count.setAttribute('aria-label', `${items.length} saved ${items.length === 1 ? 'rule' : 'rules'}`);
            const list = document.getElementById(`rule-${rule.type}-list`);
            list.replaceChildren();
            if (!items.length) {
                const empty = document.createElement('li');
                empty.className = 'rule-empty';
                empty.textContent = rule.empty;
                list.appendChild(empty);
                return;
            }
            items.forEach(value => {
                const item = document.createElement('li');
                item.className = 'rule-item';
                const label = document.createElement('span');
                label.className = 'rule-value';
                label.textContent = value;
                const remove = document.createElement('button');
                remove.type = 'button';
                remove.className = 'btn btn-ghost icon-btn';
                remove.dataset.removeRule = '';
                remove.dataset.type = rule.type;
                remove.dataset.value = value;
                remove.disabled = this.busy;
                remove.setAttribute('aria-label', `Remove rule for ${value}`);
                remove.title = `Remove ${value}`;
                remove.innerHTML = icon('trash');
                item.append(label, remove);
                list.appendChild(item);
            });
        });
        document.getElementById('rules-total-count').textContent = `${total} ${total === 1 ? 'rule' : 'rules'}`;
    }
}
