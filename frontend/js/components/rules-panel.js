import { api } from '../api.js';
import { icon, escapeHtml } from '../ui.js';

const RULE_TYPES = [
    { type: 'ip', key: 'blockedIPs', title: 'IP addresses & networks', label: 'IPv4, IPv6, or CIDR network', icon: 'server', placeholder: '192.168.1.0/24 or 2001:db8::/32', help: 'Matches either source or destination. CIDR host bits are cleared when saved.', empty: 'No IP addresses or networks blocked.', maxLength: 49 },
    { type: 'app', key: 'blockedApps', title: 'Applications', label: 'Application or application protocol', icon: 'shield', help: 'Matches traffic classified as this application. Classification may require several packets.', empty: 'No applications blocked.' },
    { type: 'domain', key: 'blockedDomains', title: 'Domains', label: 'Domain or subdomain pattern', icon: 'globe', placeholder: 'example.com or *.example.com', help: 'example.com includes its subdomains. *.example.com matches subdomains only. Requires a visible hostname.', empty: 'No domains blocked.', maxLength: 255 },
    { type: 'port', key: 'blockedPorts', title: 'Ports', label: 'Port or port range', icon: 'server', placeholder: '443 or tcp:8000-8080', help: 'Matches either endpoint, from 1 to 65535. Use tcp: or udp: to restrict the transport.', empty: 'No ports blocked.', maxLength: 15 },
    { type: 'protocol', key: 'blockedProtocols', title: 'Network protocols', label: 'Protocol', icon: 'shield', help: 'Blocks all packets of the selected network or transport protocol.', empty: 'No network protocols blocked.' },
];

// These values must match appTypeToString in the C++ engine.
const APPLICATIONS = ['Amazon', 'Apple', 'Cloudflare', 'Discord', 'Facebook', 'GitHub', 'Google', 'Instagram', 'Microsoft', 'Netflix', 'Spotify', 'Telegram', 'TikTok', 'Twitter/X', 'WhatsApp', 'YouTube', 'Zoom'];
const APPLICATION_PROTOCOLS = ['DNS', 'HTTP', 'HTTPS', 'QUIC', 'TLS', 'Unknown'];
const NETWORK_PROTOCOLS = ['tcp', 'udp', 'icmp', 'icmpv6', 'arp'];

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
                    <p class="help-text">Capture filtering uses the rules saved when each analysis starts. Changes apply to the next run and do not apply a live firewall policy.</p>
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
                <optgroup label="Application protocols and other traffic">${options(APPLICATION_PROTOCOLS)}</optgroup>
            </select>`;
        }
        if (rule.type === 'protocol') {
            return `<select ${attributes}><option value="">Select protocol</option>${NETWORK_PROTOCOLS.map(value => `<option value="${value}">${value === 'icmpv6' ? 'ICMPv6' : value.toUpperCase()}</option>`).join('')}</select>`;
        }
        return `<input ${attributes} type="text" placeholder="${rule.placeholder}" maxlength="${rule.maxLength}" autocomplete="off" autocapitalize="none" spellcheck="false">`;
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
        if (!value) return `Enter or select ${rule.label.toLowerCase()}.`;
        if (rule.type === 'ip') {
            const [address, prefix, extra] = value.split('/');
            const ipv6 = address.includes(':');
            let valid = false;
            if (ipv6 && !/[\s%\[\]]/.test(address)) {
                try { valid = new URL(`http://[${address}]/`).hostname.startsWith('['); } catch { /* Show the validation message below. */ }
            } else if (!ipv6) {
                const octets = address.split('.');
                valid = octets.length === 4 && octets.every(part => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
            }
            if (!valid || extra !== undefined || (prefix !== undefined && (!/^\d{1,3}$/.test(prefix) || Number(prefix) > (ipv6 ? 128 : 32)))) {
                return 'Enter an IPv4 or IPv6 address, optionally with a CIDR prefix, such as 192.168.1.0/24 or 2001:db8::/32.';
            }
        }
        if (rule.type === 'domain') {
            let domain = value.replace(/^\*\./, '').replace(/\.$/, '');
            if (!domain || /[\s/:@?#%*\\]/.test(domain)) return 'Enter a domain such as example.com or *.example.com, without a URL, port, or path.';
            try { domain = new URL(`http://${domain}`).hostname; } catch { return 'Enter a valid domain name.'; }
            if (domain.length > 253 || !domain.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))) return 'Enter a valid domain name.';
        }
        if (rule.type === 'port') {
            const match = value.match(/^(?:(tcp|udp):)?(\d{1,5})(?:-(\d{1,5}))?$/i);
            if (!match || Number(match[2]) < 1 || Number(match[3] || match[2]) > 65535 || Number(match[2]) > Number(match[3] || match[2])) return 'Use a port from 1 to 65535, or a range such as tcp:8000-8080.';
        }
        if (rule.type === 'app' && ![...APPLICATIONS, ...APPLICATION_PROTOCOLS].includes(value)) return 'Choose an application from the list.';
        if (rule.type === 'protocol' && !NETWORK_PROTOCOLS.includes(value)) return 'Choose a network protocol from the list.';
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
            const previous = this.state.rules?.[rule.key] || [];
            const rules = await api.addRule(rule.type, value);
            const addedValue = (rules[rule.key] || []).find(item => !previous.includes(item));
            this.publishRules(rules);
            input.value = '';
            this.showNotice(rule.type, addedValue ? `Added ${addedValue}. Applies to the next analysis.` : 'This rule is already saved.', addedValue ? 'success' : 'info');
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
        this.state.setDataError?.('blocking rules', false);
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
