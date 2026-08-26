import { api } from '../api.js';

export class RulesPanel {
    constructor(state) {
        this.state = state;
        this.container = document.getElementById('engine-rules-container');
        this.render();
        this.bindEvents();
        
        this.state.on('rules', (rules) => {
            if(rules) this.updateData(rules);
        });
    }
    
    render() {
        this.container.innerHTML = `
            <h3 style="margin-bottom: 15px;"><i class="fa-solid fa-ban"></i> Blocking Rules</h3>
            <div class="card" style="margin-bottom: 20px; background-color: rgba(59, 130, 246, 0.1); border-color: var(--accent-primary);">
                <div style="padding: 10px;">
                    <i class="fa-solid fa-circle-info" style="color: var(--accent-primary); margin-right: 10px;"></i>
                    Rules defined here will be applied the next time you start the DPI Engine.
                </div>
            </div>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px;">
                <!-- IP Blocking -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fa-solid fa-network-wired"></i> Blocked IPs</h3>
                    </div>
                    <div style="display: flex; gap: 10px; margin-bottom: 15px;">
                        <input type="text" id="rule-ip-input" class="form-control" placeholder="e.g. 192.168.1.50">
                        <button id="rule-ip-add" class="btn btn-primary">Add</button>
                    </div>
                    <ul class="rule-list" id="rule-ip-list" style="list-style: none; max-height: 200px; overflow-y: auto;">
                    </ul>
                </div>
                
                <!-- App Blocking -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fa-solid fa-mobile-screen"></i> Blocked Applications</h3>
                    </div>
                    <div style="display: flex; gap: 10px; margin-bottom: 15px;">
                        <select id="rule-app-input" class="form-control">
                            <option value="">Select app...</option>
                            <option value="YouTube">YouTube</option>
                            <option value="Facebook">Facebook</option>
                            <option value="Netflix">Netflix</option>
                            <option value="WhatsApp">WhatsApp</option>
                            <option value="Instagram">Instagram</option>
                            <option value="Twitter">Twitter</option>
                            <option value="Spotify">Spotify</option>
                            <option value="Discord">Discord</option>
                            <option value="Google">Google</option>
                            <option value="HTTPS">HTTPS (Generic)</option>
                            <option value="HTTP">HTTP (Generic)</option>
                            <option value="DNS">DNS</option>
                        </select>
                        <button id="rule-app-add" class="btn btn-primary">Add</button>
                    </div>
                    <ul class="rule-list" id="rule-app-list" style="list-style: none; max-height: 200px; overflow-y: auto;">
                    </ul>
                </div>
                
                <!-- Domain Blocking -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fa-solid fa-globe"></i> Blocked Domains (SNI)</h3>
                    </div>
                    <div style="display: flex; gap: 10px; margin-bottom: 15px;">
                        <input type="text" id="rule-domain-input" class="form-control" placeholder="e.g. tracking.com">
                        <button id="rule-domain-add" class="btn btn-primary">Add</button>
                    </div>
                    <ul class="rule-list" id="rule-domain-list" style="list-style: none; max-height: 200px; overflow-y: auto;">
                    </ul>
                </div>
            </div>
            
            <style>
                .rule-list li {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 8px 12px;
                    border-bottom: 1px solid var(--border-color);
                    background-color: var(--bg-tertiary);
                    margin-bottom: 5px;
                    border-radius: var(--radius-sm);
                    animation: ruleSlideIn 0.25s cubic-bezier(0.16, 1, 0.3, 1) forwards;
                }
                @keyframes ruleSlideIn {
                    from { opacity: 0; transform: translateX(-10px); }
                    to   { opacity: 1; transform: translateX(0); }
                }
                @keyframes ruleSlideOut {
                    from { opacity: 1; transform: translateX(0); max-height: 50px; }
                    to   { opacity: 0; transform: translateX(15px); max-height: 0; padding: 0; margin: 0; }
                }
                .rule-list li.removing {
                    animation: ruleSlideOut 0.25s ease forwards;
                    overflow: hidden;
                }
                .rule-delete-btn {
                    background: none;
                    border: none;
                    color: var(--text-muted);
                    cursor: pointer;
                    transition: color 0.2s;
                    padding: 4px 6px;
                    border-radius: var(--radius-sm);
                }
                .rule-delete-btn:hover {
                    color: var(--status-error);
                    background-color: rgba(239, 68, 68, 0.1);
                }
            </style>
        `;
    }
    
    bindEvents() {
        const setupAdd = (btnId, inputId, type) => {
            document.getElementById(btnId).addEventListener('click', async () => {
                const input = document.getElementById(inputId);
                const btn = document.getElementById(btnId);
                const val = input.value.trim();
                if (!val) return;

                // Visual feedback: disable button while saving
                btn.disabled = true;
                btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';

                try {
                    await api.addRule(type, val);
                    input.value = '';
                    this.state.refreshRules();
                } finally {
                    btn.disabled = false;
                    btn.innerHTML = 'Add';
                }
            });
        };

        setupAdd('rule-ip-add', 'rule-ip-input', 'ip');
        setupAdd('rule-app-add', 'rule-app-input', 'app');
        setupAdd('rule-domain-add', 'rule-domain-input', 'domain');

        // Use event delegation for delete buttons — animate out before removing
        this.container.addEventListener('click', async (e) => {
            const btn = e.target.closest('.rule-delete-btn');
            if (btn) {
                const li = btn.closest('li');
                const type = btn.dataset.type;
                const val = btn.dataset.val;

                // Animate out
                if (li) {
                    li.classList.add('removing');
                    await new Promise(r => setTimeout(r, 240)); // match animation duration
                }

                await api.removeRule(type, val);
                this.state.refreshRules();
            }
        });
    }
    
    updateData(rules) {
        const renderList = (containerId, items, type) => {
            const ul = document.getElementById(containerId);
            ul.innerHTML = '';
            if(items.length === 0) {
                ul.innerHTML = '<li style="justify-content:center; color: var(--text-muted);">No rules defined</li>';
                return;
            }
            
            items.forEach(item => {
                const li = document.createElement('li');
                const span = document.createElement('span');
                span.textContent = item;
                const btn = document.createElement('button');
                btn.className = 'rule-delete-btn';
                btn.dataset.type = type;
                btn.dataset.val = item;
                btn.innerHTML = '<i class="fa-solid fa-trash"></i>';
                li.appendChild(span);
                li.appendChild(btn);
                ul.appendChild(li);
            });
        };
        
        renderList('rule-ip-list', rules.blockedIPs, 'ip');
        renderList('rule-app-list', rules.blockedApps, 'app');
        renderList('rule-domain-list', rules.blockedDomains, 'domain');
    }
}
