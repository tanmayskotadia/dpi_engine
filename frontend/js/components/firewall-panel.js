import { API_BASE } from '../api.js';
import { icon, escapeHtml, formatNumber } from '../ui.js';

export class FirewallPanel {
    constructor(state) {
        this.state = state;
        this.container = document.getElementById('firewall-panel-container');
        if (!this.container) return;
        this.preview = null;
        this.status = null;
        this.busy = false;
        this.statusLoading = false;
        this.statusVersion = 0;
        this.render();
        this.bindEvents();
        this.refreshStatus();
        this.poll = setInterval(() => {
            if (document.visibilityState === 'visible' && location.hash === '#engine') this.refreshStatus();
        }, 5000);
        this.poll.unref?.();
        state.on('rules', () => this.invalidatePreview('Saved rules changed. Review a fresh native policy before applying.'));
    }

    get(id) { return this.container.querySelector('#' + id); }

    render() {
        this.container.innerHTML = `
            <section class="card" aria-labelledby="firewall-heading">
                <div class="card-header"><div><h2 class="card-title" id="firewall-heading">${icon('shield')} Live Windows firewall</h2><p class="card-description">Apply supported rules to traffic on the computer running this server.</p></div><span class="badge badge-neutral" id="firewall-state">Not checked</span></div>
                <div class="card-body">
                    <p class="help-text">Capture analysis and live enforcement are separate. Saving a blocking rule does not change Windows Firewall. Review the native policy below before applying it.</p>
                    <div class="notice notice-info" id="firewall-diagnostic" role="status" hidden></div>
                    <p id="firewall-summary" class="help-text" role="status">Native status is checked while this page is open.</p>
                    <fieldset class="form-group" id="firewall-directions">
                        <legend class="form-label">Traffic directions</legend>
                        <div class="inline-actions">
                            <label><input type="checkbox" id="firewall-inbound" value="inbound"> Inbound</label>
                            <label><input type="checkbox" id="firewall-outbound" value="outbound" checked> Outbound</label>
                        </div>
                        <p class="help-text">IP rules match remote addresses. Inbound ports match local ports; outbound ports match remote ports. Each entry blocks independently on all firewall profiles.</p>
                    </fieldset>
                    <div class="inline-actions">
                        <button class="btn btn-secondary" id="firewall-preview-button" type="button">${icon('list')} Review native policy</button>
                        <button class="btn btn-ghost btn-sm" id="firewall-refresh" type="button">${icon('refresh')} Refresh status</button>
                        <button class="btn btn-ghost btn-sm" id="firewall-remove-button" type="button" disabled>${icon('trash')} Remove managed rules</button>
                    </div>
                    <div class="notice notice-info" id="firewall-notice" role="status" aria-live="polite" hidden></div>
                    <div id="firewall-preview" hidden>
                        <div class="section-heading"><h3 id="firewall-preview-title">Native policy preview</h3><span class="badge badge-neutral" id="firewall-preview-expiry"></span></div>
                        <div class="notice notice-warning">Applying this policy changes real network traffic and may interrupt connections. It replaces only DPI Engine's managed rules. Other Windows Firewall rules remain in place.</div>
                        <div class="table-container"><table class="data-table"><caption class="visually-hidden">Native firewall rules that will be installed</caption><thead><tr><th scope="col">Direction</th><th scope="col">Native match</th><th scope="col">Action</th></tr></thead><tbody id="firewall-preview-rows"></tbody></table></div>
                        <div class="notice notice-warning" id="firewall-unsupported" hidden><div><strong>Capture-only rules excluded from live enforcement</strong><ul id="firewall-unsupported-list"></ul></div></div>
                        <p class="help-text">Domain and application classifications cannot be reproduced by these native rules. Hostnames are never silently resolved into IP rules.</p>
                        <div class="inline-actions"><button class="btn btn-primary" id="firewall-apply-button" type="button" disabled>${icon('shield')} Apply reviewed policy</button><button class="btn btn-ghost" id="firewall-cancel-preview" type="button">Cancel preview</button></div>
                    </div>
                    <div class="notice notice-warning" id="firewall-removal" hidden>
                        <p id="firewall-removal-text"></p>
                        <button class="btn btn-danger" id="firewall-confirm-remove" type="button">Remove DPI Engine rules</button>
                        <button class="btn btn-secondary" id="firewall-cancel-remove" type="button">Cancel</button>
                    </div>
                    <details id="firewall-installed" hidden><summary>Installed DPI Engine rules</summary><div class="table-container"><table class="data-table"><caption class="visually-hidden">Actual native firewall rules owned by DPI Engine</caption><thead><tr><th scope="col">Rule</th><th scope="col">Direction</th><th scope="col">Enabled</th></tr></thead><tbody id="firewall-installed-rows"></tbody></table></div></details>
                </div>
            </section>`;
    }

    bindEvents() {
        this.get('firewall-preview-button').addEventListener('click', () => this.review());
        this.get('firewall-refresh').addEventListener('click', () => this.refreshStatus(true));
        this.get('firewall-apply-button').addEventListener('click', () => this.apply());
        this.get('firewall-cancel-preview').addEventListener('click', () => this.invalidatePreview());
        ['firewall-inbound', 'firewall-outbound'].forEach(id => this.get(id).addEventListener('change', () => this.invalidatePreview('Traffic directions changed. Review the updated policy before applying.')));
        this.get('firewall-remove-button').addEventListener('click', () => {
            this.get('firewall-removal-text').textContent = `Remove all ${formatNumber(this.status?.installedCount)} DPI Engine managed rules from this computer? Other firewall rules are unaffected.`;
            this.get('firewall-removal').hidden = false;
            this.get('firewall-confirm-remove').focus();
        });
        this.get('firewall-cancel-remove').addEventListener('click', () => { this.get('firewall-removal').hidden = true; });
        this.get('firewall-confirm-remove').addEventListener('click', () => this.remove());
        window.addEventListener('hashchange', () => { if (location.hash === '#engine') this.refreshStatus(); });
        document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && location.hash === '#engine') this.refreshStatus(); });
    }

    async request(path, method = 'GET', body) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), method === 'GET' ? 25000 : 150000);
        try {
            const response = await fetch(`${API_BASE}/firewall${path}`, {
                method,
                headers: { 'Content-Type': 'application/json' },
                signal: controller.signal,
                ...(body === undefined ? {} : { body: JSON.stringify(body) }),
            });
            const result = await response.json().catch(() => ({}));
            if (!response.ok) throw new Error(result.error || 'The firewall request could not be completed.');
            return result;
        } catch (error) {
            if (error.name === 'AbortError') throw new Error('The firewall request timed out. Its final state is unconfirmed; refresh native status before retrying.');
            throw error;
        } finally {
            clearTimeout(timeout);
        }
    }

    async refreshStatus(force = false) {
        if (this.busy || this.statusLoading || (!force && (document.visibilityState !== 'visible' || location.hash !== '#engine'))) return;
        this.statusLoading = true;
        const version = ++this.statusVersion;
        this.updateControls();
        try {
            const status = await this.request('/status');
            if (version === this.statusVersion) {
                this.status = status;
                this.renderStatus();
            }
        } catch (error) {
            if (version === this.statusVersion) {
                this.status = null;
                this.get('firewall-state').textContent = 'Status unavailable';
                this.get('firewall-summary').textContent = 'Native status could not be checked. No enforcement status is assumed.';
                this.get('firewall-diagnostic').textContent = error.message;
                this.get('firewall-diagnostic').hidden = false;
                this.get('firewall-installed').hidden = true;
            }
        } finally {
            this.statusLoading = false;
            this.updateControls();
        }
    }

    renderStatus() {
        const status = this.status;
        const known = status.statusKnown !== false && status.installedCount !== null;
        this.get('firewall-state').textContent = !status.supported ? 'Windows only' : !known ? 'Status unavailable' : status.installedCount ? 'Managed policy installed' : 'No managed policy';
        this.get('firewall-summary').textContent = known && status.supported
            ? `${formatNumber(status.installedCount)} installed · ${formatNumber(status.enabledCount)} enabled · ${formatNumber(status.activeCount)} enabled in active Windows policy`
            : 'No native enforcement status is assumed.';
        let diagnostic = status.message || '';
        if (status.supported && !status.elevated) diagnostic = 'Restart the server as Administrator to inspect and change Windows Defender Firewall. This interface never prompts for elevation automatically.';
        else if (status.supported && status.firewallEnabled === false) diagnostic = 'One or more Windows Firewall profiles are disabled. Installed rules may not be enforced for those profiles.';
        else if (status.enabledCount > status.activeCount) diagnostic = 'Some managed rules are absent from active Windows policy. Check local rule merging and organization policy before relying on enforcement.';
        this.get('firewall-diagnostic').textContent = diagnostic;
        this.get('firewall-diagnostic').hidden = !diagnostic;
        const rules = status.rules || [];
        this.get('firewall-installed').hidden = !rules.length;
        this.get('firewall-installed-rows').innerHTML = rules.map(rule => `<tr><td>${escapeHtml(rule.displayName)}</td><td>${escapeHtml(rule.direction)}</td><td>${rule.enabled ? 'Yes' : 'No'}</td></tr>`).join('');
        this.updateControls();
    }

    updateControls() {
        const canChange = Boolean(this.status?.supported && this.status.available && this.status.elevated && this.status.statusKnown !== false);
        this.get('firewall-preview-button').disabled = this.busy;
        this.get('firewall-preview-button').textContent = this.busy ? 'Working…' : 'Review native policy';
        this.get('firewall-refresh').disabled = this.busy || this.statusLoading;
        this.get('firewall-directions').disabled = this.busy;
        this.get('firewall-apply-button').disabled = this.busy || !canChange || !this.preview?.nativeRuleCount || Date.parse(this.preview.expiresAt) <= Date.now();
        this.get('firewall-remove-button').disabled = this.busy || !canChange || !this.status?.installedCount;
        this.get('firewall-confirm-remove').disabled = this.busy || !canChange;
        this.get('firewall-cancel-preview').disabled = this.busy;
        this.get('firewall-cancel-remove').disabled = this.busy;
    }

    notice(message, kind = 'info') {
        const element = this.get('firewall-notice');
        element.className = 'notice notice-' + kind;
        element.textContent = message;
        element.hidden = !message;
        element.setAttribute('aria-live', kind === 'error' ? 'assertive' : 'polite');
    }

    invalidatePreview(message = '') {
        const hadPreview = Boolean(this.preview);
        this.preview = null;
        this.get('firewall-preview').hidden = true;
        if (hadPreview && message) this.notice(message);
        this.updateControls();
    }

    async review() {
        if (this.busy) return;
        const directions = ['inbound', 'outbound'].filter(value => this.get('firewall-' + value).checked);
        if (!directions.length) { this.notice('Select at least one traffic direction.', 'error'); return; }
        this.busy = true;
        this.invalidatePreview();
        this.notice('');
        this.updateControls();
        try {
            this.preview = await this.request('/preview', 'POST', { directions });
            this.get('firewall-preview-title').textContent = `Review ${formatNumber(this.preview.nativeRuleCount)} native blocking rules`;
            this.get('firewall-preview-expiry').textContent = 'Expires ' + new Date(this.preview.expiresAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            this.get('firewall-preview-rows').innerHTML = this.preview.entries.length ? this.preview.entries.map(entry => `<tr><td>${escapeHtml(entry.direction)}</td><td>${escapeHtml(entry.label)}</td><td>Block</td></tr>`).join('') : '<tr><td colspan="3" class="table-empty">No supported native rules. Add IP, port, or supported protocol rules above.</td></tr>';
            this.get('firewall-unsupported').hidden = !this.preview.unsupported.length;
            this.get('firewall-unsupported-list').innerHTML = this.preview.unsupported.map(item => `<li><strong>${escapeHtml(item.value)}</strong>: ${escapeHtml(item.reason)}</li>`).join('');
            this.get('firewall-preview').hidden = false;
            this.get('firewall-preview').scrollIntoView({ behavior: 'auto', block: 'nearest' });
        } catch (error) {
            this.notice(error.message, 'error');
        } finally {
            this.busy = false;
            this.updateControls();
        }
    }

    async apply() {
        if (this.busy || !this.preview) return;
        const token = this.preview.token;
        this.busy = true;
        this.statusVersion++;
        this.notice('');
        this.updateControls();
        try {
            this.status = await this.request('/apply', 'POST', { token });
            this.renderStatus();
            this.invalidatePreview();
            this.notice(`Policy installed. Windows reports ${formatNumber(this.status.installedCount)} DPI Engine rules. Review the native status above for profile or policy limitations.`, 'success');
        } catch (error) {
            this.status = null;
            this.notice(error.message + ' Refresh native status before retrying.', 'error');
            this.invalidatePreview();
        } finally {
            this.busy = false;
            this.updateControls();
            this.refreshStatus(true);
        }
    }

    async remove() {
        if (this.busy) return;
        this.busy = true;
        this.statusVersion++;
        this.notice('');
        this.updateControls();
        try {
            // JSON content type is required by the local-control CSRF guard, including DELETE.
            this.status = await this.request('', 'DELETE', {});
            this.renderStatus();
            this.get('firewall-removal').hidden = true;
            this.invalidatePreview();
            this.notice('DPI Engine managed rules removed. Other Windows Firewall rules were not changed.', 'success');
        } catch (error) {
            this.status = null;
            this.notice(error.message + ' Refresh native status before retrying.', 'error');
        } finally {
            this.busy = false;
            this.updateControls();
            this.refreshStatus(true);
        }
    }
}
