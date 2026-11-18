import { API_BASE } from '../api.js';
import { icon, escapeHtml, formatBytes, formatNumber } from '../ui.js';

const ACTIVE = new Set(['starting', 'capturing', 'stopping']);

export class CapturePanel {
    constructor(state) {
        this.state = state;
        this.container = document.getElementById('capture-panel-container');
        if (!this.container) return;
        this.status = { state: 'idle' };
        this.interfaces = [];
        this.available = false;
        this.busy = false;
        this.refreshing = false;
        this.statusRequest = 0;
        this.statusUnavailable = false;
        this.lastCompletedId = null;
        this.render();
        this.bindEvents();
        this.loadInterfaces();
        this.refreshStatus();
        this.state.on('connection', () => this.updateUI());
        this.pollTimer = setInterval(() => {
            if (!this.busy && (ACTIVE.has(this.status.state) || !document.getElementById('view-engine')?.hidden)) this.refreshStatus();
        }, 1500);
        window.addEventListener('pagehide', () => clearInterval(this.pollTimer), { once: true });
    }

    element(id) { return this.container.querySelector(`#${id}`); }

    async request(route, body) {
        const response = await fetch(`${API_BASE}/capture/${route}`, body === undefined
            ? { cache: 'no-store' }
            : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || 'Capture request failed.');
        return result;
    }

    render() {
        this.container.innerHTML = `
            <section class="card" aria-labelledby="capture-live-heading">
                <div class="card-header">
                    <div><h2 class="card-title" id="capture-live-heading">${icon('activity')} Live packet capture</h2>
                    <p class="card-description">Record traffic from a local interface, then analyze the saved capture.</p></div>
                    <span class="badge badge-neutral" id="capture-state-badge">Ready</span>
                </div>
                <div class="card-body">
                    <p class="help-text">Captures packets visible on the selected interface. Recording and offline blocking rules do not change your system firewall.</p>
                    <form id="capture-form" novalidate>
                        <div class="form-group">
                            <label class="form-label" for="capture-interface">Local network interface</label>
                            <div class="capture-select-row">
                                <select id="capture-interface" class="form-control" required><option value="">Loading interfaces…</option></select>
                                <button type="button" class="btn btn-secondary icon-btn" id="capture-refresh" aria-label="Refresh network interfaces" title="Refresh network interfaces">${icon('refresh')}</button>
                            </div>
                            <p class="help-text" id="capture-interface-help">Interfaces come from Wireshark dumpcap on the server.</p>
                        </div>
                        <div class="form-row">
                            <div class="form-group"><label class="form-label" for="capture-duration">Duration limit (seconds)</label>
                                <input id="capture-duration" class="form-control" type="number" min="1" max="300" step="1" value="30" required></div>
                            <div class="form-group"><label class="form-label" for="capture-packets">Packet limit</label>
                                <input id="capture-packets" class="form-control" type="number" min="1" max="1000000" step="1" value="10000" required></div>
                        </div>
                        <details class="advanced-settings">
                            <summary>${icon('filter')} Optional capture filter</summary>
                            <div class="form-group"><label class="form-label" for="capture-filter">BPF expression</label>
                                <input id="capture-filter" class="form-control" type="text" maxlength="512" placeholder="For example: host 192.168.1.10" autocomplete="off" spellcheck="false" aria-describedby="capture-filter-help">
                                <p class="help-text" id="capture-filter-help">Leave blank to record all frames. A BPF filter limits what is recorded.</p></div>
                        </details>
                        <p class="help-text" id="capture-limits">Capture stops at the first limit: duration, packet count, or 100 MB.</p>
                        <div id="capture-feedback" class="notice notice-info" role="status" aria-live="polite" hidden></div>
                        <div class="run-actions">
                            <button type="submit" class="btn btn-primary" id="capture-start">${icon('activity')} Start capture</button>
                            <button type="button" class="btn btn-danger" id="capture-stop" hidden>${icon('stop')} Stop and save</button>
                        </div>
                    </form>
                </div>
            </section>`;
    }

    bindEvents() {
        this.element('capture-refresh').addEventListener('click', () => this.loadInterfaces());
        this.element('capture-form').addEventListener('submit', event => { event.preventDefault(); this.start(); });
        this.element('capture-stop').addEventListener('click', () => this.stop());
    }

    showFeedback(message, kind = 'info') {
        const notice = this.element('capture-feedback');
        const html = `${icon(kind === 'error' ? 'alert' : kind === 'success' ? 'check' : 'info')}<span>${escapeHtml(message)}</span>`;
        notice.className = `notice notice-${kind}`;
        notice.hidden = !message;
        if (notice.innerHTML !== html) notice.innerHTML = html;
    }

    async loadInterfaces() {
        if (this.refreshing || ACTIVE.has(this.status.state)) return;
        this.refreshing = true;
        this.updateUI();
        try {
            const result = await this.request('interfaces');
            const select = this.element('capture-interface');
            const previousDevice = this.interfaces.find(network => network.id === select.value)?.name;
            this.interfaces = result.interfaces || [];
            this.available = result.available && this.interfaces.length > 0;
            select.replaceChildren(new Option(this.available ? 'Select a network interface' : 'No capture interfaces available', ''));
            this.interfaces.forEach(network => select.add(new Option(network.label, network.id)));
            const previouslySelected = this.interfaces.find(network => network.name === previousDevice);
            if (previouslySelected) select.value = previouslySelected.id;
            this.element('capture-interface-help').textContent = result.error || 'Only local capture interfaces are listed. Select the network you want to inspect.';
            if (result.maximumBytes) this.element('capture-limits').textContent = `Capture stops at the first limit: duration, packet count, or ${formatBytes(result.maximumBytes)}.`;
        } catch (error) {
            this.available = false;
            this.element('capture-interface-help').textContent = error.message;
        } finally { this.refreshing = false; this.updateUI(); }
    }

    async refreshStatus() {
        const request = ++this.statusRequest;
        try {
            const status = await this.request('status');
            if (request !== this.statusRequest) return;
            this.statusUnavailable = false;
            this.applyStatus(status);
        } catch {
            if (request !== this.statusRequest) return;
            this.statusUnavailable = true;
            this.showFeedback('Capture status is unavailable. Waiting for the server to reconnect.', 'error');
            this.updateUI();
        }
    }

    applyStatus(status) {
        this.status = status;
        if (status.state === 'complete' && status.result) {
            this.showFeedback(`Capture saved: ${formatNumber(status.result.packetCount)} packets, ${formatBytes(status.result.size)}. It is ready in saved captures.${status.result.recoveredTail ? ' An unfinished final block was discarded when stopping.' : ''}`, 'success');
            if (this.lastCompletedId !== status.result.id) {
                this.lastCompletedId = status.result.id;
                window.dispatchEvent(new CustomEvent('capture-complete', { detail: status.result }));
            }
        } else if (status.state === 'error') this.showFeedback(status.error || 'Capture failed. Check the interface and capture permissions.', 'error');
        else if (status.state === 'capturing') this.showFeedback(`Recording ${status.interface?.label || 'the selected interface'}. Stop and save at any time.`);
        else if (status.state === 'starting') this.showFeedback('Starting the capture process…');
        else if (status.state === 'stopping') this.showFeedback('Stopping capture and checking the saved file…');
        this.updateUI();
    }

    async start() {
        if (this.busy || ACTIVE.has(this.status.state) || !this.available) return;
        const network = this.interfaces.find(item => item.id === this.element('capture-interface').value);
        if (!network) { this.showFeedback('Select a local network interface first.', 'error'); this.element('capture-interface').focus(); return; }
        const duration = this.element('capture-duration');
        const packets = this.element('capture-packets');
        if (!duration.checkValidity() || !packets.checkValidity()) {
            this.showFeedback('Use a duration of 1–300 seconds and a packet limit of 1–1,000,000.', 'error');
            (!duration.checkValidity() ? duration : packets).focus(); return;
        }
        this.busy = true;
        ++this.statusRequest;
        this.showFeedback('Starting capture…');
        this.updateUI();
        try {
            this.applyStatus(await this.request('start', { interfaceId: network.id, interfaceName: network.name, duration: Number(duration.value), packetLimit: Number(packets.value), filter: this.element('capture-filter').value }));
        } catch (error) { this.showFeedback(error.message, 'error'); }
        finally { this.busy = false; this.updateUI(); }
    }

    async stop() {
        if (this.busy || !ACTIVE.has(this.status.state)) return;
        this.busy = true;
        ++this.statusRequest;
        this.updateUI();
        try { this.applyStatus(await this.request('stop', {})); }
        catch (error) { this.showFeedback(error.message, 'error'); }
        finally { this.busy = false; this.updateUI(); }
    }

    updateUI() {
        const active = ACTIVE.has(this.status.state);
        const disconnected = this.statusUnavailable || (this.state.connection && this.state.connection.state !== 'connected');
        this.element('capture-state-badge').textContent = { idle: 'Ready', starting: 'Starting', capturing: 'Recording', stopping: 'Saving', complete: 'Saved', error: 'Needs attention' }[this.status.state] || 'Ready';
        this.element('capture-start').disabled = this.busy || active || this.refreshing || !this.available || disconnected;
        this.element('capture-stop').hidden = !active;
        this.element('capture-stop').disabled = this.busy || this.status.state === 'stopping' || disconnected;
        this.element('capture-refresh').disabled = this.busy || active || this.refreshing || disconnected;
        ['capture-interface', 'capture-duration', 'capture-packets', 'capture-filter'].forEach(id => { this.element(id).disabled = this.busy || active || this.refreshing; });
    }
}
