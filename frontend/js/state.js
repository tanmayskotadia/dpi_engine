import { api, API_BASE } from './api.js';

export class StateManager {
    constructor() {
        this.status = { state: 'idle' };
        this.connection = { state: 'connecting' };
        this.rules = { blockedIPs: [], blockedApps: [], blockedDomains: [] };
        this.latestResults = null;
        this.history = [];
        this.listeners = new Map();
        this.dataErrors = new Set();
        this.resultsRevision = 0;
        this.statusRevision = 0;
        this.historyRequest = 0;
        this.resultsRequest = 0;
        this.statusRequest = 0;
        this.rulesRequest = 0;
        this.setupSSE();
    }

    setupSSE() {
        this.evtSource?.close();
        this.evtSource = new EventSource(`${API_BASE}/engine/stream`);
        const resetHeartbeat = () => {
            clearTimeout(this._heartbeatTimer);
            this._heartbeatTimer = setTimeout(() => this.evtSource.onerror(), 30000);
            this._heartbeatTimer.unref?.();
        };
        this.evtSource.onopen = () => {
            resetHeartbeat();
            const reconnected = this.connection.state === 'reconnecting';
            this._sseRetryDelay = 1000;
            this.connection = { state: 'connected' };
            this.notify('connection', this.connection);
            if (reconnected) {
                this.refreshStatus();
                this.refreshHistory();
                this.refreshRules();
            }
        };
        this.evtSource.onmessage = event => {
            resetHeartbeat();
            try {
                const { type, data } = JSON.parse(event.data);
                if (type === 'status') {
                    this.statusRevision++;
                    this.status = data;
                    this.notify('status', data);
                } else if (type === 'results') {
                    this.resultsRevision++;
                    this.latestResults = data;
                    this.notify('results', data);
                    this.refreshHistory();
                } else if (type === 'output' || type === 'error-output') {
                    this.notify('output', data, type === 'error-output');
                } else if (type === 'output-history' || type === 'error') {
                    this.notify(type, data);
                }
            } catch (error) { console.error('Could not read an engine update', error); }
        };
        this.evtSource.onerror = () => {
            clearTimeout(this._heartbeatTimer);
            this.evtSource.close();
            this.connection = { state: 'reconnecting' };
            this.notify('connection', this.connection);
            const delay = this._sseRetryDelay || 1000;
            this._sseRetryDelay = Math.min(delay * 2, 30000);
            clearTimeout(this._reconnectTimer);
            this._reconnectTimer = setTimeout(() => this.setupSSE(), delay);
        };
    }

    setDataError(name, failed) {
        if (failed) this.dataErrors.add(name);
        else this.dataErrors.delete(name);
        this.notify('data-errors', [...this.dataErrors]);
    }

    async refreshStatus() {
        const request = ++this.statusRequest;
        const revision = this.statusRevision;
        try {
            const status = await api.getStatus();
            if (request !== this.statusRequest) return;
            if (revision === this.statusRevision) {
                this.status = status;
                this.notify('status', status);
            }
            this.setDataError('engine status', false);
        } catch { if (request === this.statusRequest) this.setDataError('engine status', true); }
    }

    async refreshRules() {
        const request = ++this.rulesRequest;
        const previousRules = this.rules;
        try {
            const rules = await api.getRules();
            if (request !== this.rulesRequest) return;
            if (this.rules === previousRules) {
                this.rules = rules;
                this.notify('rules', rules);
            }
            this.setDataError('blocking rules', false);
        } catch { if (request === this.rulesRequest) this.setDataError('blocking rules', true); }
    }

    async refreshResults() {
        const request = ++this.resultsRequest;
        const revision = this.resultsRevision;
        try {
            const results = await api.getLatestResults();
            if (request !== this.resultsRequest) return;
            if (revision === this.resultsRevision) {
                this.resultsRevision++;
                this.latestResults = results.packetStats ? results : null;
                this.notify('results', this.latestResults);
            }
            this.setDataError('latest results', false);
        } catch { if (request === this.resultsRequest) this.setDataError('latest results', true); }
    }

    clearResults() {
        this.resultsRevision++;
        this.latestResults = null;
        this.notify('results', null);
    }

    async refreshHistory() {
        const request = ++this.historyRequest;
        const revision = this.resultsRevision;
        try {
            const history = await api.getHistory();
            if (request !== this.historyRequest) return;
            // A completed run can arrive over SSE while this request is in flight.
            if (revision !== this.resultsRevision && this.latestResults?.id && !history.some(run => run.id === this.latestResults.id)) history.push(this.latestResults);
            this.history = history.slice(-20);
            this.notify('history', this.history);
            const latest = this.history.at(-1);
            if (revision === this.resultsRevision && latest && latest.id !== this.latestResults?.id) {
                this.resultsRevision++;
                this.latestResults = latest;
                this.notify('results', latest);
            }
            this.setDataError('saved analyses', false);
        } catch { if (request === this.historyRequest) this.setDataError('saved analyses', true); }
    }

    on(event, callback) {
        if (!this.listeners.has(event)) this.listeners.set(event, []);
        this.listeners.get(event).push(callback);
    }

    notify(event, data, isError = false) {
        this.listeners.get(event)?.forEach(callback => callback(data, isError));
    }
}
