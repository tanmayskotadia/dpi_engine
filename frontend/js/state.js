import { api } from './api.js';

export class StateManager {
    constructor() {
        this.status = { state: 'idle' };
        this.rules = { blockedIPs: [], blockedApps: [], blockedDomains: [] };
        this.latestResults = null;
        this.history = [];
        this.listeners = new Map();
        
        this.setupSSE();
    }
    
    setupSSE() {
        if (this.evtSource) {
            this.evtSource.close();
        }
        
        this.evtSource = new EventSource('/api/engine/stream');
        
        this.evtSource.onmessage = (event) => {
            this._sseRetryDelay = 1000; // Reset backoff on successful message
            try {
                const parsed = JSON.parse(event.data);
                if (parsed.type === 'status') {
                    this.status = parsed.data;
                    this.notify('status', this.status);
                } else if (parsed.type === 'results') {
                    this.latestResults = parsed.data;
                    this.notify('results', this.latestResults);
                    this.refreshHistory(); // Fetch updated history
                } else if (parsed.type === 'output') {
                    this.notify('output', parsed.data);
                } else if (parsed.type === 'error-output') {
                    this.notify('output', parsed.data, true);
                } else if (parsed.type === 'output-history') {
                    this.notify('output-history', parsed.data);
                } else if (parsed.type === 'error') {
                    this.notify('error', parsed.data);
                }
            } catch (e) {
                console.error("SSE parse error", e);
            }
        };
        
        this.evtSource.onerror = () => {
            console.warn('SSE connection lost, will reconnect...');
            this.evtSource.close();
            
            // Exponential backoff: 1s, 2s, 4s, 8s... max 30s
            const delay = this._sseRetryDelay || 1000;
            this._sseRetryDelay = Math.min(delay * 2, 30000);
            
            setTimeout(() => this.setupSSE(), delay);
        };
    }
    
    async refreshStatus() {
        try {
            this.status = await api.getStatus();
            this.notify('status', this.status);
        } catch (e) {
            console.error('Failed to refresh status', e);
        }
    }
    
    async refreshRules() {
        try {
            this.rules = await api.getRules();
            this.notify('rules', this.rules);
        } catch (e) {
            console.error('Failed to refresh rules', e);
        }
    }
    
    async refreshResults() {
        try {
            this.latestResults = await api.getLatestResults();
            this.notify('results', this.latestResults);
        } catch (e) {
            console.error('Failed to refresh results', e);
        }
    }

    /** Clears the latest results from state and notifies the dashboard to reset */
    clearResults() {
        this.latestResults = null;
        this.notify('results', null);
    }
    
    async refreshHistory() {
        try {
            this.history = await api.getHistory();
            this.notify('history', this.history);
            
            // Also update latest results if we don't have them
            if (this.history.length > 0 && !this.latestResults?.id) {
                this.latestResults = this.history[this.history.length - 1];
                this.notify('results', this.latestResults);
            }
        } catch (e) {
            console.error('Failed to refresh history', e);
        }
    }
    
    on(event, callback) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, []);
        }
        this.listeners.get(event).push(callback);
    }
    
    notify(event, data, isError = false) {
        if (this.listeners.has(event)) {
            this.listeners.get(event).forEach(cb => cb(data, isError));
        }
    }
}
