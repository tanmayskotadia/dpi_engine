const API_BASE = '/api';

export const api = {
    // Engine API
    async startEngine(inputFile, outputFile, config) {
        const res = await fetch(`${API_BASE}/engine/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ inputFile, outputFile, config })
        });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.error || 'Failed to start engine');
        }
        return res.json();
    },

    async stopEngine() {
        const res = await fetch(`${API_BASE}/engine/stop`, { method: 'POST' });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.error || 'Failed to stop engine');
        }
        return res.json();
    },

    async getStatus() {
        const res = await fetch(`${API_BASE}/engine/status`);
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || 'Failed to get status');
        }
        return res.json();
    },

    // Results API
    async getLatestResults() {
        const res = await fetch(`${API_BASE}/results/latest`);
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || 'Failed to get latest results');
        }
        return res.json();
    },

    async getHistory() {
        const res = await fetch(`${API_BASE}/results/history`);
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || 'Failed to get history');
        }
        return res.json();
    },

    // Rules API
    async getRules() {
        const res = await fetch(`${API_BASE}/rules`);
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || 'Failed to get rules');
        }
        return res.json();
    },

    async addRule(type, value) {
        const res = await fetch(`${API_BASE}/rules/${type}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ [type]: value })
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || 'Failed to add rule');
        }
        return res.json();
    },

    async removeRule(type, value) {
        const res = await fetch(`${API_BASE}/rules/${type}/${encodeURIComponent(value)}`, {
            method: 'DELETE'
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || 'Failed to remove rule');
        }
        return res.json();
    },

    // Files API
    async uploadFile(file) {
        const formData = new FormData();
        formData.append('pcap', file);
        
        const res = await fetch(`${API_BASE}/files/upload`, {
            method: 'POST',
            body: formData
        });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.error || 'Upload failed');
        }
        return res.json();
    },
    
    async getFilesList() {
        const res = await fetch(`${API_BASE}/files/list`);
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || 'Failed to get files list');
        }
        return res.json();
    },
    
    async deleteFile(filename) {
        const res = await fetch(`${API_BASE}/files/${encodeURIComponent(filename)}`, {
            method: 'DELETE'
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || 'Failed to delete file');
        }
        return res.json();
    }
};
