import { icon, formatNumber } from '../ui.js';

const MAX_LINES = 3000;

export class LogsView {
    constructor(state) {
        this.state = state;
        this.container = document.getElementById('view-logs');
        this.autoScroll = true;
        this.rows = [];
        this.lineOpen = false;
        this.trimmedLines = 0;
        this.previousState = state.status?.state;
        this.render();
        this.terminal = this.get('logs-terminal');
        this.bindEvents();
        this.updateControls();

        state.on('output', (text, isError) => this.appendLog(text, isError));
        state.on('output-history', (text) => {
            this.clear();
            this.appendLog(text, false);
        });
        state.on('status', (status) => {
            if (status.state === 'processing' && this.previousState !== 'processing') this.clear();
            this.previousState = status.state;
            this.get('logs-engine-state').textContent = status.state === 'processing' ? 'Receiving output' : 'Engine output';
        });
    }

    get(id) {
        return this.container.querySelector(`#${id}`);
    }

    render() {
        this.container.innerHTML = `
            <div class="page-heading">
                <div><p class="eyebrow">ENGINE ACTIVITY</p><h1>Console logs</h1><p>Follow engine output and troubleshoot your most recent analysis.</p></div>
                <a href="#engine" class="btn btn-secondary">${icon('arrowRight')} Engine control</a>
            </div>
            <div class="notice notice-info" id="logs-notice" role="status" hidden></div>
            <div class="card console-card">
                <div class="card-header">
                    <div><h2 class="card-title">${icon('terminal')} <span id="logs-engine-state">Engine output</span></h2><p class="card-description">Live output from the current engine session.</p></div>
                    <div class="inline-actions console-actions" role="group" aria-label="Console controls">
                        <button id="btn-follow-logs" class="btn btn-secondary btn-sm" type="button" aria-pressed="true">${icon('pause')} Pause scrolling</button>
                        <button id="btn-copy-logs" class="btn btn-ghost btn-sm" type="button">${icon('copy')} Copy</button>
                        <button id="btn-download-logs" class="btn btn-ghost btn-sm" type="button">${icon('download')} Download</button>
                        <button id="btn-clear-logs" class="btn btn-ghost btn-sm" type="button">${icon('trash')} Clear</button>
                    </div>
                </div>
                <div class="terminal logs-terminal" id="logs-terminal" role="region" aria-label="Engine console output" tabindex="0">
                    <div class="console-empty" id="logs-empty">${icon('terminal', 30)}<strong>Waiting for engine output</strong><span>Start an analysis to see processing activity here.</span><a href="#engine" class="console-link">Go to engine control ${icon('arrowRight', 16)}</a></div>
                </div>
                <div class="console-footer"><span id="logs-line-count">0 lines</span><span id="logs-follow-status">Following new output</span></div>
            </div>
            <p class="help-text console-help">Logs reset when a new analysis starts. Clear only removes the output shown in this console.</p>
        `;
    }

    bindEvents() {
        this.terminal.addEventListener('scroll', () => {
            if (this.autoScroll && this.terminal.scrollHeight - this.terminal.clientHeight > this.terminal.scrollTop + 16) this.setFollow(false);
        }, { passive: true });
        this.terminal.addEventListener('wheel', () => this.pauseOnScroll(), { passive: true });
        this.terminal.addEventListener('touchmove', () => this.pauseOnScroll(), { passive: true });
        this.terminal.addEventListener('keydown', (event) => {
            if (['ArrowUp', 'PageUp', 'Home'].includes(event.key)) this.setFollow(false);
        });
        this.get('btn-follow-logs').addEventListener('click', () => this.setFollow(!this.autoScroll));
        this.get('btn-clear-logs').addEventListener('click', () => {
            this.clear();
            this.showNotice('Console cleared. New engine output will appear here.');
        });
        this.get('btn-copy-logs').addEventListener('click', async () => {
            try {
                if (!navigator.clipboard?.writeText) throw new Error('Clipboard access is unavailable in this browser. Download the logs instead.');
                await navigator.clipboard.writeText(this.logText());
                this.showNotice('Logs copied to your clipboard.');
            } catch (error) {
                this.showNotice(error.message || 'Could not copy logs. Download the logs instead.', true);
            }
        });
        this.get('btn-download-logs').addEventListener('click', () => {
            const url = URL.createObjectURL(new Blob([this.logText()], { type: 'text/plain;charset=utf-8' }));
            const link = document.createElement('a');
            link.href = url;
            link.download = 'dpi-engine-logs.txt';
            document.body.appendChild(link);
            link.click();
            link.remove();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        });
        window.addEventListener('hashchange', () => {
            if (window.location.hash === '#logs' && this.autoScroll) requestAnimationFrame(() => { this.terminal.scrollTop = this.terminal.scrollHeight; });
        });
    }

    pauseOnScroll() {
        if (!this.autoScroll) return;
        requestAnimationFrame(() => {
            if (this.terminal.scrollHeight - this.terminal.clientHeight > this.terminal.scrollTop + 16) this.setFollow(false);
        });
    }

    setFollow(enabled) {
        this.autoScroll = enabled;
        if (enabled) this.terminal.scrollTop = this.terminal.scrollHeight;
        this.updateControls();
    }

    clear() {
        this.rows = [];
        this.lineOpen = false;
        this.trimmedLines = 0;
        this.terminal.querySelectorAll('.term-line').forEach((line) => line.remove());
        this.get('logs-empty').hidden = false;
        this.updateControls();
    }

    logText() {
        return this.rows.map((row) => row.textContent).join('\n') + (this.lineOpen ? '' : '\n');
    }

    appendLog(text, isError = false) {
        if (!text) return;
        const lines = String(text).replace(/\r\n/g, '\n').replace(/\r/g, '').split('\n');
        this.get('logs-empty').hidden = true;
        const fragment = document.createDocumentFragment();
        lines.forEach((line, index) => {
            const lastPart = index === lines.length - 1;
            if (lastPart && line === '') return;
            let row;
            if (index === 0 && this.lineOpen && this.rows.length) {
                row = this.rows[this.rows.length - 1];
                row.textContent += line;
            } else {
                row = document.createElement('div');
                row.className = 'term-line';
                row.textContent = line || ' ';
                this.rows.push(row);
                fragment.appendChild(row);
            }
            if (isError || /\berror\b|\bfailed\b/i.test(row.textContent)) row.classList.add('term-error');
            else if (row.textContent.includes('[Rules]')) row.classList.add('term-warn');
            else if (/Total Packets|STATISTICS|BREAKDOWN/.test(row.textContent)) row.classList.add('term-info');
        });
        this.lineOpen = !String(text).endsWith('\n');
        this.terminal.appendChild(fragment);
        while (this.rows.length > MAX_LINES) {
            this.rows.shift().remove();
            this.trimmedLines++;
        }
        if (this.autoScroll) this.terminal.scrollTop = this.terminal.scrollHeight;
        this.updateControls();
    }

    updateControls() {
        const hasLogs = this.rows.length > 0;
        ['btn-clear-logs', 'btn-copy-logs', 'btn-download-logs'].forEach((id) => { this.get(id).disabled = !hasLogs; });
        const button = this.get('btn-follow-logs');
        button.setAttribute('aria-pressed', String(this.autoScroll));
        button.innerHTML = this.autoScroll ? `${icon('pause')} Pause scrolling` : `${icon('play')} Follow output`;
        this.get('logs-follow-status').textContent = this.autoScroll ? 'Following new output' : 'Scrolling paused · output is still collected';
        this.get('logs-line-count').textContent = this.trimmedLines
            ? `Latest ${formatNumber(this.rows.length)} lines · ${formatNumber(this.trimmedLines)} earlier lines omitted`
            : `${formatNumber(this.rows.length)} ${this.rows.length === 1 ? 'line' : 'lines'}`;
    }

    showNotice(message, isError = false) {
        const notice = this.get('logs-notice');
        notice.className = isError ? 'notice notice-error' : 'notice notice-info';
        notice.textContent = message;
        notice.hidden = false;
    }
}
