import { API_BASE } from '../api.js';
import { icon, escapeHtml, formatBytes, formatNumber, formatDate } from '../ui.js';

const number = (value) => Math.max(0, Number(value) || 0);
const percentage = (value) => Math.min(100, number(value));

export class ResultsView {
    constructor(state) {
        this.state = state;
        this.container = document.getElementById('view-results');
        this.latest = state.latestResults;
        this.selectedRunId = '';
        this.result = null;
        this.render();
        this.bindEvents();

        state.on('results', (result) => {
            this.latest = result;
            if (!result) this.selectedRunId = '';
            this.updateHistory();
            this.showSelectedRun();
        });
        state.on('history', () => {
            this.updateHistory();
            this.showSelectedRun();
        });
        this.updateHistory();
        this.showSelectedRun();
    }

    get(id) {
        return this.container.querySelector(`#${id}`);
    }

    render() {
        this.container.innerHTML = `
            <div class="page-heading">
                <h1>Analysis results</h1>
                <a href="#engine" class="btn btn-primary">${icon('plus')} New analysis</a>
            </div>
            <div class="card run-selector-card">
                <div class="form-group">
                    <label class="form-label" for="results-run-select">Analysis history</label>
                    <select id="results-run-select" class="form-control" aria-describedby="results-history-help"><option value="">Latest analysis</option></select>
                    <p class="help-text" id="results-history-help">Completed analyses are saved here automatically.</p>
                </div>
            </div>
            <div class="notice notice-error" id="results-error" role="alert" hidden></div>
            <div class="card empty-state" id="results-empty">
                <span class="empty-state-icon">${icon('list', 28)}</span>
                <h2>No analysis results yet</h2>
                <p>Analyze a capture to create your first report.</p>
                <a class="btn btn-primary" href="#engine">${icon('play')} Start an analysis</a>
            </div>
            <div id="results-content" class="results-content" hidden>
                <div class="notice notice-info" id="results-coverage" role="status" hidden></div>
                <div class="card result-context">
                    <div class="result-file">
                        <span class="file-icon">${icon('file', 22)}</span>
                        <div><h2 id="results-file-name" class="card-title"></h2><p id="results-run-time" class="help-text"></p></div>
                    </div>
                    <div class="inline-actions">
                        <button class="btn btn-secondary btn-sm" id="btn-download-report" type="button">${icon('download')} Export JSON</button>
                        <button class="btn btn-secondary btn-sm" id="btn-download-pcap" type="button">${icon('download')} Download capture</button>
                    </div>
                    <dl class="result-facts">
                        <div><dt>Total packets</dt><dd id="results-packets"></dd></div>
                        <div><dt>Traffic volume</dt><dd id="results-bytes"></dd></div>
                        <div><dt>Forwarded</dt><dd id="results-forwarded"></dd></div>
                        <div><dt>Dropped</dt><dd id="results-dropped"></dd></div>
                    </dl>
                    <p class="help-text" id="results-blocking-reasons"></p>
                </div>
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Application breakdown</h2>
                        <span class="badge badge-neutral" id="results-app-count">0 applications</span>
                    </div>
                    <div class="table-container">
                        <table class="data-table" id="results-app-table">
                            <caption class="visually-hidden">Application packet counts and share of traffic</caption>
                            <thead><tr><th scope="col">Application</th><th scope="col" class="numeric">Packets</th><th scope="col" class="numeric">Share</th><th scope="col" class="distribution-column">Distribution</th></tr></thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <div><h2 class="card-title">Detected domains</h2><p class="card-description">Hostnames identified from visible TLS server names, HTTP headers, and DNS questions.</p></div>
                        <span class="badge badge-neutral" id="results-domain-count">0 domains</span>
                    </div>
                    <div class="table-toolbar">
                        <div class="search-field">
                            ${icon('search')}
                            <label for="results-domain-search" class="visually-hidden">Search detected domains</label>
                            <input type="search" id="results-domain-search" class="form-control" placeholder="Search domains…" autocomplete="off">
                        </div>
                        <label for="results-app-filter" class="visually-hidden">Filter domains by application</label>
                        <select id="results-app-filter" class="form-control"><option value="">All applications</option></select>
                        <button class="btn btn-ghost btn-sm" id="btn-clear-result-filters" type="button" hidden>${icon('x')} Clear filters</button>
                    </div>
                    <div class="table-container">
                        <table class="data-table" id="results-domains-table">
                            <caption class="visually-hidden">Detected hostnames and associated applications</caption>
                            <thead><tr><th scope="col">Domain / SNI</th><th scope="col">Application</th></tr></thead>
                            <tbody></tbody>
                        </table>
                    </div>
                    <p class="table-footer" id="results-domain-summary" role="status"></p>
                </div>
                <details class="card thread-details">
                    <summary><span>${icon('activity')} Processing statistics</span><span class="help-text">Dispatch groups & analysis workers</span></summary>
                    <div class="grid grid-cols-2 thread-tables">
                        <div>
                            <h3 class="card-title">Dispatch groups</h3>
                            <div class="table-container"><table class="data-table" id="results-lb-table"><caption class="visually-hidden">Packets dispatched by each load balancer</caption><thead><tr><th scope="col">Thread</th><th scope="col" class="numeric">Dispatched packets</th></tr></thead><tbody></tbody></table></div>
                        </div>
                        <div>
                            <h3 class="card-title">Analysis workers</h3>
                            <div class="table-container"><table class="data-table" id="results-fp-table"><caption class="visually-hidden">Packets processed by each fast path thread</caption><thead><tr><th scope="col">Thread</th><th scope="col" class="numeric">Processed packets</th></tr></thead><tbody></tbody></table></div>
                        </div>
                    </div>
                </details>
            </div>
        `;
    }

    bindEvents() {
        this.get('results-run-select').addEventListener('change', (event) => {
            this.selectedRunId = event.target.value;
            this.get('results-domain-search').value = '';
            this.get('results-app-filter').value = '';
            this.showSelectedRun();
        });
        this.get('results-domain-search').addEventListener('input', () => this.renderDomains());
        this.get('results-app-filter').addEventListener('change', () => this.renderDomains());
        this.get('btn-clear-result-filters').addEventListener('click', () => {
            this.get('results-domain-search').value = '';
            this.get('results-app-filter').value = '';
            this.renderDomains();
            this.get('results-domain-search').focus();
        });
        this.get('btn-download-report').addEventListener('click', () => {
            if (!this.result) return;
            this.saveBlob(new Blob([JSON.stringify(this.result, null, 2)], { type: 'application/json' }), `${this.result.id || 'analysis'}-report.json`);
        });
        this.get('btn-download-pcap').addEventListener('click', () => this.downloadPcap());
    }

    updateHistory() {
        const history = [...(this.state.history || [])].reverse();
        const select = this.get('results-run-select');
        select.replaceChildren(new Option('Latest analysis', ''));
        for (const result of history) {
            if (!result.id) continue;
            select.add(new Option(`${formatDate(result.timestamp)} · ${result.inputFile || 'Packet capture'}`, result.id));
        }
        if (this.selectedRunId && !history.some((result) => result.id === this.selectedRunId)) this.selectedRunId = '';
        select.value = this.selectedRunId;
        select.disabled = history.length === 0;
        this.get('results-history-help').textContent = history.length
            ? `${formatNumber(history.length)} saved ${history.length === 1 ? 'analysis' : 'analyses'}. Choose a run to review its results.`
            : 'Completed analyses are saved here automatically.';
    }

    showSelectedRun() {
        const result = this.selectedRunId
            ? this.state.history.find((item) => item.id === this.selectedRunId)
            : this.latest;
        this.updateData(result);
    }

    resetData() {
        this.latest = null;
        this.selectedRunId = '';
        this.updateHistory();
        this.updateData(null);
    }

    updateData(result) {
        this.result = result?.packetStats ? result : null;
        const hasResults = Boolean(this.result);
        this.get('results-empty').hidden = hasResults;
        this.get('results-content').hidden = !hasResults;
        this.get('results-error').hidden = true;
        if (!hasResults) return;

        this.get('results-file-name').textContent = result.inputFile || 'Packet capture';
        this.get('results-run-time').textContent = `${this.selectedRunId ? 'Saved analysis' : 'Latest analysis'} · ${formatDate(result.timestamp)}`;
        this.get('results-packets').textContent = formatNumber(number(result.packetStats.totalPackets));
        this.get('results-bytes').textContent = formatBytes(number(result.packetStats.totalBytes));
        this.get('results-forwarded').textContent = formatNumber(number(result.filteringStats?.forwarded));
        this.get('results-dropped').textContent = formatNumber(number(result.filteringStats?.dropped));
        this.get('btn-download-pcap').disabled = !result.outputFile;
        const coverage = [['unsupported', 'unsupported frames'], ['malformed', 'malformed frames'], ['truncated', 'truncated frames'], ['fragments', 'IP fragments'], ['inspectionLimited', 'flows at the inspection limit']]
            .filter(([key]) => result.packetStats[key]).map(([key, label]) => `${formatNumber(result.packetStats[key])} ${label}`);
        this.get('results-coverage').hidden = !coverage.length;
        this.get('results-coverage').textContent = `${coverage.join(' · ')}. These are counted and preserved unless a known rule matches. Hostname inspection is limited for incomplete, fragmented, or encrypted traffic.`;
        this.get('results-blocking-reasons').textContent = (result.blockingReasons || []).length
            ? `Blocked by: ${result.blockingReasons.map(item => `${item.reason} (${formatNumber(item.count)})`).join(' · ')}. These counts describe the filtered capture, not live firewall activity.`
            : 'Filtering results describe this saved capture. Live firewall policy is managed separately.';

        const apps = [...(result.appBreakdown || [])].sort((a, b) => number(b.count) - number(a.count));
        this.get('results-app-count').textContent = `${apps.length} ${apps.length === 1 ? 'application' : 'applications'}`;
        this.get('results-app-table').querySelector('tbody').innerHTML = apps.length
            ? apps.map((app) => `<tr><td><span class="application-name">${escapeHtml(String(app.app))}</span></td><td class="numeric">${formatNumber(number(app.count))}</td><td class="numeric">${percentage(app.percentage).toFixed(1)}%</td><td><div class="progress-bar-bg" aria-hidden="true"><div class="progress-bar-fill" style="width:${percentage(app.percentage)}%"></div></div></td></tr>`).join('')
            : '<tr><td colspan="4" class="table-empty">No application classifications were reported for this capture.</td></tr>';

        const filter = this.get('results-app-filter');
        const previousFilter = filter.value;
        filter.replaceChildren(new Option('All applications', ''));
        [...new Set((result.detectedDomains || []).map((domain) => String(domain.app)))].sort().forEach((app) => filter.add(new Option(app, app)));
        filter.value = [...filter.options].some((option) => option.value === previousFilter) ? previousFilter : '';
        this.renderDomains();
        this.renderThreads('results-lb-table', result.threadStats?.loadBalancers, 'LB', 'dispatched');
        this.renderThreads('results-fp-table', result.threadStats?.fastPaths, 'FP', 'processed');
    }

    renderDomains() {
        const domains = this.result?.detectedDomains || [];
        const query = this.get('results-domain-search').value.trim().toLocaleLowerCase();
        const app = this.get('results-app-filter').value;
        const filtered = domains.filter((domain) => String(domain.sni).toLocaleLowerCase().includes(query) && (!app || String(domain.app) === app));
        this.get('btn-clear-result-filters').hidden = !query && !app;
        this.get('results-domain-count').textContent = `${domains.length} ${domains.length === 1 ? 'domain' : 'domains'}`;
        this.get('results-domains-table').querySelector('tbody').innerHTML = filtered.length
            ? filtered.map((domain) => `<tr><td class="domain-cell">${escapeHtml(String(domain.sni))}</td><td><span class="badge badge-neutral">${escapeHtml(String(domain.app))}</span></td></tr>`).join('')
            : `<tr><td colspan="2" class="table-empty">${domains.length ? 'No domains match your filters. Try another search or clear the filters.' : 'No hostnames were detected in this capture. Encrypted traffic may not expose a server name.'}</td></tr>`;
        this.get('results-domain-summary').textContent = `Showing ${formatNumber(filtered.length)} of ${formatNumber(domains.length)} detected ${domains.length === 1 ? 'domain' : 'domains'}`;
    }

    renderThreads(tableId, rows = [], prefix, countKey) {
        this.get(tableId).querySelector('tbody').innerHTML = rows.length
            ? rows.map((row) => `<tr><td class="mono">${prefix}-${escapeHtml(String(row.id))}</td><td class="numeric">${formatNumber(number(row[countKey]))}</td></tr>`).join('')
            : '<tr><td colspan="2" class="table-empty">No thread statistics reported.</td></tr>';
    }

    saveBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    async downloadPcap() {
        if (!this.result?.outputFile) return;
        const filename = this.result.outputFile;
        const button = this.get('btn-download-pcap');
        button.disabled = true;
        button.innerHTML = `${icon('download')} Downloading…`;
        this.get('results-error').hidden = true;
        try {
            const response = await fetch(`${API_BASE}/files/download/${encodeURIComponent(filename)}`);
            if (!response.ok) {
                const error = await response.json().catch(() => ({}));
                throw new Error(error.error || 'The output file is no longer available. Run the capture again to generate a new file.');
            }
            this.saveBlob(await response.blob(), filename);
        } catch (error) {
            this.get('results-error').textContent = `Could not download the capture. ${error.message}`;
            this.get('results-error').hidden = false;
        } finally {
            button.disabled = !this.result?.outputFile;
            button.innerHTML = `${icon('download')} Download capture`;
        }
    }
}
