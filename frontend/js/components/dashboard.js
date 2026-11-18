import { icon, escapeHtml, formatBytes, formatNumber, formatDate } from '../ui.js';

export class Dashboard {
    constructor(state) {
        this.state = state;
        this.container = document.getElementById('view-dashboard');
        this.render();
        state.on('results', results => this.updateData(results));
        state.on('history', history => this.updateHistory(history));
        state.on('status', status => {
            const notice = document.getElementById('dashboard-processing');
            notice.hidden = status.state !== 'processing';
        });
    }

    render() {
        this.container.innerHTML = `
            <div class="page-heading">
                <h1>Traffic overview</h1>
                <a class="btn btn-primary" href="#engine">${icon('plus')} New analysis</a>
            </div>
            <div class="notice notice-info" id="dashboard-processing" role="status" hidden>${icon('activity')} Analysis in progress. The overview will update when it finishes. <a href="#logs">View live logs</a></div>
            <div class="welcome-panel" id="dashboard-welcome">
                <div class="welcome-icon">${icon('packets', 28)}</div><div><h2>No completed captures</h2><p>Record packets from an interface or upload a PCAP or PCAPNG file.</p></div>
                <a class="btn btn-secondary" href="#engine">Analyze a capture ${icon('arrowRight')}</a>
            </div>
            <div class="capture-context" id="capture-context" hidden>
                <span class="capture-file-icon">${icon('file', 20)}</span><div class="capture-context-copy"><span class="overline">LATEST COMPLETED CAPTURE</span><strong id="dash-capture-name"></strong></div>
                <span id="dash-capture-date" class="capture-date"></span>
            </div>
            <div class="stats-grid">
                ${[
                    ['total-packets', 'Total packets', 'packets', 'Packets inspected'],
                    ['total-bytes', 'Traffic volume', 'activity', 'Total capture size'],
                    ['forwarded', 'Forwarded', 'arrowRight', 'Passed filtering rules'],
                    ['dropped', 'Blocked', 'shield', 'Dropped by filtering rules'],
                ].map(([id, label, glyph, help]) => `<div class="stat-widget"><div class="stat-top"><span class="stat-label">${label}</span>${icon(glyph)}</div><strong class="stat-value" id="dash-${id}">—</strong><span class="stat-help" id="dash-${id}-help">${help}</span></div>`).join('')}
            </div>
            <div class="dashboard-charts">
                <article class="card">
                    <div class="card-header"><h2 class="card-title">Application breakdown</h2><span class="badge badge-neutral" id="dash-app-count">No data</span></div>
                    <div class="card-body app-chart" id="dash-app-chart"></div>
                    <div class="card-footer"><span>Top applications by packet count</span><a href="#results">View full breakdown ${icon('arrowRight', 15)}</a></div>
                </article>
                <article class="card">
                    <div class="card-header"><h2 class="card-title">Protocol distribution</h2></div>
                    <div class="card-body protocol-content">
                        <div class="protocol-donut" id="protocol-donut" aria-hidden="true"><div><strong id="protocol-total">—</strong><span>packets</span></div></div>
                        <div id="protocol-legend" class="protocol-legend"></div>
                    </div>
                    <div class="card-footer"><span id="protocol-note">Run an analysis to inspect protocols.</span></div>
                </article>
            </div>
            <div class="dashboard-bottom">
                <article class="card">
                    <div class="card-header"><h2 class="card-title">Detected domains</h2><span class="badge badge-neutral" id="dash-domain-count">0 domains</span></div>
                    <div class="table-container"><table class="data-table" id="dash-domains-table"><caption class="sr-only">Up to five detected hostnames and applications</caption><thead><tr><th scope="col">Domain / SNI</th><th scope="col">Application</th></tr></thead><tbody></tbody></table></div>
                    <div class="card-footer"><span>Showing up to 5 detected domains</span><a href="#results">Explore results ${icon('arrowRight', 15)}</a></div>
                </article>
                <article class="card">
                    <div class="card-header"><h2 class="card-title">Recent analyses</h2></div>
                    <div id="dash-history" class="recent-runs"></div>
                    <div class="card-footer"><span>Up to 20 runs retained</span><a href="#results">View history ${icon('arrowRight', 15)}</a></div>
                </article>
            </div>`;
        this.updateData(null);
        this.updateHistory([]);
    }

    updateData(results) {
        const hasData = Boolean(results?.packetStats);
        document.getElementById('dashboard-welcome').hidden = hasData;
        document.getElementById('capture-context').hidden = !hasData;
        document.getElementById('dash-capture-name').textContent = results?.inputFile || 'Packet capture';
        document.getElementById('dash-capture-date').textContent = hasData ? formatDate(results.timestamp) : '';
        const stats = results?.packetStats || {};
        const total = Number(stats.totalPackets) || 0;
        const forwarded = Number(results?.filteringStats?.forwarded) || 0;
        const dropped = Number(results?.filteringStats?.dropped) || 0;
        const values = { 'total-packets': formatNumber(total), 'total-bytes': formatBytes(stats.totalBytes), forwarded: formatNumber(forwarded), dropped: formatNumber(dropped) };
        Object.entries(values).forEach(([name, value]) => { document.getElementById(`dash-${name}`).textContent = hasData ? value : '—'; });
        document.getElementById('dash-forwarded-help').textContent = hasData && total ? `${(forwarded / total * 100).toFixed(1)}% of all packets` : 'Passed filtering rules';
        document.getElementById('dash-dropped-help').textContent = hasData && total ? `${(dropped / total * 100).toFixed(1)}% of all packets` : 'Dropped by filtering rules';

        const apps = [...(results?.appBreakdown || [])].sort((a, b) => b.count - a.count);
        const maxCount = Math.max(1, ...apps.map(app => Number(app.count) || 0));
        document.getElementById('dash-app-count').textContent = `${apps.length} application${apps.length === 1 ? '' : 's'}`;
        document.getElementById('dash-app-chart').innerHTML = apps.length ? apps.slice(0, 5).map((app, index) => {
            const percentage = total ? (Number(app.count) || 0) / total * 100 : 0;
            const width = Math.max(0, Math.min(100, (Number(app.count) || 0) / maxCount * 100));
            return `<div class="app-chart-row"><div class="app-chart-label"><span><span class="chart-key chart-key-${index}"></span>${escapeHtml(app.app)}</span><span><strong>${formatNumber(app.count)}</strong><small>${percentage.toFixed(1)}%</small></span></div><div class="chart-track" aria-hidden="true"><div class="chart-bar chart-bar-${index}" style="width:${width}%"></div></div></div>`;
        }).join('') : `<div class="empty-state"><strong>${hasData ? 'No applications identified in this capture.' : 'No capture analyzed.'}</strong></div>`;

        const protocols = [
            ['TCP', Number(stats.tcpPackets) || 0, '#000000'],
            ['UDP', Number(stats.udpPackets) || 0, '#969696'],
            ['ICMP', Number(stats.icmpPackets) || 0, '#393939'],
            ['ICMPv6', Number(stats.icmpv6Packets) || 0, '#b8b8b8'],
            ['ARP', Number(stats.arpPackets) || 0, '#686868'],
        ];
        const known = protocols.reduce((sum, [, count]) => sum + count, 0);
        protocols.push(['Other', Math.max(0, total - known), '#d8d8d8']);
        let position = 0;
        const segments = protocols.map(([, count, color]) => {
            const start = position;
            position += total ? count / total * 100 : 0;
            return color + ' ' + start + '% ' + position + '%';
        });
        document.getElementById('protocol-donut').style.background = total ? 'conic-gradient(' + segments.join(',') + ')' : 'var(--border-light)';
        document.getElementById('protocol-total').textContent = hasData ? formatNumber(total) : '—';
        document.getElementById('protocol-legend').innerHTML = protocols.filter(([, count], index) => count || index < 2).map(([name, count, color]) => `<div class="protocol-item"><span><span class="legend-dot" style="background:${color}"></span>${name}</span><strong>${hasData ? (total ? count / total * 100 : 0).toFixed(1) + '%' : '—'}</strong><small>${formatNumber(count)} packets</small></div>`).join('');
        document.getElementById('protocol-note').textContent = hasData ? 'All captured frames are counted, including unsupported traffic.' : 'Run an analysis to inspect protocols.';

        const domains = results?.detectedDomains || [];
        document.getElementById('dash-domain-count').textContent = `${domains.length} domain${domains.length === 1 ? '' : 's'}`;
        document.querySelector('#dash-domains-table tbody').innerHTML = domains.length ? domains.slice(0, 5).map(domain => `<tr><td class="domain-cell">${escapeHtml(domain.sni)}</td><td><span class="badge badge-neutral">${escapeHtml(domain.app)}</span></td></tr>`).join('') : `<tr><td colspan="2" class="table-empty">${hasData ? 'No domain names detected in this capture.' : 'Detected domains will appear after an analysis.'}</td></tr>`;
    }

    updateHistory(history) {
        document.getElementById('dash-history').innerHTML = history.length ? [...history].reverse().slice(0, 3).map(run => `<div class="recent-run"><span class="recent-run-icon">${icon('file', 18)}</span><div><strong title="${escapeHtml(run.inputFile)}">${escapeHtml(run.inputFile || 'Packet capture')}</strong><small>${escapeHtml(formatDate(run.timestamp))}</small></div><span class="recent-run-count">${formatNumber(run.packetStats?.totalPackets)}<small>packets</small></span></div>`).join('') : `<div class="empty-state">${icon('clock', 26)}<strong>No completed analyses yet</strong><p>Completed runs will be saved here.</p></div>`;
    }
}
