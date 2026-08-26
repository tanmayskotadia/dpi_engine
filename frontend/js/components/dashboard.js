export class Dashboard {
    constructor(state) {
        this.state = state;
        this.container = document.getElementById('view-dashboard');
        this.render();
        
        this.chart = null;
        this._chartTimeout = null;
        
        this.state.on('results', (results) => {
            if (results) {
                this.updateData(results);
            } else {
                this.resetData();
            }
        });
    }
    
    render() {
        this.container.innerHTML = `
            <div class="grid grid-cols-4" style="margin-bottom: 20px;">
                <div class="stat-widget">
                    <span class="stat-label">Total Packets</span>
                    <span class="stat-value" id="dash-total-packets">0</span>
                </div>
                <div class="stat-widget">
                    <span class="stat-label">Total Bytes</span>
                    <span class="stat-value" id="dash-total-bytes">0</span>
                </div>
                <div class="stat-widget">
                    <span class="stat-label">Forwarded</span>
                    <span class="stat-value stat-success" id="dash-forwarded">0</span>
                </div>
                <div class="stat-widget">
                    <span class="stat-label">Dropped (Blocked)</span>
                    <span class="stat-value stat-danger" id="dash-dropped">0</span>
                </div>
            </div>
            
            <div class="grid grid-cols-2">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fa-solid fa-chart-pie"></i> Application Analysis</h3>
                    </div>
                    <div style="height: 300px; display: flex; justify-content: center; align-items: center;">
                        <canvas id="app-breakdown-chart"></canvas>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fa-solid fa-network-wired"></i> Protocol Distribution</h3>
                    </div>
                    <div style="padding-top: 20px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                            <span>TCP</span>
                            <span id="dash-tcp-pct">0%</span>
                        </div>
                        <div class="progress-bar-bg" style="margin-bottom: 25px;">
                            <div class="progress-bar-fill" id="dash-tcp-bar" style="width: 0%; background-color: var(--accent-primary);"></div>
                        </div>
                        
                        <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                            <span>UDP</span>
                            <span id="dash-udp-pct">0%</span>
                        </div>
                        <div class="progress-bar-bg" style="margin-bottom: 25px;">
                            <div class="progress-bar-fill" id="dash-udp-bar" style="width: 0%; background-color: var(--status-warning);"></div>
                        </div>
                    </div>
                    
                    <div style="margin-top: 30px;">
                        <h4 style="font-size: 0.9rem; margin-bottom: 15px; color: var(--text-secondary);">Top Detected Domains</h4>
                        <table class="data-table" id="dash-domains-table">
                            <thead>
                                <tr>
                                    <th>Domain / SNI</th>
                                    <th>Detected App</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr><td colspan="2" style="text-align:center; color: var(--text-muted);">No data available</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    }
    
    escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    resetData() {
        // Zero out stats
        const zeros = {
            'dash-total-packets': '0',
            'dash-total-bytes': '0',
            'dash-forwarded': '0',
            'dash-dropped': '0',
            'dash-tcp-pct': '0%',
            'dash-udp-pct': '0%',
        };
        Object.entries(zeros).forEach(([id, val]) => {
            const el = document.getElementById(id);
            if (el) el.textContent = val;
        });

        // Reset progress bars
        const tcpBar = document.getElementById('dash-tcp-bar');
        const udpBar = document.getElementById('dash-udp-bar');
        if (tcpBar) tcpBar.style.width = '0%';
        if (udpBar) udpBar.style.width = '0%';

        // Reset domains table
        const domainsBody = document.querySelector('#dash-domains-table tbody');
        if (domainsBody) {
            domainsBody.innerHTML = '<tr><td colspan="2" style="text-align:center; color: var(--text-muted);">No data available</td></tr>';
        }

        // Cancel any pending chart creation
        if (this._chartTimeout) {
            clearTimeout(this._chartTimeout);
            this._chartTimeout = null;
        }

        // Destroy chart
        if (this.chart) {
            this.chart.destroy();
            this.chart = null;
        }
    }
    
    updateData(results) {
        if(!results || !results.packetStats) return;
        
        // Update stats
        document.getElementById('dash-total-packets').textContent = results.packetStats.totalPackets.toLocaleString();
        document.getElementById('dash-total-bytes').textContent = results.packetStats.totalBytes.toLocaleString();
        
        if (results.filteringStats) {
            document.getElementById('dash-forwarded').textContent = results.filteringStats.forwarded.toLocaleString();
            document.getElementById('dash-dropped').textContent = results.filteringStats.dropped.toLocaleString();
        }
        
        // Update Protocol Bars
        const totalTcpUdp = results.packetStats.tcpPackets + results.packetStats.udpPackets;
        if(totalTcpUdp > 0) {
            const tcpPct = (results.packetStats.tcpPackets / totalTcpUdp) * 100;
            const udpPct = (results.packetStats.udpPackets / totalTcpUdp) * 100;
            
            document.getElementById('dash-tcp-pct').textContent = tcpPct.toFixed(1) + '%';
            document.getElementById('dash-tcp-bar').style.width = tcpPct + '%';
            
            document.getElementById('dash-udp-pct').textContent = udpPct.toFixed(1) + '%';
            document.getElementById('dash-udp-bar').style.width = udpPct + '%';
        }
        
        // Update Chart
        this.updateChart(results.appBreakdown);
        
        // Update Top Domains (take first 5)
        const domainsBody = document.querySelector('#dash-domains-table tbody');
        domainsBody.innerHTML = '';
        if(results.detectedDomains && results.detectedDomains.length > 0) {
            const topDomains = results.detectedDomains.slice(0, 5);
            topDomains.forEach(d => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${this.escapeHtml(d.sni)}</td><td><span class="badge">${this.escapeHtml(d.app)}</span></td>`;
                domainsBody.appendChild(tr);
            });
        } else {
            domainsBody.innerHTML = '<tr><td colspan="2" style="text-align:center; color: var(--text-muted);">No domains detected</td></tr>';
        }
    }
    
    updateChart(appData) {
        if(!appData || appData.length === 0) return;
        
        // Take top 6 apps, group rest into "Other"
        let displayData = [...appData].sort((a,b) => b.count - a.count);
        if(displayData.length > 6) {
            const top6 = displayData.slice(0, 6);
            const others = displayData.slice(6);
            const otherCount = others.reduce((sum, item) => sum + item.count, 0);
            top6.push({ app: 'Other', count: otherCount });
            displayData = top6;
        }
        
        const labels = displayData.map(d => d.app);
        const data = displayData.map(d => d.count);
        
        const colors = [
            '#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#ef4444', '#06b6d4', '#6b7280'
        ];
        
        const ctx = document.getElementById('app-breakdown-chart');
        
        if(this.chart) {
            this.chart.data.labels = labels;
            this.chart.data.datasets[0].data = data;
            this.chart.update();
        } else {
            // Wait a bit for the canvas to be ready if hidden
            this._chartTimeout = setTimeout(() => {
                this._chartTimeout = null;
                try {
                    this.chart = new Chart(ctx, {
                        type: 'doughnut',
                        data: {
                            labels: labels,
                            datasets: [{
                                data: data,
                                backgroundColor: colors,
                                borderWidth: 0
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    position: 'right',
                                    labels: { color: '#f3f4f6' }
                                }
                            }
                        }
                    });
                } catch(e) { console.error('Chart error', e); }
            }, 100);
        }
    }
}
