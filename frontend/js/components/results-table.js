export class ResultsView {
    constructor(state) {
        this.state = state;
        this.container = document.getElementById('view-results');
        this.render();
        
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
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title"><i class="fa-solid fa-list"></i> Full Application Breakdown</h3>
                </div>
                <table class="data-table" id="results-app-table">
                    <thead>
                        <tr>
                            <th>Application Type</th>
                            <th>Packet Count</th>
                            <th>Percentage</th>
                            <th style="width: 40%;">Distribution</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td colspan="4" style="text-align:center; color: var(--text-muted);">No analysis data available</td></tr>
                    </tbody>
                </table>
            </div>
            
            <div class="grid grid-cols-2" style="margin-top: 20px;">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fa-solid fa-microchip"></i> Load Balancer Threads</h3>
                    </div>
                    <table class="data-table" id="results-lb-table">
                        <thead>
                            <tr><th>Thread ID</th><th>Dispatched Packets</th></tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fa-solid fa-microchip"></i> Fast Path Threads</h3>
                    </div>
                    <table class="data-table" id="results-fp-table">
                        <thead>
                            <tr><th>Thread ID</th><th>Processed Packets</th></tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        `;
    }
    
    resetData() {
        const appBody = document.querySelector('#results-app-table tbody');
        if (appBody) {
            appBody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-muted);">No analysis data available</td></tr>';
        }

        const lbBody = document.querySelector('#results-lb-table tbody');
        if (lbBody) lbBody.innerHTML = '';

        const fpBody = document.querySelector('#results-fp-table tbody');
        if (fpBody) fpBody.innerHTML = '';
    }

    updateData(results) {
        if(!results) return;
        
        // App Breakdown
        const appBody = document.querySelector('#results-app-table tbody');
        appBody.innerHTML = '';
        if(results.appBreakdown && results.appBreakdown.length > 0) {
            // Sort by count descending
            const sorted = [...results.appBreakdown].sort((a,b) => b.count - a.count);
            
            sorted.forEach(app => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><strong>${app.app}</strong></td>
                    <td>${app.count.toLocaleString()}</td>
                    <td>${app.percentage.toFixed(2)}%</td>
                    <td>
                        <div class="progress-bar-bg">
                            <div class="progress-bar-fill" style="width: ${app.percentage}%; background-color: var(--accent-primary);"></div>
                        </div>
                    </td>
                `;
                appBody.appendChild(tr);
            });
        }
        
        // Thread Stats
        const lbBody = document.querySelector('#results-lb-table tbody');
        lbBody.innerHTML = '';
        if(results.threadStats?.loadBalancers) {
            results.threadStats.loadBalancers.forEach(lb => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>LB-${lb.id}</td><td>${lb.dispatched.toLocaleString()}</td>`;
                lbBody.appendChild(tr);
            });
        }
        
        const fpBody = document.querySelector('#results-fp-table tbody');
        fpBody.innerHTML = '';
        if(results.threadStats?.fastPaths) {
            results.threadStats.fastPaths.forEach(fp => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>FP-${fp.id}</td><td>${fp.processed.toLocaleString()}</td>`;
                fpBody.appendChild(tr);
            });
        }
    }
}
