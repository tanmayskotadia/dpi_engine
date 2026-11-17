export function initStatusMonitor(state) {
    const statusDot = document.querySelector('#global-status .status-dot');
    const statusText = document.querySelector('#global-status .status-text');
    const connection = document.getElementById('connection-status');
    const update = () => {
        const status = state.status;
        let [label, style] = ({ processing: ['Processing', 'processing'], complete: ['Ready · last run complete', 'complete'], error: ['Last run failed', 'error'] })[status.state] || ['Ready for analysis', 'complete'];
        if (status.engineDiagnostic?.exists === false || status.engineDiagnostic?.isExecutable === false) [label, style] = ['Engine unavailable', 'error'];
        if (state.connection.state !== 'connected') [label, style] = ['Waiting for connection', 'idle'];
        statusText.textContent = label;
        statusDot.className = `status-dot status-${style}`;
        const file = document.getElementById('current-file-badge');
        file.textContent = status.currentFile || 'No active capture';
        file.title = status.currentFile || '';
    };
    state.on('status', update);
    state.on('connection', value => {
        const connected = value.state === 'connected';
        connection.querySelector('.status-dot').className = `status-dot ${connected ? 'status-complete' : 'status-idle'}`;
        connection.lastElementChild.textContent = connected ? 'Connected' : value.state === 'connecting' ? 'Connecting' : 'Reconnecting';
        document.getElementById('connection-alert').hidden = value.state !== 'reconnecting';
        update();
    });
    state.on('data-errors', errors => {
        document.getElementById('data-alert').hidden = !errors.length;
        document.getElementById('data-alert-text').textContent = `Could not load ${errors.join(' and ')}. Check the connection and retry.`;
    });
    document.getElementById('retry-data').addEventListener('click', async event => {
        event.currentTarget.disabled = true;
        await Promise.allSettled([state.refreshStatus(), state.refreshRules(), state.refreshHistory()]);
        document.getElementById('retry-data').disabled = false;
    });
    update();
}
