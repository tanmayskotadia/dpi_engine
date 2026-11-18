import { icon } from '../ui.js';

function setIndicator(element, label, glyph) {
    const symbol = element.querySelector('.status-symbol');
    if (symbol.dataset.icon !== glyph) {
        symbol.dataset.icon = glyph;
        symbol.innerHTML = icon(glyph);
    }
    const text = element.querySelector('.status-text');
    if (text.textContent !== label) text.textContent = label;
}

export function initStatusMonitor(state) {
    const engine = document.getElementById('global-status');
    const connection = document.getElementById('connection-status');
    const file = document.getElementById('current-file-badge');
    const update = () => {
        const status = state.status;
        const connected = state.connection.state === 'connected';
        const reconnecting = state.connection.state === 'reconnecting';
        let [label, glyph] = ({
            processing: ['Processing', 'activity'],
            complete: ['Ready · last run complete', 'check'],
            error: ['Last run failed', 'alert']
        })[status.state] || ['Ready for analysis', 'check'];
        if (status.engineDiagnostic?.exists === false || status.engineDiagnostic?.isExecutable === false) [label, glyph] = ['Engine unavailable', 'alert'];
        if (!connected) [label, glyph] = ['Waiting for connection', 'clock'];
        setIndicator(engine, label, glyph);
        setIndicator(connection, connected ? 'Connected' : reconnecting ? 'Reconnecting' : 'Connecting', connected ? 'link' : 'refresh');
        document.getElementById('connection-alert').hidden = !reconnecting;
        file.hidden = !status.currentFile;
        file.textContent = status.currentFile || '';
        file.title = status.currentFile || '';
    };
    state.on('status', update);
    state.on('connection', update);
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
