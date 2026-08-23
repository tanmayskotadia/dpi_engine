export function initStatusMonitor(state) {
    const statusDot = document.querySelector('#global-status .status-dot');
    const statusText = document.querySelector('#global-status .status-text');
    const fileBadge = document.getElementById('current-file-badge');
    
    state.on('status', (status) => {
        // Reset classes
        statusDot.className = 'status-dot';
        
        switch (status.state) {
            case 'processing':
                statusDot.classList.add('status-processing');
                statusText.textContent = '● Running';
                break;
            case 'complete':
                statusDot.classList.add('status-complete');
                statusText.textContent = '✓ Completed';
                break;
            case 'error':
                statusDot.classList.add('status-error');
                statusText.textContent = '✕ Failed';
                break;
            default:
                if (status.engineDiagnostic && !status.engineDiagnostic.exists) {
                    statusDot.classList.add('status-error'); // Or a distinct unavailable style
                    statusText.textContent = '● Unavailable';
                } else {
                    statusDot.classList.add('status-idle');
                    statusText.textContent = '● Ready';
                }
        }
        
        if (status.currentFile) {
            fileBadge.textContent = status.currentFile;
        } else {
            fileBadge.textContent = 'No file loaded';
        }
    });
}
