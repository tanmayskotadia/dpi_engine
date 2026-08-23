export class LogsView {
    constructor(state) {
        this.state = state;
        this.container = document.getElementById('view-logs');
        this.autoScroll = true;
        
        this.render();
        
        // Cache DOM references AFTER render
        this.terminal = document.getElementById('logs-terminal');
        
        // Listen for new output
        this.state.on('output', (text, isError) => {
            this.appendLog(text, isError);
        });
        
        this.state.on('output-history', (text) => {
            this.terminal.innerHTML = ''; // clear
            this.appendLog(text, false);
        });
        
        this.terminal.addEventListener('scroll', () => {
            // Check if user scrolled up manually
            const isScrolledToBottom = this.terminal.scrollHeight - this.terminal.clientHeight <= this.terminal.scrollTop + 10;
            this.autoScroll = isScrolledToBottom;
        });
        
        document.getElementById('btn-clear-logs').addEventListener('click', () => {
            this.terminal.innerHTML = '';
        });
    }
    
    appendLog(text, isError) {
        const lines = text.split('\n');
        
        lines.forEach(line => {
            if (!line.trim() && lines.length > 1) return; // skip empty lines unless it's the only one
            
            const div = document.createElement('div');
            div.className = 'term-line';
            
            if (isError) {
                div.classList.add('term-error');
            } else if (line.includes('[Rules]')) {
                div.classList.add('term-warn');
            } else if (line.includes('Error')) {
                div.classList.add('term-error');
            } else if (line.includes('Total Packets') || line.includes('================')) {
                div.classList.add('term-info');
            } else if (line.includes('->')) {
                div.classList.add('term-highlight');
            }
            
            div.textContent = line;
            this.terminal.appendChild(div);
        });
        
        if (this.autoScroll) {
            this.terminal.scrollTop = this.terminal.scrollHeight;
        }
    }
    
    render() {
        this.container.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title"><i class="fa-solid fa-terminal"></i> Engine Console</h3>
                    <div>
                        <button id="btn-clear-logs" class="btn btn-secondary btn-sm"><i class="fa-solid fa-eraser"></i> Clear</button>
                    </div>
                </div>
                <div class="terminal" id="logs-terminal">
                    <div class="term-line term-info">DPI Engine Frontend Console initialized...</div>
                </div>
            </div>
        `;
    }
}
