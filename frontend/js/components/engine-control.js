import { api } from '../api.js';

export class EngineControl {
    constructor(state) {
        this.state = state;
        this.container = document.getElementById('view-engine');
        this.render();
        this.bindEvents();
        
        this.state.on('status', this.updateUI.bind(this));
    }
    
    render() {
        this.container.innerHTML = `
            <div class="grid grid-cols-2">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fa-solid fa-play"></i> Run Analysis</h3>
                    </div>
                    
                    <div class="form-group" style="position: relative; z-index: 100;">
                        <label class="form-label">Input PCAP File</label>
                        <div style="display: flex; gap: 10px; flex-direction: column;">
                            <div id="pcap-custom-select" class="custom-select form-control" style="padding: 0;">
                                <div class="custom-select-trigger" style="padding: 12px 14px;">
                                    <span id="pcap-custom-select-text">Select uploaded file...</span>
                                    <i class="fa-solid fa-chevron-down" style="font-size: 0.8rem; color: var(--text-muted);"></i>
                                </div>
                                <div id="pcap-custom-select-dropdown" class="custom-select-dropdown">
                                    <!-- Options populated dynamically -->
                                </div>
                            </div>
                            <input type="hidden" id="engine-input-file" value="">
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Upload New PCAP</label>
                        <div style="display: flex; gap: 10px;">
                            <input type="file" id="engine-upload-input" class="form-control" accept=".pcap,.pcapng">
                            <button id="btn-upload" class="btn btn-secondary">Upload</button>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Output Filename <span style="color: var(--text-muted); font-weight: 400;">(filename only — saved to server outputs directory)</span></label>
                        <input type="text" id="engine-output-file" class="form-control" value="output.pcap" placeholder="output.pcap">
                    </div>
                    
                    <div style="margin-top: 25px; display: flex; gap: 15px;">
                        <button id="btn-start" class="btn btn-primary" style="flex: 1;"><i class="fa-solid fa-bolt"></i> Start Engine</button>
                        <button id="btn-stop" class="btn btn-danger" style="flex: 1;" disabled><i class="fa-solid fa-stop"></i> Stop</button>
                    </div>
                    <div style="margin-top: 15px; display: flex; justify-content: center;">
                        <button id="btn-reset" class="btn btn-secondary" style="width: 100%;"><i class="fa-solid fa-rotate-right"></i> Reset Selections</button>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fa-solid fa-gear"></i> Engine Configuration</h3>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Load Balancer Threads (--lbs)</label>
                        <input type="number" id="engine-cfg-lbs" class="form-control" value="2" min="1" max="16">
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Fast Path Threads per LB (--fps)</label>
                        <input type="number" id="engine-cfg-fps" class="form-control" value="2" min="1" max="16">
                    </div>
                    
                    <div class="stat-widget" style="margin-top: 20px;">
                        <span class="stat-label">Total Processing Threads</span>
                        <span class="stat-value" id="engine-total-threads">4</span>
                    </div>
                    
                    <div class="form-group" style="margin-top: 20px;">
                        <label class="form-label">Active Blocking Rules</label>
                        <div class="badge" id="engine-rules-count" style="cursor: pointer; user-select: none;" onclick="document.getElementById('engine-rules-container').scrollIntoView({behavior: 'smooth', block: 'start'})">0 Rules Active</div>
                        <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 5px;">Manage rules in the section below before starting.</p>
                    </div>
                </div>
            </div>
            
            <div id="engine-rules-container" style="margin-top: 25px;"></div>
            
            <div id="engine-error-alert" class="engine-error-box" style="display: none; margin-top: 20px;">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                    <i class="fa-solid fa-circle-exclamation" style="color: var(--status-error); font-size: 1.2rem;"></i>
                    <strong style="color: var(--status-error);" id="engine-error-title">Engine Failed</strong>
                </div>
                <pre id="engine-error-text" style="margin: 0; font-family: var(--font-mono); font-size: 0.85rem; color: var(--text-secondary); white-space: pre-wrap; word-break: break-word;"></pre>
            </div>
            
            <div class="card" style="margin-top: 20px;">
                <div class="card-header" style="display: flex; justify-content: space-between; align-items: center;">
                    <h3 class="card-title"><i class="fa-solid fa-desktop"></i> Console Output</h3>
                    <span id="engine-progress-badge" class="badge" style="display: none; background-color: var(--accent-primary); color: white;">Processing...</span>
                </div>
                <div class="terminal" id="engine-mini-console" style="height: 250px;">
                    <div class="term-line term-info">Waiting for engine to start...</div>
                </div>
            </div>
        `;
        
        this.refreshFileList();
    }
    
    bindEvents() {
        const lbsInput = document.getElementById('engine-cfg-lbs');
        const fpsInput = document.getElementById('engine-cfg-fps');
        const totalThreads = document.getElementById('engine-total-threads');
        
        const updateThreads = () => {
            const lbs = parseInt(lbsInput.value) || 1;
            const fps = parseInt(fpsInput.value) || 1;
            totalThreads.textContent = lbs * fps;
        };
        
        lbsInput.addEventListener('input', updateThreads);
        fpsInput.addEventListener('input', updateThreads);
        
        // Custom Dropdown logic
        const selectTrigger = document.querySelector('.custom-select-trigger');
        const dropdown = document.getElementById('pcap-custom-select-dropdown');
        
        if (selectTrigger && dropdown) {
            selectTrigger.addEventListener('click', (e) => {
                dropdown.classList.toggle('open');
                e.stopPropagation();
            });
            
            document.addEventListener('click', (e) => {
                if (!e.target.closest('.custom-select')) {
                    dropdown.classList.remove('open');
                }
            });
            
            dropdown.addEventListener('click', async (e) => {
                const option = e.target.closest('.custom-option');
                if (!option || !option.dataset.value) return;
                
                const deleteBtn = e.target.closest('.delete-icon');
                const filename = option.dataset.filename;
                const filepath = option.dataset.value;
                
                if (deleteBtn) {
                    e.stopPropagation(); // prevent option selection
                    
                    const isOutput = filename.includes('output');
                    let msg = `Are you sure you want to permanently delete "${filename}"?`;
                    if (isOutput) {
                        msg += '\n\nWARNING: This appears to be an output file. Deleting it may break existing Analysis Results that rely on it.';
                    }
                    
                    if (confirm(msg)) {
                        try {
                            await api.deleteFile(filename);
                            
                            // If the deleted file was the selected one, clear selection
                            const input = document.getElementById('engine-input-file');
                            if (input.value === filepath) {
                                input.value = '';
                                document.getElementById('pcap-custom-select-text').textContent = 'Select uploaded file...';
                                document.getElementById('pcap-custom-select-text').style.color = 'var(--text-muted)';
                            }
                            
                            await this.refreshFileList();
                            
                            // Close dropdown after successful deletion
                            dropdown.classList.remove('open');
                        } catch (err) {
                            console.error('Delete failed:', err);
                            this.showError('Unable to delete PCAP. ' + err.message);
                        }
                    }
                } else {
                    // Option selection
                    const input = document.getElementById('engine-input-file');
                    input.value = filepath;
                    
                    document.getElementById('pcap-custom-select-text').textContent = filename;
                    document.getElementById('pcap-custom-select-text').style.color = 'var(--text-primary)';
                    
                    // Update visual selection
                    dropdown.querySelectorAll('.custom-option').forEach(opt => opt.classList.remove('selected'));
                    option.classList.add('selected');
                    
                    dropdown.classList.remove('open');
                }
            });
        }
        
        // Upload handler
        document.getElementById('btn-upload').addEventListener('click', async () => {
            const input = document.getElementById('engine-upload-input');
            if (input.files.length === 0) {
                alert('Please select a PCAP file first.');
                return;
            }
            
            const btn = document.getElementById('btn-upload');
            try {
                btn.textContent = "Uploading...";
                btn.disabled = true;
                this.hideError();
                
                await api.uploadFile(input.files[0]);
                await this.refreshFileList();
                
                btn.textContent = "Upload";
                btn.disabled = false;
                input.value = '';
                
                // Show concise success message
                const alertBox = document.getElementById('engine-error-alert');
                const title = document.getElementById('engine-error-title');
                const text = document.getElementById('engine-error-text');
                const icon = alertBox.querySelector('i');
                
                alertBox.style.display = 'block';
                alertBox.style.backgroundColor = 'rgba(16, 185, 129, 0.1)';
                alertBox.style.border = '1px solid rgba(16, 185, 129, 0.3)';
                alertBox.style.borderLeft = '4px solid var(--status-success)';
                
                if (icon) {
                    icon.className = 'fa-solid fa-circle-check';
                    icon.style.color = 'var(--status-success)';
                }
                
                if (title) {
                    title.textContent = 'Success';
                    title.style.color = 'var(--status-success)';
                }
                
                text.textContent = 'PCAP uploaded successfully';
                
                setTimeout(() => {
                    this.hideError();
                    // Reset styling to default error
                    alertBox.style.backgroundColor = '';
                    alertBox.style.border = '';
                    alertBox.style.borderLeft = '';
                    if (icon) {
                        icon.className = 'fa-solid fa-circle-exclamation';
                        icon.style.color = 'var(--status-error)';
                    }
                    if (title) {
                        title.textContent = 'Engine Failed';
                        title.style.color = 'var(--status-error)';
                    }
                }, 4000);
            } catch (e) {
                btn.textContent = "Upload";
                btn.disabled = false;
                
                // Ensure default error styling is restored before showing error
                const alertBox = document.getElementById('engine-error-alert');
                const title = document.getElementById('engine-error-title');
                const icon = alertBox.querySelector('i');
                
                alertBox.style.backgroundColor = '';
                alertBox.style.border = '';
                alertBox.style.borderLeft = '';
                if (icon) {
                    icon.className = 'fa-solid fa-circle-exclamation';
                    icon.style.color = 'var(--status-error)';
                }
                if (title) {
                    title.textContent = 'Upload Failed';
                    title.style.color = 'var(--status-error)';
                }
                
                this.showError('Upload failed: ' + e.message);
            }
        });
        
        // Reset handler
        document.getElementById('btn-reset').addEventListener('click', () => {
            const inputFile = document.getElementById('engine-input-file');
            const outputFile = document.getElementById('engine-output-file');
            const pcapText = document.getElementById('pcap-custom-select-text');
            const dropdown = document.getElementById('pcap-custom-select-dropdown');
            
            inputFile.value = '';
            outputFile.value = 'output.pcap';
            
            if (pcapText) {
                pcapText.textContent = 'Select uploaded file...';
                pcapText.style.color = 'var(--text-muted)';
            }
            
            if (dropdown) {
                dropdown.querySelectorAll('.custom-option').forEach(opt => opt.classList.remove('selected'));
            }
            
            lbsInput.value = '2';
            fpsInput.value = '2';
            updateThreads();
            
            this.hideError();
            document.getElementById('engine-mini-console').innerHTML = '<div class="term-line term-info">Waiting for engine to start...</div>';
            document.getElementById('engine-progress-badge').style.display = 'none';
        });
        
        // Start handler
        document.getElementById('btn-start').addEventListener('click', async () => {
            const btnStart = document.getElementById('btn-start');
            
            // Prevent double-click
            if (btnStart.disabled) return;
            
            const inputFile = document.getElementById('engine-input-file').value;
            const outputFile = document.getElementById('engine-output-file').value.trim();
            const lbs = parseInt(lbsInput.value);
            const fps = parseInt(fpsInput.value);
            
            // Validation
            if (!inputFile) {
                alert("Please select an input PCAP file");
                return;
            }
            if (!outputFile) {
                alert("Please specify an output filename");
                return;
            }
            if (isNaN(lbs) || lbs < 1) {
                alert("Load Balancer Threads must be at least 1");
                return;
            }
            if (isNaN(fps) || fps < 1) {
                alert("Fast Path Threads per LB must be at least 1");
                return;
            }
            
            const config = { numLbs: lbs, fpsPerLb: fps };
            
            // Disable start immediately to prevent duplicates
            btnStart.disabled = true;
            this.hideError();
            document.getElementById('engine-progress-badge').style.display = 'inline-block';
            document.getElementById('engine-progress-badge').textContent = 'Starting...';
            document.getElementById('engine-mini-console').innerHTML = '';
            
            try {
                await api.startEngine(inputFile, outputFile, config);
                this.state.refreshStatus();
            } catch (e) {
                btnStart.disabled = false;
                document.getElementById('engine-progress-badge').style.display = 'none';
                this.showError(e.message);
            }
        });
        
        // Stop handler
        document.getElementById('btn-stop').addEventListener('click', async () => {
            const btnStop = document.getElementById('btn-stop');
            btnStop.disabled = true;
            try {
                await api.stopEngine();
                this.state.refreshStatus();
            } catch (e) {
                this.showError('Stop failed: ' + e.message);
            }
        });
        
        // SSE output handler
        this.state.on('output', (text, isError) => {
            const term = document.getElementById('engine-mini-console');
            const lines = text.split('\n').filter(l => l.trim());
            lines.forEach(line => {
                const div = document.createElement('div');
                div.className = 'term-line ' + (isError ? 'term-error' : '');
                div.textContent = line;
                term.appendChild(div);
                
                // Extract progress from engine logs
                if (line.includes('Processing packets')) {
                    document.getElementById('engine-progress-badge').textContent = 'Processing packets...';
                } else if (line.includes('Done reading')) {
                    document.getElementById('engine-progress-badge').textContent = 'Finalizing...';
                }
            });
            term.scrollTop = term.scrollHeight;
        });
        
        // SSE output-history handler (for reconnects)
        this.state.on('output-history', (text) => {
            const term = document.getElementById('engine-mini-console');
            term.innerHTML = '';
            const lines = text.split('\n').filter(l => l.trim());
            lines.forEach(line => {
                const div = document.createElement('div');
                div.className = 'term-line';
                div.textContent = line;
                term.appendChild(div);
            });
            term.scrollTop = term.scrollHeight;
        });
        
        // Rules count handler
        this.state.on('rules', (rules) => {
            if(rules) {
                const count = rules.blockedIPs.length + rules.blockedApps.length + rules.blockedDomains.length;
                document.getElementById('engine-rules-count').textContent = count + " Rules Active";
            }
        });
        
        // Error handler from SSE
        this.state.on('error', (errMsg) => {
            this.showError(errMsg);
            document.getElementById('engine-progress-badge').style.display = 'none';
        });
    }
    
    showError(msg) {
        const alert = document.getElementById('engine-error-alert');
        const text = document.getElementById('engine-error-text');
        alert.style.display = 'block';
        text.textContent = msg;
    }
    
    hideError() {
        document.getElementById('engine-error-alert').style.display = 'none';
    }
    
    async refreshFileList() {
        try {
            const files = await api.getFilesList();
            const input = document.getElementById('engine-input-file');
            const dropdown = document.getElementById('pcap-custom-select-dropdown');
            const textElement = document.getElementById('pcap-custom-select-text');
            
            // Remember current selection
            const currentSelection = input.value;
            
            dropdown.innerHTML = '';
            
            if (files.length === 0) {
                const div = document.createElement('div');
                div.className = 'custom-option';
                div.style.color = 'var(--text-muted)';
                div.style.cursor = 'not-allowed';
                div.textContent = "No uploaded PCAP files available";
                dropdown.appendChild(div);
                
                input.value = '';
                textElement.textContent = 'Select uploaded file...';
                textElement.style.color = 'var(--text-muted)';
                return;
            }

            let selectionStillExists = false;
            let selectionFilename = '';

            files.forEach(f => {
                const opt = document.createElement('div');
                opt.className = 'custom-option';
                if (currentSelection === f.path) {
                    opt.classList.add('selected');
                    selectionStillExists = true;
                    selectionFilename = f.filename;
                }
                opt.dataset.value = f.path; // Absolute path
                opt.dataset.filename = f.filename;
                
                const sizeMb = (f.size / (1024 * 1024)).toFixed(2);
                
                let badgeHtml = '';
                if (f.filename.includes('output')) {
                    badgeHtml = `<span class="badge badge-output" style="font-size: 0.6rem; padding: 2px 6px; margin-right: 6px;">OUTPUT</span>`;
                } else {
                    badgeHtml = `<span class="badge badge-input" style="font-size: 0.6rem; padding: 2px 6px; margin-right: 6px;">INPUT</span>`;
                }
                
                opt.innerHTML = `
                    <div class="custom-option-text" title="${f.filename}">
                        ${badgeHtml} ${f.filename} <span style="color: var(--text-muted); font-size: 0.8rem; margin-left: 8px;">${sizeMb} MB</span>
                    </div>
                    <i class="fa-solid fa-trash delete-icon" title="Delete PCAP"></i>
                `;
                dropdown.appendChild(opt);
            });
            
            // Try to restore the previous selection if it still exists
            if (selectionStillExists) {
                input.value = currentSelection;
                textElement.textContent = selectionFilename;
                textElement.style.color = 'var(--text-primary)';
            } else {
                input.value = '';
                textElement.textContent = 'Select uploaded file...';
                textElement.style.color = 'var(--text-muted)';
            }
        } catch (e) {
            console.error('Failed to refresh file list', e);
        }
    }
    
    updateUI(status) {
        const btnStart = document.getElementById('btn-start');
        const btnStop = document.getElementById('btn-stop');
        const inputs = [
            document.getElementById('engine-input-file'),
            document.getElementById('engine-output-file'),
            document.getElementById('engine-cfg-lbs'),
            document.getElementById('engine-cfg-fps')
        ];
        
        if (status.state === 'processing') {
            btnStart.disabled = true;
            btnStop.disabled = false;
            inputs.forEach(i => i.disabled = true);
            this.hideError();
            document.getElementById('engine-progress-badge').style.display = 'inline-block';
        } else {
            // Check diagnostic first
            if (status.engineDiagnostic && !status.engineDiagnostic.exists) {
                btnStart.disabled = true;
                btnStop.disabled = true;
                inputs.forEach(i => i.disabled = false); // keep inputs editable
                
                const title = document.getElementById('engine-error-title');
                if (title) title.textContent = "C++ Engine Unavailable";
                
                let diagnosticMsg = "Engine executable not found.\n\n";
                diagnosticMsg += "Expected Path: " + (status.engineDiagnostic.path || "Unknown") + "\n";
                diagnosticMsg += "Please compile the engine using CMake or the provided build scripts.";
                
                this.showError(diagnosticMsg);
            } else {
                btnStart.disabled = false;
                btnStop.disabled = true;
                inputs.forEach(i => i.disabled = false);
                this.hideError(); // clear diagnostic error if it exists
                
                const title = document.getElementById('engine-error-title');
                if (title) title.textContent = "Engine Failed";
                
                if (status.state === 'error' && status.errorMessage) {
                    this.showError(status.errorMessage);
                }
            }
            document.getElementById('engine-progress-badge').style.display = 'none';
        }
    }
}
