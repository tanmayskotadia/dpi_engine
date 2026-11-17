import { api } from '../api.js';
import { icon, escapeHtml, formatBytes } from '../ui.js';

const captureName = (filename = '') => filename.replace(/^\d{13}-/, '');

export class EngineControl {
    constructor(state) {
        this.state = state;
        this.container = document.getElementById('view-engine');
        this.files = [];
        this.starting = false;
        this.stopping = false;
        this.uploading = false;
        this.deleting = false;
        this.loadingFiles = false;
        this.filesLoaded = false;
        this.render();
        this.bindEvents();
        this.state.on('status', () => this.updateUI());
        this.state.on('connection', () => {
            this.updateUI();
            if (this.state.connection?.state === 'connected' && !this.filesLoaded && !this.loadingFiles) {
                this.refreshFileList();
            }
        });
        this.state.on('rules', rules => this.updateRules(rules));
        this.state.on('output', (text, isError) => this.appendOutput(text, isError));
        this.state.on('output-history', text => {
            this.element('engine-mini-console').replaceChildren();
            this.appendOutput(text);
        });
        this.state.on('error', message => {
            if (this.state.status.state !== 'error') this.showError(String(message).split('\n')[0], 'Analysis error');
        });
        this.updateRules(this.state.rules);
        this.updateUI();
        this.refreshFileList();
    }

    element(id) {
        return document.getElementById(id);
    }

    get processing() {
        return this.starting || this.state.status.state === 'processing';
    }

    get offline() {
        return this.state.connection && this.state.connection.state !== 'connected';
    }

    render() {
        this.container.innerHTML = `
            <div class="page-heading">
                <div><p class="eyebrow">ANALYSIS WORKSPACE</p><h1 tabindex="-1">New analysis</h1>
                <p>Choose a capture, review your rules, and inspect the traffic.</p></div>
                <a class="btn btn-secondary" href="#results">${icon('folder')} Previous results</a>
            </div>

            <form id="engine-analysis-form" novalidate>
                <div class="engine-layout">
                    <section class="card" aria-labelledby="capture-heading">
                        <div class="card-header">
                            <div><p class="step-label">01 / INPUT</p><h2 class="card-title" id="capture-heading">Packet capture</h2>
                            <p class="card-description">Upload a PCAP file or select a saved capture.</p></div>
                        </div>
                        <div class="card-body">
                            <div id="engine-upload-zone" class="upload-zone" aria-disabled="false">
                                <span class="upload-icon">${icon('upload', 24)}</span>
                                <p class="upload-title">Drop a capture file here</p>
                                <p class="upload-description">Classic .pcap format</p>
                                <button type="button" id="btn-upload" class="btn btn-secondary">${icon('plus')} Browse files</button>
                                <input type="file" id="engine-upload-input" accept=".pcap" hidden aria-label="Upload a PCAP capture">
                            </div>
                            <p id="engine-upload-feedback" class="help-text" role="status" aria-live="polite">Files upload automatically when selected.</p>

                            <div class="form-group">
                                <label class="form-label" for="engine-input-file">Saved captures</label>
                                <div class="capture-select-row">
                                    <select id="engine-input-file" class="form-control" aria-describedby="engine-file-meta" required>
                                        <option value="">Loading captures…</option>
                                    </select>
                                    <button type="button" id="btn-refresh-files" class="btn btn-secondary icon-btn" aria-label="Refresh saved captures" title="Refresh saved captures">${icon('refresh')}</button>
                                    <button type="button" id="btn-delete-file" class="btn btn-ghost icon-btn" aria-label="Delete selected capture" title="Delete selected capture" disabled>${icon('trash')}</button>
                                </div>
                                <p class="help-text file-meta" id="engine-file-meta">Select a capture to start an analysis.</p>
                            </div>
                        </div>
                    </section>

                    <section class="card engine-summary" aria-labelledby="configuration-heading">
                        <div class="card-header">
                            <div><p class="step-label">02 / CONFIGURATION</p><h2 class="card-title" id="configuration-heading">Analysis settings</h2>
                            <p class="card-description">Prepare the filtered capture and processing options.</p></div>
                        </div>
                        <div class="card-body">
                            <div class="form-group">
                                <label class="form-label" for="engine-output-file">Output filename</label>
                                <input id="engine-output-file" type="text" class="form-control" value="filtered.pcap" placeholder="filtered.pcap" autocomplete="off" spellcheck="false" required aria-describedby="engine-output-help">
                                <p class="help-text" id="engine-output-help">Download the filtered capture from the results page.</p>
                            </div>
                            <details class="advanced-settings" id="engine-advanced-settings">
                                <summary>${icon('settings')} Processing settings</summary>
                                <p class="help-text">The defaults suit most captures. Increase these values for larger workloads.</p>
                                <div class="form-row">
                                    <div class="form-group">
                                        <label class="form-label" for="engine-cfg-lbs">Load balancers</label>
                                        <input type="number" id="engine-cfg-lbs" class="form-control" value="2" min="1" max="16" step="1" required>
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label" for="engine-cfg-fps">Workers per balancer</label>
                                        <input type="number" id="engine-cfg-fps" class="form-control" value="2" min="1" max="16" step="1" required>
                                    </div>
                                </div>
                                <p class="thread-summary"><strong id="engine-total-threads">4</strong> processing workers</p>
                            </details>
                            <div class="section-heading">
                                <span class="form-label">Blocking rules</span>
                                <a id="engine-rules-link" href="#engine-rules-container" class="btn btn-ghost btn-sm">Manage ${icon('arrowRight', 14)}</a>
                            </div>
                            <p class="help-text" id="engine-rules-count">No blocking rules. All traffic is allowed.</p>
                        </div>
                    </section>
                </div>

                <div class="engine-form-footer">
                    <div id="engine-error-alert" class="notice notice-error" role="alert" hidden>
                        ${icon('alert')}<div><strong class="notice-title" id="engine-error-title">Unable to continue</strong><p class="notice-message" id="engine-error-text"></p></div>
                    </div>
                    <div class="engine-run-notice" id="engine-run-notice" role="status" aria-live="polite"></div>
                    <div class="run-actions">
                        <button type="submit" id="btn-start" class="btn btn-primary" aria-describedby="engine-run-notice">${icon('play')} Start analysis</button>
                        <button type="button" id="btn-stop" class="btn btn-danger" hidden>${icon('stop')} Stop analysis</button>
                        <button type="button" id="btn-reset" class="btn btn-ghost">Reset form</button>
                        <a href="#results" id="engine-results-link" class="btn btn-secondary" hidden>View results ${icon('arrowRight')}</a>
                    </div>
                </div>
            </form>

            <div id="engine-rules-container"></div>

            <section class="card" aria-labelledby="engine-console-heading">
                <div class="card-header">
                    <div><h2 class="card-title" id="engine-console-heading">Engine output</h2><p class="card-description">Recent activity from the analysis engine.</p></div>
                    <a class="btn btn-ghost btn-sm" href="#logs">Open console ${icon('arrowRight', 14)}</a>
                </div>
                <div class="terminal engine-console-preview" id="engine-mini-console" role="log" aria-label="Recent engine output" aria-live="off" tabindex="0">
                    <div class="term-line term-muted">Output will appear here when an analysis starts.</div>
                </div>
            </section>
        `;
    }

    bindEvents() {
        this.element('engine-analysis-form').addEventListener('submit', event => {
            event.preventDefault();
            this.startAnalysis();
        });
        this.element('btn-stop').addEventListener('click', () => this.stopAnalysis());
        this.element('btn-reset').addEventListener('click', () => this.resetForm());
        this.element('btn-refresh-files').addEventListener('click', () => this.refreshFileList());
        this.element('btn-delete-file').addEventListener('click', () => this.deleteSelectedFile());
        this.element('btn-upload').addEventListener('click', () => this.element('engine-upload-input').click());
        this.element('engine-upload-input').addEventListener('change', event => {
            const file = event.target.files[0];
            if (file) this.uploadFile(file);
            event.target.value = '';
        });
        this.element('engine-input-file').addEventListener('change', () => {
            this.hideError();
            this.updateFileMeta();
            this.updateUI();
        });
        ['engine-cfg-lbs', 'engine-cfg-fps'].forEach(id => {
            this.element(id).addEventListener('input', () => this.updateThreads());
        });
        this.element('engine-rules-link').addEventListener('click', event => {
            event.preventDefault();
            this.element('engine-rules-container').scrollIntoView({ behavior: 'auto', block: 'start' });
            const firstInput = this.element('engine-rules-container').querySelector('input, select, button');
            if (firstInput) firstInput.focus({ preventScroll: true });
        });

        const zone = this.element('engine-upload-zone');
        zone.addEventListener('dragover', event => {
            event.preventDefault();
            if (!this.processing && !this.uploading && !this.deleting && !this.loadingFiles && !this.offline) zone.classList.add('dragover');
        });
        zone.addEventListener('dragleave', event => {
            if (!zone.contains(event.relatedTarget)) zone.classList.remove('dragover');
        });
        zone.addEventListener('drop', event => {
            event.preventDefault();
            zone.classList.remove('dragover');
            if (this.processing || this.uploading || this.deleting || this.loadingFiles || this.offline) return;
            const files = event.dataTransfer.files;
            if (files.length !== 1) {
                this.showError('Upload one capture at a time.');
                return;
            }
            this.uploadFile(files[0]);
        });
    }

    updateThreads() {
        const lbs = Number(this.element('engine-cfg-lbs').value);
        const fps = Number(this.element('engine-cfg-fps').value);
        this.element('engine-total-threads').textContent = lbs > 0 && fps > 0 && Number.isInteger(lbs) && Number.isInteger(fps) ? (lbs * fps).toLocaleString() : '—';
    }

    updateRules(rules) {
        const count = (rules?.blockedIPs?.length || 0) + (rules?.blockedApps?.length || 0) + (rules?.blockedDomains?.length || 0);
        this.element('engine-rules-count').textContent = count
            ? `${count} blocking ${count === 1 ? 'rule' : 'rules'} will apply to the next analysis.`
            : 'No blocking rules. All traffic is allowed.';
    }

    async refreshFileList(selectedPath) {
        if (this.loadingFiles) return;
        this.hideError();
        this.loadingFiles = true;
        this.updateUI();
        try {
            const files = await api.getFilesList();
            this.files = files.filter(file => /\.pcap$/i.test(file.filename));
            const select = this.element('engine-input-file');
            const previous = selectedPath || select.value;
            select.replaceChildren(new Option(this.files.length ? 'Select a saved capture' : 'No captures yet — upload a file above', ''));
            for (const file of this.files) {
                select.add(new Option(`${captureName(file.filename)} · ${formatBytes(file.size)}`, file.path));
            }
            select.value = this.files.some(file => file.path === previous) ? previous : '';
            this.filesLoaded = true;
            this.updateFileMeta();
        } catch (error) {
            this.filesLoaded = false;
            if (!this.files.length) {
                this.element('engine-input-file').replaceChildren(new Option('Captures unavailable — refresh to retry', ''));
            }
            this.showError(`Could not load saved captures. ${error.message}`);
        } finally {
            this.loadingFiles = false;
            this.updateUI();
        }
    }

    updateFileMeta() {
        const selected = this.files.find(file => file.path === this.element('engine-input-file').value);
        this.element('engine-file-meta').textContent = selected
            ? `${captureName(selected.filename)} · ${formatBytes(selected.size)} · Ready to analyze`
            : 'Select a capture to start an analysis.';
    }

    async uploadFile(file) {
        if (this.processing || this.uploading || this.deleting || this.loadingFiles || this.offline) return;
        this.hideError();
        const feedback = this.element('engine-upload-feedback');
        if (!/\.pcap$/i.test(file.name)) {
            feedback.textContent = 'Choose a classic .pcap file. Export PCAPNG captures as PCAP before uploading.';
            this.showError(feedback.textContent);
            return;
        }
        if (file.size < 24) {
            feedback.textContent = 'This file is too small to contain a valid PCAP header. Choose another capture.';
            this.showError(feedback.textContent);
            return;
        }
        this.uploading = true;
        feedback.textContent = `Uploading ${file.name} (${formatBytes(file.size)})…`;
        this.updateUI();
        try {
            // The engine reads classic microsecond PCAP headers, not PCAPNG or nanosecond PCAP.
            const header = new DataView(await file.slice(0, 4).arrayBuffer()).getUint32(0, true);
            if (header !== 0xa1b2c3d4 && header !== 0xd4c3b2a1) {
                throw new Error('This capture format is not supported. Export it as classic PCAP with microsecond timestamps.');
            }
            const normalized = file.name.endsWith('.pcap') ? file : new File([file], file.name.replace(/\.pcap$/i, '.pcap'), { type: file.type });
            const uploaded = await api.uploadFile(normalized);
            await this.refreshFileList(uploaded.path);
            feedback.textContent = `${file.name} uploaded${this.filesLoaded ? ' and selected' : ''}.`;
        } catch (error) {
            feedback.textContent = error.message;
            this.showError(error.message, 'Upload failed');
        } finally {
            this.uploading = false;
            this.updateUI();
            if (this.filesLoaded) this.element('engine-input-file').focus();
        }
    }

    async deleteSelectedFile() {
        if (this.processing || this.uploading || this.deleting || this.offline) return;
        const selected = this.files.find(file => file.path === this.element('engine-input-file').value);
        if (!selected) return;
        if (!window.confirm(`Delete “${captureName(selected.filename)}” from saved captures? This cannot be undone.`)) return;
        this.deleting = true;
        this.hideError();
        this.updateUI();
        try {
            await api.deleteFile(selected.filename);
            this.element('engine-input-file').value = '';
            await this.refreshFileList();
            this.element('engine-upload-feedback').textContent = `${captureName(selected.filename)} deleted.`;
        } catch (error) {
            this.showError(error.message, 'Could not delete capture');
        } finally {
            this.deleting = false;
            this.updateUI();
            this.element('engine-input-file').focus();
        }
    }

    resetForm() {
        if (this.processing || this.uploading || this.deleting) return;
        this.element('engine-analysis-form').reset();
        this.element('engine-input-file').value = '';
        this.element('engine-upload-feedback').textContent = 'Files upload automatically when selected.';
        this.updateThreads();
        this.updateFileMeta();
        this.hideError();
        this.updateUI();
        this.element('engine-input-file').focus();
    }

    async startAnalysis() {
        if (this.processing || this.uploading || this.deleting || this.loadingFiles || this.offline) return;
        const diagnostic = this.state.status.engineDiagnostic;
        if (diagnostic && (!diagnostic.exists || diagnostic.isExecutable === false)) return;
        this.hideError();
        const input = this.element('engine-input-file');
        const output = this.element('engine-output-file');
        const lbs = this.element('engine-cfg-lbs');
        const fps = this.element('engine-cfg-fps');
        if (!input.value) {
            this.showError('Upload or select a capture before starting the analysis.');
            input.focus();
            return;
        }
        if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*\.pcap$/i.test(output.value.trim()) || output.value.includes('..')) {
            this.showError('Use a .pcap filename with letters, numbers, single dots, hyphens, or underscores, for example filtered.pcap.');
            output.focus();
            return;
        }
        if (!lbs.checkValidity() || !fps.checkValidity()) {
            this.element('engine-advanced-settings').open = true;
            this.showError('Choose a whole number between 1 and 16 for each processing setting.');
            (!lbs.checkValidity() ? lbs : fps).focus();
            return;
        }
        this.starting = true;
        this.element('engine-mini-console').replaceChildren();
        this.updateUI();
        try {
            await api.startEngine(input.value, output.value.trim(), { numLbs: Number(lbs.value), fpsPerLb: Number(fps.value) });
            await this.state.refreshStatus();
        } catch (error) {
            this.showError(error.message, 'Could not start analysis');
        } finally {
            this.starting = false;
            this.updateUI();
        }
    }

    async stopAnalysis() {
        if (!this.processing || this.stopping || this.offline) return;
        this.stopping = true;
        this.updateUI();
        try {
            await api.stopEngine();
            await this.state.refreshStatus();
        } catch (error) {
            this.showError(error.message, 'Could not stop analysis');
        } finally {
            this.stopping = false;
            this.updateUI();
        }
    }

    showError(message, title = 'Unable to continue') {
        this.element('engine-error-title').textContent = title;
        this.element('engine-error-text').textContent = String(message);
        this.element('engine-error-alert').hidden = false;
    }

    hideError() {
        this.element('engine-error-alert').hidden = true;
    }

    appendOutput(text, isError = false) {
        const terminal = this.element('engine-mini-console');
        const nearBottom = terminal.scrollHeight - terminal.clientHeight - terminal.scrollTop < 40;
        terminal.querySelector('.term-muted')?.remove();
        const fragment = document.createDocumentFragment();
        for (const line of String(text).split('\n').filter(line => line.trim()).slice(-300)) {
            const row = document.createElement('div');
            row.className = `term-line${isError ? ' term-error' : ''}`;
            row.textContent = line;
            fragment.appendChild(row);
        }
        terminal.appendChild(fragment);
        while (terminal.childElementCount > 300) terminal.firstElementChild.remove();
        if (nearBottom) terminal.scrollTop = terminal.scrollHeight;
    }

    updateUI() {
        const status = this.state.status;
        const running = this.processing;
        const busy = running || this.uploading || this.deleting;
        const unavailable = status.engineDiagnostic && (!status.engineDiagnostic.exists || status.engineDiagnostic.isExecutable === false);
        const selected = Boolean(this.element('engine-input-file').value);
        const start = this.element('btn-start');
        start.disabled = busy || this.offline || this.loadingFiles || !selected || unavailable;
        start.innerHTML = `${icon('play')} ${this.starting ? 'Starting…' : running ? 'Analysis running…' : 'Start analysis'}`;
        const stop = this.element('btn-stop');
        stop.hidden = !running;
        stop.disabled = this.starting || this.stopping || this.offline;
        stop.innerHTML = `${icon('stop')} ${this.stopping ? 'Stopping…' : 'Stop analysis'}`;
        this.element('btn-reset').disabled = busy;
        this.element('btn-upload').disabled = busy || this.offline || this.loadingFiles;
        this.element('btn-upload').innerHTML = `${icon('upload')} ${this.uploading ? 'Uploading…' : 'Browse files'}`;
        this.element('engine-upload-input').disabled = busy || this.offline || this.loadingFiles;
        this.element('engine-upload-zone').setAttribute('aria-disabled', String(Boolean(busy || this.offline || this.loadingFiles)));
        this.element('btn-delete-file').disabled = busy || this.offline || this.loadingFiles || !selected;
        this.element('btn-refresh-files').disabled = busy || this.offline || this.loadingFiles;
        this.element('engine-input-file').disabled = busy || this.loadingFiles;
        ['engine-output-file', 'engine-cfg-lbs', 'engine-cfg-fps'].forEach(id => { this.element(id).disabled = running; });
        this.element('engine-results-link').hidden = status.state !== 'complete' || running;

        const notice = this.element('engine-run-notice');
        notice.className = 'engine-run-notice';
        if (this.offline) {
            notice.classList.add('notice', 'notice-info');
            notice.innerHTML = `${icon('info')}<span>Waiting for the server connection. Analysis controls will be available when connected.</span>`;
        } else if (unavailable) {
            notice.classList.add('notice', 'notice-error');
            notice.innerHTML = `${icon('alert')}<div><strong class="notice-title">Analysis engine unavailable</strong><p class="notice-message">The server cannot run the analysis engine. Build it with <code>npm run build:engine</code>, then refresh this page.</p></div>`;
        } else if (running) {
            notice.classList.add('notice', 'notice-info');
            notice.innerHTML = `${icon('info')}<span>${this.starting ? 'Starting analysis…' : 'Analysis in progress. Capture and configuration are locked until this run finishes.'}</span>`;
        } else if (status.state === 'error') {
            notice.classList.add('notice', 'notice-error');
            notice.innerHTML = `${icon('alert')}<div><strong class="notice-title">Analysis could not finish</strong><p class="notice-message">${escapeHtml((status.errorMessage || 'Check the engine output below, then try again.').split('\n')[0])}</p><a href="#logs">View console details</a></div>`;
        } else if (status.state === 'complete') {
            notice.classList.add('notice', 'notice-success');
            notice.innerHTML = `${icon('check')}<span>Analysis complete. Your traffic report and filtered capture are ready.</span>`;
        } else {
            notice.textContent = selected ? 'Ready to analyze. Blocking rules below will apply to this run.' : 'Select a packet capture to enable analysis.';
        }
    }
}
