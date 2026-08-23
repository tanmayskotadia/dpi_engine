/**
 * engine-manager.js
 * Manages the lifecycle of the C++ DPI engine process.
 * Uses central config for all paths and settings.
 */

const { spawn }           = require('child_process');
const path                = require('path');
const fs                  = require('fs');
const { parseEngineOutput } = require('./output-parser');
const rulesManager        = require('./rules-manager');
const config              = require('./config');

class EngineManager {
    constructor() {
        this.process      = null;
        this.state        = 'idle'; // 'idle' | 'processing' | 'complete' | 'error'
        this.currentFile  = null;
        this.outputFile   = null;
        this.startTime    = null;
        this.errorMessage = null;
        this.engineConfig = { numLbs: config.ENGINE_DEFAULT_LBS, fpsPerLb: config.ENGINE_DEFAULT_FPS };
        this.latestResults= null;
        this.rawOutput    = [];
        this.listeners    = [];
    }

    // ── Engine diagnostics ──────────────────────────────────────────────────

    getEngineDiagnostic() {
        const enginePath = config.ENGINE_PATH;
        let exists       = false;
        let isExecutable = false;

        if (enginePath && fs.existsSync(enginePath)) {
            exists = true;
            try {
                fs.accessSync(enginePath, fs.constants.X_OK);
                isExecutable = true;
            } catch (_) {
                isExecutable = false;
            }
        }

        return { exists, isExecutable };
        // NOTE: We intentionally do NOT send the full filesystem path to the
        // browser. Diagnostics are logged server-side. The frontend only needs
        // to know exists/isExecutable to show appropriate UI.
    }

    // ── File lock check ─────────────────────────────────────────────────────
    
    isProcessingFile(absolutePath) {
        if (this.state !== 'processing') return false;
        if (!absolutePath) return false;
        
        const normTarget = path.normalize(absolutePath);
        
        if (this.currentFile && path.normalize(this.currentFile) === normTarget) return true;
        if (this.outputFile && path.normalize(this.outputFile) === normTarget) return true;
        
        return false;
    }

    // ── Start the C++ engine ────────────────────────────────────────────────

    start(inputFile, outputFile, engineConfig) {
        if (this.state === 'processing') {
            throw new Error('Engine is already processing');
        }

        // ── Security: ensure inputFile is inside the uploads directory ──────
        const resolvedInput = path.resolve(inputFile);
        const storageDir    = path.resolve(config.PCAP_STORAGE_PATH);
        if (!resolvedInput.startsWith(storageDir + path.sep) && !resolvedInput.startsWith(storageDir)) {
            throw new Error('Invalid input file: must be a previously uploaded PCAP file');
        }
        if (!fs.existsSync(resolvedInput)) {
            throw new Error(`Input PCAP file no longer exists. Please select or upload another PCAP.`);
        }

        // ── Security: generate a safe output path server-side ───────────────
        // The client provides a suggested filename; we sanitize and place it
        // in the outputs directory only. The client cannot write outside it.
        const safeName     = path.basename(outputFile).replace(/[^a-zA-Z0-9._-]/g, '_');
        const finalOutput  = path.join(config.PCAP_OUTPUT_PATH, `${Date.now()}_${safeName}`);

        // ── Validate and clamp thread counts ────────────────────────────────
        const numLbs   = Math.max(1, Math.min(parseInt(engineConfig?.numLbs)   || config.ENGINE_DEFAULT_LBS,   config.ENGINE_MAX_LBS));
        const fpsPerLb = Math.max(1, Math.min(parseInt(engineConfig?.fpsPerLb) || config.ENGINE_DEFAULT_FPS, config.ENGINE_MAX_FPS_PER_LB));

        this.state        = 'processing';
        this.currentFile  = resolvedInput;
        this.outputFile   = finalOutput;
        this.errorMessage = null;
        this.engineConfig = { numLbs, fpsPerLb };
        this.startTime    = new Date().toISOString();
        this.rawOutput    = [];
        this.latestResults= null;

        // ── Check engine executable ─────────────────────────────────────────
        const enginePath = config.ENGINE_PATH;
        console.log(`[Engine] Executable : ${enginePath}`);
        console.log(`[Engine] Exists     : ${fs.existsSync(enginePath)}`);

        if (!fs.existsSync(enginePath)) {
            this.handleError(new Error(
                'Engine executable not found. Run "npm run build:engine" to compile the C++ DPI engine.'
            ));
            return;
        }

        // ── Build argument array (safe — never shell-expanded) ──────────────
        const rules = rulesManager.getRules();
        const args  = [resolvedInput, finalOutput];

        rules.blockedIPs.forEach(ip       => args.push('--block-ip',     ip));
        rules.blockedApps.forEach(app     => args.push('--block-app',    app));
        rules.blockedDomains.forEach(dom  => args.push('--block-domain', dom));
        args.push('--lbs', numLbs.toString());
        args.push('--fps', fpsPerLb.toString());

        console.log(`[Engine] Launching  : ${path.basename(enginePath)} ${args.join(' ')}`);
        this.broadcast({ type: 'status', data: this.getStatus() });

        // ── Spawn ───────────────────────────────────────────────────────────
        try {
            this.process = spawn(enginePath, args);

            this.process.stdout.on('data', data => {
                const text = data.toString();
                this.rawOutput.push(text);
                this.broadcast({ type: 'output', data: text });
            });

            this.process.stderr.on('data', data => {
                const text = data.toString();
                this.rawOutput.push(text);
                this.broadcast({ type: 'error-output', data: text });
            });

            this.process.on('close', code => {
                if (code === 0) {
                    this.handleComplete();
                } else {
                    const output = this.rawOutput.join('').trim();
                    const msg = output
                        ? `Engine exited with code ${code}.\n${output}`
                        : `Engine exited with code ${code}`;
                    this.handleError(new Error(msg));
                }
                this.process = null;
            });

            this.process.on('error', err => {
                this.handleError(new Error(`Failed to launch engine: ${err.message}`));
                this.process = null;
            });

        } catch (err) {
            this.handleError(err);
        }
    }

    // ── Stop ────────────────────────────────────────────────────────────────

    stop() {
        if (this.state === 'processing' && this.process) {
            if (process.platform === 'win32') {
                spawn('taskkill', ['/pid', this.process.pid.toString(), '/f', '/t']);
            } else {
                this.process.kill('SIGINT');
            }
            this.state        = 'idle';
            this.errorMessage = null;
            this.broadcast({ type: 'status', data: this.getStatus() });
        }
    }

    // ── Completion & error handlers ─────────────────────────────────────────

    handleComplete() {
        this.state        = 'complete';
        this.errorMessage = null;

        const fullOutput      = this.rawOutput.join('');
        this.latestResults    = parseEngineOutput(fullOutput);

        if (this.latestResults) {
            this.latestResults.id         = `run_${Date.now()}`;
            this.latestResults.timestamp  = this.startTime;
            this.latestResults.inputFile  = path.basename(this.currentFile);
            this.latestResults.outputFile = path.basename(this.outputFile);
            this.saveResultsToHistory(this.latestResults);
        }

        this.broadcast({ type: 'status',  data: this.getStatus() });
        this.broadcast({ type: 'results', data: this.latestResults });
    }

    handleError(err) {
        this.state        = 'error';
        this.errorMessage = err.message;
        console.error('[Engine] Error:', err.message);
        this.broadcast({ type: 'status', data: this.getStatus() });
        this.broadcast({ type: 'error',  data: err.message });
    }

    // ── Status ──────────────────────────────────────────────────────────────

    getStatus() {
        return {
            state:            this.state,
            currentFile:      this.currentFile  ? path.basename(this.currentFile)  : null,
            outputFile:       this.outputFile   ? path.basename(this.outputFile)   : null,
            startTime:        this.startTime,
            config:           this.engineConfig,
            errorMessage:     this.errorMessage,
            engineDiagnostic: this.getEngineDiagnostic(),
        };
    }

    // ── SSE listener management ─────────────────────────────────────────────

    addListener(res) {
        this.listeners.push(res);
        res.write(`data: ${JSON.stringify({ type: 'status', data: this.getStatus() })}\n\n`);
        if (this.rawOutput.length > 0) {
            res.write(`data: ${JSON.stringify({ type: 'output-history', data: this.rawOutput.join('') })}\n\n`);
        }
    }

    removeListener(res) {
        this.listeners = this.listeners.filter(l => l !== res);
    }

    broadcast(message) {
        const payload = `data: ${JSON.stringify(message)}\n\n`;
        this.listeners.forEach(res => {
            try { res.write(payload); } catch (_) { /* broken pipe */ }
        });
    }

    // ── History ─────────────────────────────────────────────────────────────

    saveResultsToHistory(results) {
        let history = [];
        if (fs.existsSync(config.HISTORY_PATH)) {
            try { history = JSON.parse(fs.readFileSync(config.HISTORY_PATH, 'utf8')); }
            catch (e) { console.error('Failed to read history:', e); }
        }
        history.push(results);
        if (history.length > 20) history = history.slice(-20);
        fs.writeFileSync(config.HISTORY_PATH, JSON.stringify(history, null, 2));
    }

    getHistory() {
        if (fs.existsSync(config.HISTORY_PATH)) {
            try { return JSON.parse(fs.readFileSync(config.HISTORY_PATH, 'utf8')); }
            catch (_) { return []; }
        }
        return [];
    }
}

const engineManager = new EngineManager();
module.exports = engineManager;
