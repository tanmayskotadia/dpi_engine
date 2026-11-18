const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const config = require('./config');

const ACTIVE_STATES = new Set(['starting', 'capturing', 'stopping']);
const MAX_CAPTURE_BYTES = 100 * 1024 * 1024;

class CaptureError extends Error {
    constructor(message, statusCode = 400) { super(message); this.statusCode = statusCode; }
}

function resolveDumpcap(platform = process.platform) {
    if (process.env.DUMPCAP_PATH) return process.env.DUMPCAP_PATH;
    return platform === 'win32' ? path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Wireshark', 'dumpcap.exe') : 'dumpcap';
}

function parseInterfaces(output, platform, localNames) {
    const interfaces = [];
    for (const line of String(output).split(/\r?\n/)) {
        const match = line.trim().match(/^(\d+)\.\s+(\S+)(?:\s+\((.*)\))?$/);
        if (!match) continue;
        const [, id, name, description] = match;
        // Only actual local devices discovered by dumpcap are eligible. Pipes,
        // rpcap/TCP URLs, extcap commands and arbitrary device strings are not.
        const local = platform === 'win32'
            ? /^\\Device\\NPF_(?:\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}|Loopback)$/i.test(name)
            : name === 'any' || localNames.has(name);
        if (!local || /[\x00-\x1f]/.test(name)) continue;
        interfaces.push({ id, name, label: description ? `${description} (${name})` : name });
    }
    return interfaces;
}

// Walk block headers/trailers without loading packet payloads. A forcibly
// stopped Windows process may leave one unfinished final block; only that tail
// is recoverable, and only after an explicitly requested stop.
function inspectCapture(filename, recoverTail, maximumBytes) {
    const stat = fs.lstatSync(filename);
    if (!stat.isFile() || stat.size < 28 || stat.size > maximumBytes) throw new CaptureError('Capture output is empty, invalid, or exceeds the size limit.', 500);
    const descriptor = fs.openSync(filename, recoverTail ? 'r+' : 'r');
    let position = 0, little = true, sectionSeen = false, interfaceSeen = false, packets = 0, recovered = false;
    try {
        const header = Buffer.alloc(12);
        const trailer = Buffer.alloc(4);
        while (position < stat.size) {
            const remaining = stat.size - position;
            if (remaining < 12) {
                if (!recoverTail) throw new CaptureError('Capture ended with a truncated block.', 500);
                recovered = true; break;
            }
            if (fs.readSync(descriptor, header, 0, 12, position) !== 12) throw new CaptureError('Could not read capture output.', 500);
            const section = header.readUInt32LE(0) === 0x0a0d0d0a;
            if (section) {
                if (header.readUInt32LE(8) === 0x1a2b3c4d) little = true;
                else if (header.readUInt32BE(8) === 0x1a2b3c4d) little = false;
                else throw new CaptureError('Capture has an invalid section header.', 500);
            } else if (!sectionSeen) throw new CaptureError('Capture is not a PCAPNG file.', 500);
            const read32 = (buffer, offset) => little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
            const length = read32(header, 4);
            const type = read32(header, 0);
            if (length < (section ? 28 : 12) || length % 4 || length > 32 * 1024 * 1024) throw new CaptureError('Capture contains an invalid block length.', 500);
            if (length > remaining) {
                if (!recoverTail) throw new CaptureError('Capture ended with a truncated block.', 500);
                recovered = true; break;
            }
            if (fs.readSync(descriptor, trailer, 0, 4, position + length - 4) !== 4 || read32(trailer, 0) !== length) throw new CaptureError('Capture block length does not match its trailer.', 500);
            if (section) { sectionSeen = true; interfaceSeen = false; }
            else if (type === 1) interfaceSeen = true;
            else if ([2, 3, 6].includes(type)) {
                if (!interfaceSeen) throw new CaptureError('Capture packet has no interface description.', 500);
                packets++;
            }
            position += length;
        }
        if (!sectionSeen || !interfaceSeen) throw new CaptureError('Capture has no usable interface data.', 500);
        if (recovered) fs.ftruncateSync(descriptor, position);
        return { size: position, packetCount: packets, recoveredTail: recovered };
    } finally { fs.closeSync(descriptor); }
}

class CaptureManager {
    constructor(options = {}) {
        this.platform = options.platform || process.platform;
        this.executable = options.executable || resolveDumpcap(this.platform);
        this.storagePath = path.resolve(options.storagePath || config.PCAP_STORAGE_PATH);
        this.spawn = options.spawn || childProcess.spawn;
        this.execFile = options.execFile || childProcess.execFile;
        this.networkInterfaces = options.networkInterfaces || os.networkInterfaces;
        this.maximumBytes = Math.min(options.maximumBytes || MAX_CAPTURE_BYTES, config.PCAP_MAX_FILE_SIZE_BYTES || MAX_CAPTURE_BYTES, MAX_CAPTURE_BYTES);
        this.status = { state: 'idle', result: null, error: null };
        this.active = null;
    }

    getStatus() { return structuredClone({ ...this.status, maximumBytes: this.maximumBytes }); }

    async listInterfaces() {
        try {
            const output = await new Promise((resolve, reject) => {
                this.execFile(this.executable, ['-D'], { windowsHide: true, timeout: 8000, maxBuffer: 256 * 1024, encoding: 'utf8' }, (error, stdout, stderr) => {
                    if (error) {
                        if (error.code === 'ENOENT') reject(new Error('Wireshark dumpcap is not available. Install Wireshark with its capture driver, or configure DUMPCAP_PATH on the server.'));
                        else reject(new Error(String(stderr || error.message).trim().slice(0, 800) || 'Unable to list network interfaces. Check the capture driver and capture permissions.'));
                    } else resolve(stdout);
                });
            });
            const interfaces = parseInterfaces(output, this.platform, new Set(Object.keys(this.networkInterfaces())));
            return { available: true, interfaces, maximumBytes: this.maximumBytes, error: interfaces.length ? null : 'No local capture interfaces are available. Check the capture driver and permissions.' };
        } catch (error) {
            return { available: false, interfaces: [], maximumBytes: this.maximumBytes, error: error.message };
        }
    }

    validateOptions(options) {
        if (!options || typeof options !== 'object' || Array.isArray(options)) throw new CaptureError('Capture settings are required.');
        if (typeof options.interfaceId !== 'string' || !/^\d{1,6}$/.test(options.interfaceId)) throw new CaptureError('Select a listed local network interface.');
        const duration = options.duration ?? 30;
        const packetLimit = options.packetLimit ?? 10000;
        if (!Number.isInteger(duration) || duration < 1 || duration > 300) throw new CaptureError('Capture duration must be a whole number between 1 and 300 seconds.');
        if (!Number.isInteger(packetLimit) || packetLimit < 1 || packetLimit > 1000000) throw new CaptureError('Packet limit must be a whole number between 1 and 1,000,000.');
        const filter = options.filter ?? '';
        if (typeof filter !== 'string' || filter.length > 512 || /[\x00-\x1f\x7f]/.test(filter)) throw new CaptureError('Capture filter must be at most 512 characters and cannot contain control characters.');
        if (options.interfaceName !== undefined && (typeof options.interfaceName !== 'string' || options.interfaceName.length > 256 || /[\x00-\x1f\x7f]/.test(options.interfaceName))) throw new CaptureError('Invalid capture interface name.');
        return { interfaceId: options.interfaceId, interfaceName: options.interfaceName, duration, packetLimit, filter: filter.trim() };
    }

    async start(options) {
        if (ACTIVE_STATES.has(this.status.state)) throw new CaptureError('A capture is already in progress.', 409);
        const settings = this.validateOptions(options);
        this.status = { state: 'starting', result: null, error: null, settings };
        try {
            const discovery = await this.listInterfaces();
            if (!discovery.available) throw new CaptureError(discovery.error, 503);
            const network = discovery.interfaces.find(item => item.id === settings.interfaceId);
            if (!network) throw new CaptureError('The selected local interface is no longer available. Refresh the interface list.');
            if (settings.interfaceName && settings.interfaceName !== network.name) throw new CaptureError('The interface list changed. Refresh it and select the intended interface again.', 409);
            fs.mkdirSync(this.storagePath, { recursive: true });
            const id = crypto.randomUUID();
            const filename = `live-${Date.now()}-${id}.pcapng`;
            const outputPath = path.join(this.storagePath, filename);
            const temporaryPath = `${outputPath}.partial`;
            const args = ['-i', network.name, '-F', 'pcapng', '-q', '-s', '0', '-a', `duration:${settings.duration}`, '-a', `filesize:${Math.max(1, Math.floor(this.maximumBytes / 1024) - 512)}`, '-c', String(settings.packetLimit), '-w', temporaryPath];
            if (settings.filter) args.push('-f', settings.filter);
            const child = this.spawn(this.executable, args, { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'], shell: false });
            const run = { id, filename, outputPath, temporaryPath, child, stderr: '', stopRequested: false, finished: false, settings, network };
            this.active = run;
            this.status = { state: 'starting', id, settings, interface: network, startedAt: new Date().toISOString(), result: null, error: null };
            child.stderr?.on('data', chunk => { run.stderr = (run.stderr + chunk.toString()).slice(-4096); });
            child.once('close', (code, signal) => this.finish(run, code, signal));
            child.once('error', error => this.failRun(run, error.code === 'ENOENT' ? 'Wireshark dumpcap is not available.' : `Could not start capture: ${error.message}`));
            await new Promise((resolve, reject) => {
                child.once('spawn', () => {
                    if (!run.finished) {
                        this.status.state = run.stopRequested ? 'stopping' : 'capturing';
                        run.deadline = setTimeout(() => this.requestStop(run, 'time limit'), (settings.duration + 5) * 1000);
                        run.deadline.unref?.();
                    }
                    resolve();
                });
                child.once('error', reject);
            });
            return this.getStatus();
        } catch (error) {
            if (this.status.state !== 'error') this.status = { ...this.status, state: 'error', error: error.message, result: null };
            throw error instanceof CaptureError ? error : new CaptureError(error.message, 500);
        }
    }

    stop() {
        if (this.status.state === 'starting' && !this.active) throw new CaptureError('Capture is still starting. Try stopping it again in a moment.', 409);
        if (this.active && !this.active.finished) this.requestStop(this.active, 'user');
        return this.getStatus();
    }

    requestStop(run, reason) {
        if (run.finished || run.stopRequested) return;
        run.stopRequested = true;
        run.stopReason = reason;
        this.status.state = 'stopping';
        try { run.child.kill('SIGINT'); } catch { /* Escalation below also handles a failed graceful stop. */ }
        run.killTimer = setTimeout(() => {
            if (run.finished) return;
            try { run.child.kill('SIGKILL'); } catch { /* close/error owns final state. */ }
        }, 3000);
        run.killTimer.unref?.();
    }

    clearTimers(run) { clearTimeout(run.deadline); clearTimeout(run.killTimer); }

    removeTemporary(run) {
        if (path.dirname(run.temporaryPath) === this.storagePath && path.basename(run.temporaryPath) === `${run.filename}.partial`) {
            try { fs.unlinkSync(run.temporaryPath); } catch (error) { if (error.code !== 'ENOENT') return false; }
        }
        return true;
    }

    failRun(run, message) {
        if (run.finished) return;
        run.finished = true;
        this.clearTimers(run);
        this.removeTemporary(run);
        if (this.active === run) {
            this.active = null;
            this.status = { ...this.status, state: 'error', error: message, result: null, finishedAt: new Date().toISOString() };
        }
    }

    finish(run, code, signal) {
        if (run.finished) return;
        if (code !== 0 && !run.stopRequested) {
            this.failRun(run, run.stderr.trim().slice(-800) || `Capture process exited unexpectedly (${signal || code}). Check capture permissions and the interface.`);
            return;
        }
        try {
            const details = inspectCapture(run.temporaryPath, run.stopRequested, this.maximumBytes);
            fs.renameSync(run.temporaryPath, run.outputPath);
            run.finished = true;
            this.clearTimers(run);
            this.active = null;
            this.status = { ...this.status, state: 'complete', error: null, finishedAt: new Date().toISOString(), result: { id: run.id, filename: run.filename, path: run.outputPath, ...details, stopped: run.stopRequested, stopReason: run.stopReason || 'capture limit' } };
        } catch (error) { this.failRun(run, error.code === 'ENOENT' ? 'Capture did not produce a file. Check capture permissions and try again.' : error.message); }
    }

    dispose() {
        const run = this.active;
        if (!run) return;
        this.clearTimers(run);
        run.finished = true;
        try { run.child.kill('SIGKILL'); } catch { /* Best effort during shutdown. */ }
        this.removeTemporary(run);
        this.active = null;
    }
}

const manager = new CaptureManager();
module.exports = manager;
module.exports.CaptureManager = CaptureManager;
module.exports.CaptureError = CaptureError;
module.exports.parseInterfaces = parseInterfaces;
module.exports.inspectCapture = inspectCapture;
