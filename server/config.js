/**
 * Central configuration module.
 * All environment-dependent values are read here.
 * Validated at startup so failures are immediately obvious.
 */

const path = require('path');
const fs   = require('fs');

// ── Project root (two levels up from server/config.js) ─────────────────────
const PROJECT_ROOT = path.resolve(__dirname, '..');

// ── Engine executable ───────────────────────────────────────────────────────
function resolveEnginePath() {
    const isWin  = process.platform === 'win32';
    const exeName = isWin ? 'packet_analyzer.exe' : 'packet_analyzer';

    const candidates = [
        process.env.DPI_ENGINE_PATH,                          // 1. Explicit override
        path.join(PROJECT_ROOT, 'build', 'Release', exeName), // 2. CMake Release
        path.join(PROJECT_ROOT, 'build', 'Debug',   exeName), // 3. CMake Debug
        path.join(PROJECT_ROOT, 'build',             exeName), // 4. CMake generic
        path.join(PROJECT_ROOT,                      exeName), // 5. Project root
    ];

    for (const p of candidates) {
        if (p && fs.existsSync(p)) return path.resolve(p);
    }

    // Return expected path even if missing — lets diagnostics report it clearly
    return path.join(PROJECT_ROOT, 'build', exeName);
}

// ── Storage directories ─────────────────────────────────────────────────────
const PCAP_STORAGE_PATH = process.env.PCAP_STORAGE_PATH
    ? path.resolve(process.env.PCAP_STORAGE_PATH)
    : path.join(PROJECT_ROOT, 'uploads');

const PCAP_OUTPUT_PATH = process.env.PCAP_OUTPUT_PATH
    ? path.resolve(process.env.PCAP_OUTPUT_PATH)
    : path.join(PCAP_STORAGE_PATH, 'outputs');

// Ensure directories exist on startup
[PCAP_STORAGE_PATH, PCAP_OUTPUT_PATH].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ── History storage ─────────────────────────────────────────────────────────
const HISTORY_PATH = path.join(__dirname, 'data', 'history.json');
const HISTORY_DIR  = path.dirname(HISTORY_PATH);
if (!fs.existsSync(HISTORY_DIR)) fs.mkdirSync(HISTORY_DIR, { recursive: true });

// ── Engine thread constraints ────────────────────────────────────────────────
const ENGINE_MAX_LBS         = parseInt(process.env.ENGINE_MAX_LBS)         || 16;
const ENGINE_MAX_FPS_PER_LB  = parseInt(process.env.ENGINE_MAX_FPS_PER_LB)  || 16;
const ENGINE_DEFAULT_LBS     = parseInt(process.env.ENGINE_DEFAULT_LBS)     || 2;
const ENGINE_DEFAULT_FPS     = parseInt(process.env.ENGINE_DEFAULT_FPS)     || 2;

// ── Upload limits ────────────────────────────────────────────────────────────
const PCAP_MAX_FILE_SIZE_BYTES = parseInt(process.env.PCAP_MAX_FILE_SIZE_MB || '500') * 1024 * 1024;

// ── Network ─────────────────────────────────────────────────────────────────
const PORT        = parseInt(process.env.PORT)        || 3000;
const CORS_ORIGIN = process.env.CORS_ORIGIN           || '*';   // Set to frontend URL in production

// ── Print config summary on startup ─────────────────────────────────────────
const enginePath = resolveEnginePath();
console.log('─────────────────────────────────────────');
console.log(' DPI Engine Backend — Configuration');
console.log('─────────────────────────────────────────');
console.log(` PORT              : ${PORT}`);
console.log(` CORS_ORIGIN       : ${CORS_ORIGIN}`);
console.log(` DPI_ENGINE_PATH   : ${enginePath}`);
console.log(` Engine exists     : ${fs.existsSync(enginePath)}`);
console.log(` PCAP_STORAGE_PATH : ${PCAP_STORAGE_PATH}`);
console.log(` PCAP_OUTPUT_PATH  : ${PCAP_OUTPUT_PATH}`);
console.log(` Max upload        : ${PCAP_MAX_FILE_SIZE_BYTES / (1024*1024)} MB`);
console.log(` Max LBs / FPs     : ${ENGINE_MAX_LBS} / ${ENGINE_MAX_FPS_PER_LB}`);
console.log('─────────────────────────────────────────');

module.exports = {
    PORT,
    CORS_ORIGIN,
    PROJECT_ROOT,
    ENGINE_PATH: enginePath,
    PCAP_STORAGE_PATH,
    PCAP_OUTPUT_PATH,
    HISTORY_PATH,
    PCAP_MAX_FILE_SIZE_BYTES,
    ENGINE_MAX_LBS,
    ENGINE_MAX_FPS_PER_LB,
    ENGINE_DEFAULT_LBS,
    ENGINE_DEFAULT_FPS,
};
