/**
 * scripts/build-engine.js
 *
 * Cross-platform build script for the C++ DPI engine.
 * Run via: node scripts/build-engine.js
 *
 * Strategy:
 *  1. Try CMake (preferred — respects CMakeLists.txt targets).
 *  2. Fall back to g++ direct compilation if cmake is not available.
 */

const { execSync, spawnSync } = require('child_process');
const path = require('path');
const fs   = require('fs');

const ROOT      = path.resolve(__dirname, '..');
const BUILD_DIR = path.join(ROOT, 'build');
const IS_WIN    = process.platform === 'win32';
const EXE_NAME  = IS_WIN ? 'packet_analyzer.exe' : 'packet_analyzer';

function run(cmd, args, opts = {}) {
    const result = spawnSync(cmd, args, { stdio: 'inherit', ...opts });
    return result.status === 0;
}

function commandExists(cmd) {
    try {
        execSync(IS_WIN ? `where.exe ${cmd}` : `which ${cmd}`, { stdio: 'pipe' });
        return true;
    } catch (_) {
        return false;
    }
}

// Ensure build directory exists
if (!fs.existsSync(BUILD_DIR)) fs.mkdirSync(BUILD_DIR, { recursive: true });

// ── Strategy 1: CMake ─────────────────────────────────────────────────────────
if (commandExists('cmake')) {
    console.log('[build] CMake found — running cmake configure + build...');
    const configured = run('cmake', ['-B', BUILD_DIR, '-S', ROOT], { cwd: ROOT });
    if (!configured) { console.error('[build] cmake configure failed'); process.exit(1); }
    const built = run('cmake', ['--build', BUILD_DIR, '--config', 'Release'], { cwd: ROOT });
    if (!built) { console.error('[build] cmake build failed'); process.exit(1); }

// ── Strategy 2: g++ direct ────────────────────────────────────────────────────
} else if (commandExists('g++')) {
    console.log('[build] cmake not found — falling back to g++ direct compilation...');
    const sources = [
        'src/dpi_mt.cpp',
        'src/pcap_reader.cpp',
        'src/packet_parser.cpp',
        'src/sni_extractor.cpp',
        'src/types.cpp',
    ].map(s => path.join(ROOT, s));

    const output = path.join(BUILD_DIR, EXE_NAME);
    const ok = run('g++', [
        '-std=c++17', '-O2',
        ...sources,
        '-I', path.join(ROOT, 'include'),
        '-o', output,
        '-lpthread',
    ]);
    if (!ok) { console.error('[build] g++ compilation failed'); process.exit(1); }

// ── No compiler available ──────────────────────────────────────────────────────
} else {
    console.error('[build] Neither cmake nor g++ found in PATH.');
    console.error('[build] Install CMake (https://cmake.org/download/) or g++ and try again.');
    process.exit(1);
}

// ── Verify output ─────────────────────────────────────────────────────────────
// Search standard output locations
const locations = [
    path.join(BUILD_DIR, 'Release', EXE_NAME),
    path.join(BUILD_DIR, 'Debug',   EXE_NAME),
    path.join(BUILD_DIR,             EXE_NAME),
];

const found = locations.find(p => fs.existsSync(p));
if (found) {
    console.log(`\n✓ Engine built successfully: ${found}`);
    console.log('  Start the backend with: npm run server');
} else {
    console.error('\n✗ Build appeared to succeed but executable not found in expected locations.');
    locations.forEach(p => console.error(`  Checked: ${p}`));
    process.exit(1);
}
