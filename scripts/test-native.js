const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'dpi-native-tests-'));
const compiler = process.env.CXX || 'g++';
const suites = [
    { name: 'capture-reader-test', sources: ['tests/capture-reader-test.cpp', 'src/pcap_reader.cpp'] },
    { name: 'packet-parser-test', sources: ['tests/packet-parser-test.cpp', 'src/packet_parser.cpp'] },
];

function run(command, args) {
    const result = spawnSync(command, args, { cwd: root, stdio: 'inherit', timeout: 120000 });
    if (result.error) throw new Error(`Could not run ${command}: ${result.error.message}`);
    if (result.status !== 0) throw new Error(`${command} exited with ${result.status ?? result.signal}`);
}

try {
    for (const suite of suites) {
        console.log(`[native test] ${suite.name}`);
        const executable = path.join(temporaryRoot, suite.name + (process.platform === 'win32' ? '.exe' : ''));
        run(compiler, [
            '-std=c++17', '-O1', '-Wall', '-Wextra', '-Wpedantic',
            '-I', path.join(root, 'include'),
            ...suite.sources.map((source) => path.join(root, source)),
            '-o', executable, '-pthread',
        ]);
        run(executable, []);
    }
} catch (error) {
    console.error(`[native test] ${error.message}`);
    process.exitCode = 1;
} finally {
    // Remove only the unique directory created by this runner.
    const resolved = path.resolve(temporaryRoot);
    assert.equal(path.dirname(resolved), path.resolve(os.tmpdir()));
    assert.ok(path.basename(resolved).startsWith('dpi-native-tests-'));
    fs.rmSync(resolved, { recursive: true, force: true });
}
