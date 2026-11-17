const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const { test } = require('node:test');
const express = require('express');

// Use the real router and HTTP stack, but never read or mutate user captures.
test('output capture downloads', async (t) => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'dpi-download-tests-'));
    const inputDirectory = path.join(temporaryRoot, 'captures');
    const outputDirectory = path.join(temporaryRoot, 'outputs');
    fs.mkdirSync(inputDirectory);
    fs.mkdirSync(outputDirectory);

    const configPath = require.resolve('../server/config');
    const enginePath = require.resolve('../server/engine-manager');
    const routerPath = require.resolve('../server/routes/files');
    const originalModules = new Map([configPath, enginePath, routerPath].map((filename) => [filename, require.cache[filename]]));
    let processingFile = null;
    let server;

    t.after(async () => {
        if (server?.listening) {
            await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
        }
        for (const [filename, original] of originalModules) {
            if (original) require.cache[filename] = original;
            else delete require.cache[filename];
        }
        // Recursive cleanup is restricted to this test's generated temp directory.
        const resolvedRoot = path.resolve(temporaryRoot);
        assert.equal(path.dirname(resolvedRoot), path.resolve(os.tmpdir()));
        assert.ok(path.basename(resolvedRoot).startsWith('dpi-download-tests-'));
        fs.rmSync(resolvedRoot, { recursive: true, force: true });
    });

    require.cache[configPath] = {
        id: configPath,
        filename: configPath,
        loaded: true,
        exports: {
            PCAP_STORAGE_PATH: inputDirectory,
            PCAP_OUTPUT_PATH: outputDirectory,
            PCAP_MAX_FILE_SIZE_BYTES: 1024 * 1024,
        },
    };
    require.cache[enginePath] = {
        id: enginePath,
        filename: enginePath,
        loaded: true,
        exports: { isProcessingFile: (filename) => filename === processingFile },
    };
    delete require.cache[routerPath];

    const app = express();
    app.use('/api/files', require(routerPath));
    server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const port = server.address().port;

    // http.request preserves encoded traversal paths; fetch normalizes dot segments.
    const request = (filename) => new Promise((resolve, reject) => {
        const req = http.get({
            host: '127.0.0.1',
            port,
            path: `/api/files/download/${filename}`,
            agent: false,
        }, (response) => {
            const chunks = [];
            response.on('data', (chunk) => chunks.push(chunk));
            response.on('error', reject);
            response.on('end', () => resolve({
                status: response.statusCode,
                headers: response.headers,
                body: Buffer.concat(chunks),
            }));
        });
        req.on('error', reject);
        req.setTimeout(5000, () => req.destroy(new Error('Download request timed out')));
    });

    const assertJsonError = (response, status) => {
        assert.equal(response.status, status);
        assert.match(response.headers['content-type'], /^application\/json\b/);
        const body = JSON.parse(response.body.toString('utf8'));
        assert.equal(typeof body.error, 'string');
        assert.ok(body.error.length > 0);
        return body.error;
    };

    const capture = Buffer.from('d4c3b2a1020004000000000000000000ffff000001000000', 'hex');
    const outputName = 'analysis-output.pcap';
    fs.writeFileSync(path.join(outputDirectory, outputName), capture);
    fs.writeFileSync(path.join(inputDirectory, 'input-only.pcap'), Buffer.from('private input capture'));

    await t.test('downloads exact bytes with attachment and no-store headers', async () => {
        const response = await request(outputName);
        assert.equal(response.status, 200);
        assert.deepEqual(response.body, capture);
        assert.equal(response.headers['content-disposition'], `attachment; filename="${outputName}"`);
        assert.equal(response.headers['content-length'], String(capture.length));
        assert.equal(response.headers['cache-control'], 'no-store');
        assert.match(response.headers['content-type'], /^application\//);
    });

    await t.test('returns a JSON 404 for a missing capture', async () => {
        assertJsonError(await request('missing-output.pcap'), 404);
    });

    await t.test('rejects dot segments and encoded path separators', async (traversal) => {
        for (const filename of [
            '..',
            '%2e%2e',
            '..%2Fcaptures%2Finput-only.pcap',
            '..%5Ccaptures%5Cinput-only.pcap',
            'folder%2Fanalysis-output.pcap',
            'folder%5Canalysis-output.pcap',
            '%2Fanalysis-output.pcap',
            'C%3A%5CWindows%5Ccapture.pcap',
            'capture..pcap',
        ]) {
            await traversal.test(filename, async () => {
                assert.match(assertJsonError(await request(filename), 400), /invalid output filename/i);
            });
        }
    });

    await t.test('does not serve directories named like captures', async () => {
        fs.mkdirSync(path.join(outputDirectory, 'directory.pcap'));
        assertJsonError(await request('directory.pcap'), 404);
    });

    await t.test('does not expose input captures through the output endpoint', async () => {
        assertJsonError(await request('input-only.pcap'), 404);
    });

    await t.test('returns a JSON 409 while an output is still being written', async () => {
        processingFile = path.join(outputDirectory, outputName);
        try {
            assert.match(assertJsonError(await request(outputName), 409), /still being written/i);
        } finally {
            processingFile = null;
        }
        // The same output becomes downloadable once the engine has finished.
        assert.deepEqual((await request(outputName)).body, capture);
    });

    await t.test('rejects symbolic links even when their target is a regular file', async (symlink) => {
        const linkName = 'linked-capture.pcap';
        try {
            fs.symlinkSync(path.join(inputDirectory, 'input-only.pcap'), path.join(outputDirectory, linkName), 'file');
        } catch (error) {
            if (process.platform === 'win32' && ['EPERM', 'EACCES'].includes(error.code)) {
                symlink.skip('Windows does not grant this process permission to create symbolic links.');
                return;
            }
            throw error;
        }
        assertJsonError(await request(linkName), 404);
    });
});
