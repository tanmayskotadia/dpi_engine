/**
 * routes/engine.js — Engine control API.
 * Thread counts are validated here; path security is enforced in engine-manager.
 */

const express       = require('express');
const router        = express.Router();
const engineManager = require('../engine-manager');
const config        = require('../config');

// ── POST /api/engine/start ────────────────────────────────────────────────────
router.post('/start', (req, res) => {
    try {
        const { inputFile, outputFile, config: engineConfig } = req.body || {};

        if (typeof inputFile !== 'string' || typeof outputFile !== 'string' || !inputFile || !outputFile) {
            res.status(400);
            return res.json({ error: 'inputFile and outputFile are required' });
        }

        // Validate thread counts early so the client gets a meaningful error
        if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,160}\.(pcap|pcapng)$/i.test(outputFile) || outputFile.includes('..')) {
            return res.status(400).json({ error: 'Choose a short .pcap or .pcapng output filename without directory separators.' });
        }
        const numLbs   = engineConfig?.numLbs ?? config.ENGINE_DEFAULT_LBS;
        const fpsPerLb = engineConfig?.fpsPerLb ?? config.ENGINE_DEFAULT_FPS;

        if (!Number.isInteger(numLbs) || numLbs < 1 || numLbs > config.ENGINE_MAX_LBS) {
            res.status(400);
            return res.json({ error: `numLbs must be between 1 and ${config.ENGINE_MAX_LBS}` });
        }
        if (!Number.isInteger(fpsPerLb) || fpsPerLb < 1 || fpsPerLb > config.ENGINE_MAX_FPS_PER_LB) {
            res.status(400);
            return res.json({ error: `fpsPerLb must be between 1 and ${config.ENGINE_MAX_FPS_PER_LB}` });
        }

        engineManager.start(inputFile, outputFile, { numLbs, fpsPerLb });
        res.json({ success: true, message: 'Engine started' });
    } catch (err) {
        res.status(500);
        res.json({ error: err.message });
    }
});

// ── POST /api/engine/stop ─────────────────────────────────────────────────────
router.post('/stop', (req, res) => {
    try {
        engineManager.stop();
        res.json({ success: true, message: 'Engine stopped' });
    } catch (err) {
        res.status(500);
        res.json({ error: err.message });
    }
});

// ── GET /api/engine/status ────────────────────────────────────────────────────
router.get('/status', (_req, res) => {
    res.json(engineManager.getStatus());
});

// ── GET /api/engine/stream (SSE) ──────────────────────────────────────────────
router.get('/stream', (req, res) => {
    res.setHeader('Content-Type',  'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection',    'keep-alive');

    engineManager.addListener(res);
    // Keep proxy connections alive and let the client detect a silent disconnect.
    const heartbeat = setInterval(() => {
        res.write(`data: ${JSON.stringify({ type: 'heartbeat' })}\n\n`);
    }, 10000);
    heartbeat.unref();
    req.on('close', () => {
        clearInterval(heartbeat);
        engineManager.removeListener(res);
    });
});

module.exports = router;
