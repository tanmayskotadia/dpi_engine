const express = require('express');
const manager = require('../capture-manager');

function createCaptureRouter(captureManager = manager) {
    const router = express.Router();
    router.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
    router.get('/interfaces', async (_req, res) => { res.json(await captureManager.listInterfaces()); });
    router.get('/status', (_req, res) => { res.json(captureManager.getStatus()); });
    router.post('/start', async (req, res) => {
        try { res.json(await captureManager.start(req.body)); }
        catch (error) { res.status(error.statusCode || 500).json({ error: error.message }); }
    });
    router.post('/stop', (_req, res) => {
        try { res.json(captureManager.stop()); }
        catch (error) { res.status(error.statusCode || 500).json({ error: error.message }); }
    });
    return router;
}

module.exports = createCaptureRouter();
module.exports.createCaptureRouter = createCaptureRouter;
