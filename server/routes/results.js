const express = require('express');
const router = express.Router();
const engineManager = require('../engine-manager');

router.get('/latest', (req, res) => {
    res.json(engineManager.latestResults || {});
});

router.get('/history', (req, res) => {
    res.json(engineManager.getHistory());
});

router.get('/:id', (req, res) => {
    const history = engineManager.getHistory();
    const result = history.find(r => r.id === req.params.id);
    if (result) {
        res.json(result);
    } else {
        res.status(404);
        res.json({ error: 'Result not found' });
    }
});

module.exports = router;
