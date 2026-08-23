const express = require('express');
const router = express.Router();
const rulesManager = require('../rules-manager');

router.get('/', (req, res) => {
    res.json(rulesManager.getRules());
});

router.post('/ip', (req, res) => {
    const { ip } = req.body;
    if (ip) rulesManager.addIP(ip);
    res.json(rulesManager.getRules());
});

router.delete('/ip/:ip', (req, res) => {
    rulesManager.removeIP(req.params.ip);
    res.json(rulesManager.getRules());
});

router.post('/app', (req, res) => {
    const { app } = req.body;
    if (app) rulesManager.addApp(app);
    res.json(rulesManager.getRules());
});

router.delete('/app/:app', (req, res) => {
    rulesManager.removeApp(req.params.app);
    res.json(rulesManager.getRules());
});

router.post('/domain', (req, res) => {
    const { domain } = req.body;
    if (domain) rulesManager.addDomain(domain);
    res.json(rulesManager.getRules());
});

router.delete('/domain/:domain', (req, res) => {
    rulesManager.removeDomain(req.params.domain);
    res.json(rulesManager.getRules());
});

router.delete('/', (req, res) => {
    rulesManager.clearAll();
    res.json(rulesManager.getRules());
});

module.exports = router;
