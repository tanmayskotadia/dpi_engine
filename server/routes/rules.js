const express = require('express');
const router = express.Router();
const rulesManager = require('../rules-manager');
const { RuleValidationError, RULE_KEYS } = require('../rule-validation');

function respond(res, action) {
    try {
        res.json(action());
    } catch (error) {
        const status = error instanceof RuleValidationError ? 400 : 500;
        res.status(status).json({ error: error.message || 'Unable to update blocking rules.' });
    }
}

router.get('/', (_req, res) => respond(res, () => rulesManager.getRules()));
router.post('/', (_req, res) => res.status(400).json({ error: 'A rule type is required.' }));

router.post('/:type', (req, res) => respond(res, () => {
    const { type } = req.params;
    if (!Object.hasOwn(RULE_KEYS, type)) throw new RuleValidationError('Unknown rule type. Use ip, app, domain, port, or protocol.');
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) throw new RuleValidationError('Send a JSON object containing the rule value.');
    return rulesManager.addRule(type, req.body[type]);
}));

router.delete('/:type/:value', (req, res) => respond(res, () => rulesManager.removeRule(req.params.type, req.params.value)));
router.delete('/:type', (_req, res) => res.status(400).json({ error: 'A rule type and value are required.' }));
router.delete('/', (_req, res) => respond(res, () => rulesManager.clearAll()));

module.exports = router;
