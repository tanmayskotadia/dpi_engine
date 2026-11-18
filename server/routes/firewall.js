const express = require('express');
const router = express.Router();
const firewall = require('../firewall-manager');
const rules = require('../rules-manager');

const respond = action => async (req, res) => {
    try { res.json(await action(req)); }
    catch (error) {
        res.status(error.status || 500).json({
            error: error.message || 'The firewall operation failed.',
            ...(error.rollbackSucceeded === undefined ? {} : { rollbackSucceeded: error.rollbackSucceeded }),
            ...(error.stateUnconfirmed === undefined ? {} : { stateUnconfirmed: error.stateUnconfirmed }),
        });
    }
};

// The server mounts this router behind its local-control origin and loopback guard.
router.get('/status', respond(() => firewall.status()));
router.post('/preview', respond(req => firewall.preview(rules.getRules(), req.body?.directions)));
router.post('/apply', respond(req => firewall.apply(req.body?.token)));
router.delete('/', respond(() => firewall.remove()));

module.exports = router;
