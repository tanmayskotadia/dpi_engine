// Privileged local controls must never be reachable through remote browsers,
// DNS rebinding, cross-origin forms, or forwarded-client headers.
function localRequest(req, res, next) {
    const peer = req.socket.remoteAddress;
    if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(peer)) {
        return res.status(403).json({ error: 'Live capture and firewall controls are available only on this computer.' });
    }
    let target;
    try { target = new URL(`http://${req.headers.host}`); } catch { return res.status(403).json({ error: 'Invalid local host.' }); }
    if (!['localhost', '127.0.0.1', '[::1]'].includes(target.hostname)) return res.status(403).json({ error: 'Use localhost to access local controls.' });
    if (req.headers.origin) {
        let origin;
        try { origin = new URL(req.headers.origin); } catch { return res.status(403).json({ error: 'Invalid request origin.' }); }
        const sameHost = origin.hostname === target.hostname;
        const allowedPort = origin.port === target.port || origin.port === '5173';
        if (!sameHost || !allowedPort || !['http:', 'https:'].includes(origin.protocol)) return res.status(403).json({ error: 'Local controls require a trusted local page.' });
    }
    if (req.headers['sec-fetch-site'] === 'cross-site') return res.status(403).json({ error: 'Cross-site requests cannot change local controls.' });
    next();
}
function localControl(req, res, next) {
    return localRequest(req, res, () => {
        if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && !req.is('application/json')) {
            return res.status(415).json({ error: 'Local control requests require application/json.' });
        }
        res.setHeader('Cache-Control', 'no-store');
        next();
    });
}
module.exports = { localControl, localRequest };
