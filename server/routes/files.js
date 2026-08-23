/**
 * routes/files.js — PCAP upload and listing.
 * Uses central config for storage paths and file size limits.
 */

const express = require('express');
const router  = express.Router();
const multer  = require('multer');
const fs      = require('fs');
const path    = require('path');
const config  = require('../config');

// Storage is fully determined by the server — client cannot influence location
const storage = multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, config.PCAP_STORAGE_PATH),
    filename:    (_req, file, cb)  => {
        // Sanitize the original filename — strip path separators and control chars
        const safe = path.basename(file.originalname).replace(/[^a-zA-Z0-9._-]/g, '_');
        cb(null, `${Date.now()}-${safe}`);
    },
});

// Only allow .pcap / .pcapng MIME types and extensions
function pcapFilter(_req, file, cb) {
    const ext  = path.extname(file.originalname).toLowerCase();
    const allowed = ['.pcap', '.pcapng'];
    if (allowed.includes(ext)) {
        cb(null, true);
    } else {
        cb(new Error(`Only ${allowed.join('/')} files are accepted`));
    }
}

const upload = multer({
    storage,
    fileFilter: pcapFilter,
    limits: { fileSize: config.PCAP_MAX_FILE_SIZE_BYTES },
});

// ── POST /api/files/upload ────────────────────────────────────────────────────
router.post('/upload', upload.single('pcap'), (req, res) => {
    if (!req.file) {
        res.status(400);
        return res.json({ error: 'No file uploaded' });
    }

    res.json({
        success:  true,
        filename: req.file.filename,
        path:     req.file.path,   // absolute — used by engine-manager internally
        size:     req.file.size,
    });
});

// ── Multer error handler ──────────────────────────────────────────────────────
router.use((err, _req, res, _next) => {
    if (err && err.code === 'LIMIT_FILE_SIZE') {
        res.status(413);
        return res.json({ error: `File too large. Maximum allowed size is ${config.PCAP_MAX_FILE_SIZE_BYTES / (1024 * 1024)} MB.` });
    }
    res.status(400);
    res.json({ error: err.message || 'Upload error' });
});

// ── GET /api/files/list ───────────────────────────────────────────────────────
router.get('/list', (_req, res) => {
    try {
        const files = fs.readdirSync(config.PCAP_STORAGE_PATH)
            .filter(f => f.endsWith('.pcap') || f.endsWith('.pcapng'))
            .map(f => {
                const fullPath = path.join(config.PCAP_STORAGE_PATH, f);
                const stat     = fs.statSync(fullPath);
                return {
                    filename:  f,
                    path:      fullPath,   // absolute — used by engine-manager
                    size:      stat.size,
                    createdAt: stat.birthtime,
                };
            })
            .sort((a, b) => b.createdAt - a.createdAt);

        res.json(files);
    } catch (err) {
        res.status(500);
        res.json({ error: err.message });
    }
});

// ── DELETE /api/files/:filename ───────────────────────────────────────────────
router.delete('/:filename', (req, res) => {
    try {
        const filename = req.params.filename;
        if (!filename || filename.includes('/') || filename.includes('\\') || filename.includes('..')) {
            res.status(400);
            return res.json({ error: 'Invalid filename' });
        }

        const fullPath = path.join(config.PCAP_STORAGE_PATH, filename);
        
        // Prevent path traversal
        if (!fullPath.startsWith(config.PCAP_STORAGE_PATH)) {
            res.status(403);
            return res.json({ error: 'Access denied' });
        }

        if (!fs.existsSync(fullPath)) {
            res.status(404);
            return res.json({ error: 'File not found' });
        }
        
        // Ensure file is not currently being processed
        const engineManager = require('../engine-manager');
        if (engineManager.isProcessingFile(fullPath)) {
            res.status(409);
            return res.json({ error: 'This PCAP is currently being processed and cannot be deleted.' });
        }

        fs.unlinkSync(fullPath);
        res.json({ success: true, message: 'File deleted successfully' });
    } catch (err) {
        res.status(500);
        res.json({ error: `Unable to delete PCAP. ${err.message}` });
    }
});

module.exports = router;
