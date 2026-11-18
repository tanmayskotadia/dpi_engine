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
const { inspectCaptureHeader } = require('../capture-format');
const { randomUUID } = require('node:crypto');

// Storage is fully determined by the server — client cannot influence location
const storage = multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, config.PCAP_STORAGE_PATH),
    filename:    (_req, _file, cb) => cb(null, `.upload-${randomUUID()}.partial`),
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

    let format;
    try { format = inspectCaptureHeader(req.file.path); }
    catch (error) {
        fs.unlinkSync(req.file.path);
        return res.status(400).json({ error: error.message });
    }
    const stem = path.parse(path.basename(req.file.originalname)).name
        .replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 120) || 'capture';
    const filename = `${Date.now()}-${randomUUID()}-${stem}${format.extension}`;
    const published = path.join(config.PCAP_STORAGE_PATH, filename);
    try { fs.renameSync(req.file.path, published); }
    catch {
        fs.rmSync(req.file.path, { force: true });
        return res.status(500).json({ error: 'Could not save the uploaded capture.' });
    }
    res.json({
        success:  true,
        filename,
        path:     published,
        size:     req.file.size,
        format:   format.format,
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
            .filter(f => /\.(pcap|pcapng)$/i.test(f) && fs.lstatSync(path.join(config.PCAP_STORAGE_PATH, f)).isFile())
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

// Completed captures are downloadable only from the dedicated output directory.
router.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;
    if (!filename || filename.includes('/') || filename.includes('\\') || filename.includes('..') || !/^[a-zA-Z0-9._-]+$/.test(filename)) {
        return res.status(400).json({ error: 'Invalid output filename' });
    }
    const outputDirectory = path.resolve(config.PCAP_OUTPUT_PATH);
    const filePath = path.resolve(outputDirectory, filename);
    if (path.dirname(filePath) !== outputDirectory) {
        return res.status(400).json({ error: 'Invalid output filename' });
    }
    try {
        // Reject symlinks and directories, even when their names look valid.
        if (!fs.lstatSync(filePath).isFile()) {
            return res.status(404).json({ error: 'Output capture not found. Run the analysis again to generate it.' });
        }
        const engineManager = require('../engine-manager');
        if (engineManager.isProcessingFile(filePath)) {
            return res.status(409).json({ error: 'This capture is still being written. Wait for the analysis to finish.' });
        }
        res.download(filePath, filename, { headers: { 'Cache-Control': 'no-store' } }, error => {
            if (error && !res.headersSent) res.status(404).json({ error: 'Output capture is no longer available.' });
        });
    } catch (error) {
        if (error.code === 'ENOENT') return res.status(404).json({ error: 'Output capture not found. Run the analysis again to generate it.' });
        res.status(500).json({ error: 'Unable to download this output capture.' });
    }
});

// ── DELETE /api/files/:filename ───────────────────────────────────────────────
router.delete('/:filename', (req, res) => {
    try {
        const filename = req.params.filename;
        if (!filename || filename.includes('/') || filename.includes('\\') || filename.includes('..') || !/\.(pcap|pcapng)$/i.test(filename)) {
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
