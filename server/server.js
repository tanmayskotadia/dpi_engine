/**
 * server.js — Express application entry point.
 * All configuration is loaded from server/config.js which reads environment variables.
 */

// Load .env file if present (production environment variables)
try { require('dotenv').config(); } catch (_) { /* dotenv optional */ }


const express      = require('express');
const cors         = require('cors');
const path         = require('path');
const config       = require('./config');
const engineRoutes = require('./routes/engine');
const rulesRoutes  = require('./routes/rules');
const resultsRoutes= require('./routes/results');
const filesRoutes  = require('./routes/files');

const app = express();

// ── CORS ─────────────────────────────────────────────────────────────────────
// In development, CORS_ORIGIN defaults to '*' (allow all).
// In production, set CORS_ORIGIN=https://your-frontend-domain.com
app.use(cors({
    origin: config.CORS_ORIGIN,
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type'],
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Static frontend (production only) ────────────────────────────────────────
// In development, Vite serves the frontend on its own port with HMR.
// In production, build the frontend first (`npm run build` inside /frontend)
// and Express will serve the compiled files from /frontend/dist.
const frontendDist = path.join(config.PROJECT_ROOT, 'frontend', 'dist');
const fs = require('fs');
if (fs.existsSync(frontendDist)) {
    app.use(express.static(frontendDist));
    console.log(`Serving built frontend from: ${frontendDist}`);
}

// ── API Routes ────────────────────────────────────────────────────────────────
app.use('/api/engine',  engineRoutes);
app.use('/api/rules',   rulesRoutes);
app.use('/api/results', resultsRoutes);
app.use('/api/files',   filesRoutes);

// ── SPA fallback (production) ─────────────────────────────────────────────────
// Express 5 uses path-to-regexp v8 which requires named wildcard params
if (fs.existsSync(frontendDist)) {
    app.get('/{*path}', (req, res) => {
        res.sendFile(path.join(frontendDist, 'index.html'));
    });
}

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(config.PORT, () => {
    console.log(`DPI Engine Backend listening on port ${config.PORT}`);
});
