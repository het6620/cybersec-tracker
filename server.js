const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const path = require('path');
const fs = require('fs');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');

const app = express();
const PORT = process.env.PORT || 3000;

// DB setup
const dbPath = path.join(__dirname, 'data');
if (!fs.existsSync(dbPath)) fs.mkdirSync(dbPath);
const adapter = new FileSync(path.join(dbPath, 'db.json'));
const db = low(adapter);

db.defaults({
  users: {},
  progress: {},
  quiz_scores: {},
  theme: {}
}).write();

app.use(compression());
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── API: Get progress for a session ──
app.get('/api/progress/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  const progress = db.get(`progress.${sessionId}`).value() || {};
  res.json(progress);
});

// ── API: Update day completion ──
app.post('/api/progress/:sessionId/day/:day', (req, res) => {
  const { sessionId, day } = req.params;
  const { completed } = req.body;
  const key = `progress.${sessionId}.day_${day}`;
  db.set(key, completed).write();
  res.json({ ok: true });
});

// ── API: Save quiz score ──
app.post('/api/quiz/:sessionId/day/:day', (req, res) => {
  const { sessionId, day } = req.params;
  const { score, total, answers } = req.body;
  const key = `quiz_scores.${sessionId}.day_${day}`;
  db.set(key, { score, total, answers, completedAt: new Date().toISOString() }).write();
  res.json({ ok: true });
});

// ── API: Get quiz scores ──
app.get('/api/quiz/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  const scores = db.get(`quiz_scores.${sessionId}`).value() || {};
  res.json(scores);
});

// ── API: Get full summary ──
app.get('/api/summary/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  const progress = db.get(`progress.${sessionId}`).value() || {};
  const quizScores = db.get(`quiz_scores.${sessionId}`).value() || {};
  res.json({ progress, quizScores });
});

// Serve index for all routes
app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🔐 CyberSec Tracker running on port ${PORT}`);
});
