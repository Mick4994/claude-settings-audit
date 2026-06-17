#!/usr/bin/env node
// PostToolUse hook for Claude Code. Captures settings-file changes and forwards
// them to the Python daemon over a Windows named pipe. Must exit fast and
// never throw — failures are silent so Claude Code is never blocked.

const fs = require('fs');
const crypto = require('crypto');
const net = require('net');

const PIPE = '\\\\.\\pipe\\claude-settings-audit';
const TIMEOUT_MS = 200;

let payload = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { payload += chunk; });
process.stdin.on('end', () => {
  try {
    handle(JSON.parse(payload || '{}'));
  } catch (e) {
    process.stderr.write(`[postsettingschange] bad payload: ${e.message}\n`);
    process.exit(0);
  }
});

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function isWatchedPath(p) {
  if (!p) return false;
  const norm = String(p).replace(/\\/g, '/').toLowerCase();
  const watched = [
    '/.claude/settings.json',
    '/.claude/settings.local.json',
    '/.claude/hooks/hooks.json',
    '/.claude/plugin.json',
    '/.claude/marketplace.json',
  ];
  return watched.some((suf) => norm.endsWith(suf));
}

function handle(data) {
  const tool = data.tool_name || data.tool || '';
  const cwd = data.cwd || '';
  const sessionId = data.session_id || '';
  const ti = data.tool_input || {};
  const tr = data.tool_result || {};

  let filePath = '';
  let after = '';
  if (tool === 'Write') {
    filePath = ti.file_path || '';
    after = typeof ti.content === 'string' ? ti.content : JSON.stringify(ti.content || '');
  } else if (tool === 'Edit' || tool === 'MultiEdit') {
    filePath = ti.file_path || '';
    if (typeof tr === 'string') after = tr;
    else if (tr && tr.new_string) after = tr.new_string;
    else if (tr && tr.content) after = tr.content;
  } else if (tool === 'Bash') {
    const cmd = ti.command || '';
    if (/settings(?:\.local)?\.json|hooks\.json|plugin\.json|marketplace\.json/i.test(cmd)) {
      filePath = guessFromBash(cmd);
    }
  }

  if (!isWatchedPath(filePath)) {
    process.exit(0);
  }

  let beforeText = '';
  try {
    if (fs.existsSync(filePath)) {
      beforeText = fs.readFileSync(filePath, 'utf8');
    }
  } catch (_) { /* may not exist on Write */ }

  const event = {
    type: 'hook',
    ts: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
    tool,
    session_id: sessionId,
    cwd,
    file_path: filePath,
    sha256_before: sha256(beforeText),
    sha256_after: sha256(after),
    diff: simpleDiff(beforeText, after),
  };

  send(event);
}

function guessFromBash(cmd) {
  const m = cmd.match(/['"]?([A-Za-z]:[\\/][^'"\s|&;]*?\.(?:json|local\.json))['"]?/);
  return m ? m[1] : '';
}

function simpleDiff(a, b) {
  if (a === b) return '';
  const al = a.split('\n');
  const bl = b.split('\n');
  const out = [];
  const max = Math.max(al.length, bl.length);
  for (let i = 0; i < max; i++) {
    if (al[i] !== bl[i]) {
      if (al[i] !== undefined) out.push(`- ${al[i]}`);
      if (bl[i] !== undefined) out.push(`+ ${bl[i]}`);
    }
  }
  return out.join('\n');
}

function send(event) {
  const json = JSON.stringify(event);
  const sock = net.connect(PIPE);
  let done = false;
  const finish = (code) => { if (!done) { done = true; process.exit(code); } };
  sock.setTimeout(TIMEOUT_MS);
  sock.on('connect', () => {
    sock.end(json + '\n');
    finish(0);
  });
  sock.on('error', () => finish(0));
  sock.on('timeout', () => finish(0));
}
