// vm-console.js — the maintenance VM's screen (vmmaint.rs: /api/vm/console = QEMU's VNC through Broom), drawn by noVNC
// (static/novnc/, MPL-2.0). Keys go as PC scancodes (QEMU's extended key events), so any keyboard layout works;
// the mouse is a USB tablet in the VM, so the pointer follows exactly.
import RFB from '/novnc/core/rfb.js';

// Colour mode follows the OS, like the admin pages.
const dark = matchMedia('(prefers-color-scheme: dark)');
const theme = () => { document.documentElement.dataset.bsTheme = dark.matches ? 'dark' : 'light'; };
theme(); dark.addEventListener('change', theme);

const $ = id => document.getElementById(id);
const note = (t) => { const n = $('note'); n.textContent = t || ''; n.classList.toggle('hidden', !t); };
const state = (t) => { $('state').textContent = t; };

async function api(url, body) {
  const r = await fetch(url, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined);
  if (r.status === 401) { location.replace('/login'); throw new Error('login required'); }
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

let rfb = null, fit = true, last = null;

function connect() {
  if (rfb) return;
  $('again').hidden = true;
  note('Connecting to the VM…');
  rfb = new RFB($('screen'), `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/vm/console`);
  rfb.scaleViewport = fit;
  rfb.resizeSession = false;
  rfb.focusOnClick = true;
  rfb.background = '#111';
  rfb.addEventListener('connect', () => { note(''); state('connected — click the screen to type'); rfb.focus(); });
  rfb.addEventListener('disconnect', () => {
    rfb = null; $('again').hidden = false;
    note(last && !['running', 'stopping'].includes(last.state) ? '' : 'Disconnected from the VM.');
    poll();
  });
}

// The session's state every 5 s: the bar, and what happened once the VM is off.
async function poll() {
  let s;
  try { s = (await api('/api/vm')).session; } catch (e) { state('server: ' + e.message); return; }
  last = s;
  if (!s) { state('no VM'); note('No VM is running — start one on the Diskless page (Maintain in the browser).'); return; }
  $('title').textContent = `VM · ${s.golden}`;
  document.title = `${s.golden} · VM screen · Broom`;
  const run = s.state === 'running' || s.state === 'stopping';
  for (const id of ['cad', 'off', 'kill']) $(id).disabled = !run;
  if (run) {
    const games = (s.games || []).map(g => `${g.name} as ${g.letter}:`).join(', ');
    if (!rfb || s.state === 'stopping') state((s.state === 'stopping' ? 'shutting down — ' : 'running — ') +
      (games ? 'games disk ' + games + ' writable — ' : '') + (s.keep ? 'Windows changes kept' : 'Windows changes discarded at the end'));
    if (!rfb && s.state === 'running') connect();
  } else {
    if (rfb) { rfb.disconnect(); rfb = null; }
    $('again').hidden = true;
    state(s.state);
    note(`The VM is ${s.state}. ${s.msg || ''}`);
  }
}

// A button that asks once more before it acts (no browser dialog).
function confirmed(btn, label, act) {
  let armed = 0;
  btn.addEventListener('click', async () => {
    if (!armed) {
      const was = btn.textContent; btn.textContent = label; armed = setTimeout(() => { btn.textContent = was; armed = 0; }, 4000);
      btn.dataset.was = was; return;
    }
    clearTimeout(armed); armed = 0; btn.textContent = btn.dataset.was;
    try { state((await act()).msg); } catch (e) { state('✗ ' + e.message); }
    poll();
  });
}

$('cad').addEventListener('click', () => { if (rfb) { rfb.sendCtrlAltDel(); rfb.focus(); } });
$('scale').addEventListener('click', () => {
  fit = !fit; $('scale').textContent = fit ? 'Real size' : 'Fit to window';
  if (rfb) { rfb.scaleViewport = fit; rfb.clipViewport = !fit; rfb.focus(); }
});
$('full').addEventListener('click', () => {
  if (document.fullscreenElement) document.exitFullscreen(); else document.documentElement.requestFullscreen().catch(() => {});
});
$('again').addEventListener('click', () => connect());
confirmed($('off'), 'Sure? Shut down', () => api('/api/vm/stop', { force: false }));
confirmed($('kill'), 'Sure? Turn off now', () => api('/api/vm/stop', { force: true }));

poll();
setInterval(poll, 5000);
