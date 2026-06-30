/**
 * CipherVault ES — Lógica de interfaz
 * Maneja tabs, formularios, visualización del abecedario
 */

'use strict';

const { cifrar, descifrar, ABC, N, shiftChar, unshiftChar } = window.CipherVault;

// ─── TABS ─────────────────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = btn.dataset.tab;
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + target).classList.add('active');
    if (target === 'abc') buildABC();
  });
});

// ─── PASSWORD TOGGLE ──────────────────────────────────────────────────────────
function togglePw(inputId, btn) {
  const el = document.getElementById(inputId);
  el.type = el.type === 'password' ? 'text' : 'password';
  btn.textContent = el.type === 'password' ? '👁' : '🙈';
}
window.togglePw = togglePw;

// ─── PASSWORD STRENGTH ────────────────────────────────────────────────────────
document.getElementById('enc-pw').addEventListener('input', function () {
  updateStrength(this.value);
});

function updateStrength(pw) {
  const fill = document.getElementById('str-fill');
  const txt  = document.getElementById('str-txt');
  if (!pw) { fill.style.width = '0'; txt.textContent = ''; return; }

  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 14) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/\d/.test(pw))   score++;
  if (/[^a-zA-Z0-9]/.test(pw)) score++;

  const levels = [
    { w: '15%',  c: '#e85d5d', l: 'Muy débil'   },
    { w: '30%',  c: '#e85d5d', l: 'Débil'        },
    { w: '55%',  c: '#f5a623', l: 'Moderada'     },
    { w: '75%',  c: '#5b8cf7', l: 'Fuerte'       },
    { w: '100%', c: '#3ecf8e', l: 'Muy fuerte'   },
  ];
  const lv = levels[Math.min(score, 4)];
  fill.style.width      = lv.w;
  fill.style.background = lv.c;
  txt.textContent = 'Fortaleza: ' + lv.l;
}

// ─── STATUS ───────────────────────────────────────────────────────────────────
function showStatus(id, msg, type) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.className = 'status ' + type;
  if (type === 'ok') setTimeout(() => { el.style.display = 'none'; }, 4000);
}

// ─── CIFRAR ───────────────────────────────────────────────────────────────────
async function doEncrypt() {
  const text = document.getElementById('enc-input').value;
  const pw   = document.getElementById('enc-pw').value;
  const btn  = document.getElementById('btn-enc');
  const out  = document.getElementById('enc-out');

  if (!text.trim()) { showStatus('enc-status', 'Escribe algo para cifrar.', 'err'); return; }
  if (pw.length < 8) { showStatus('enc-status', 'La contraseña necesita al menos 8 caracteres.', 'err'); return; }

  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span>Cifrando 3 fases...';
  out.textContent = 'Procesando...';

  try {
    const result = await cifrar(text, pw);
    out.textContent = result;
    showStatus('enc-status', '✅ Cifrado completado — sustitución ES + AES-256-GCM ×2 aplicados.', 'ok');
  } catch (e) {
    out.textContent = 'Error al cifrar.';
    showStatus('enc-status', '❌ Error: ' + e.message, 'err');
  }

  btn.disabled = false;
  btn.innerHTML = '🔒 Cifrar mensaje';
}
window.doEncrypt = doEncrypt;

// ─── DESCIFRAR ────────────────────────────────────────────────────────────────
async function doDecrypt() {
  const text = document.getElementById('dec-input').value.trim();
  const pw   = document.getElementById('dec-pw').value;
  const out  = document.getElementById('dec-out');

  if (!text) { showStatus('dec-status', 'Pega el texto cifrado.', 'err'); return; }
  if (!pw)   { showStatus('dec-status', 'Ingresa la contraseña.', 'err'); return; }

  out.textContent = 'Descifrando...';

  try {
    const result = await descifrar(text, pw);
    out.textContent = result;
    showStatus('dec-status', '✅ Descifrado exitoso — 3 fases revertidas.', 'ok');
  } catch (e) {
    out.textContent = 'No se pudo descifrar.';
    showStatus('dec-status', '❌ Contraseña incorrecta o datos corruptos.', 'err');
  }
}
window.doDecrypt = doDecrypt;

// ─── COPIAR / DESCARGAR / LIMPIAR ─────────────────────────────────────────────
function copyEl(id) {
  const text = document.getElementById(id).textContent;
  if (text && !text.includes('aparecerá')) {
    navigator.clipboard.writeText(text)
      .then(() => console.log('Copiado'))
      .catch(() => alert('No se pudo copiar. Selecciona el texto manualmente.'));
  }
}
window.copyEl = copyEl;

function dlEl(id, filename) {
  const text = document.getElementById(id).textContent;
  if (!text || text.includes('aparecerá')) return;
  const a = document.createElement('a');
  a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(text);
  a.download = filename;
  a.click();
}
window.dlEl = dlEl;

function clrEnc() {
  document.getElementById('enc-input').value = '';
  document.getElementById('enc-pw').value = '';
  document.getElementById('enc-out').textContent = 'El texto cifrado aparecerá aquí...';
  document.getElementById('str-fill').style.width = '0';
  document.getElementById('str-txt').textContent = '';
  document.getElementById('enc-status').style.display = 'none';
}
window.clrEnc = clrEnc;

function clrDec() {
  document.getElementById('dec-input').value = '';
  document.getElementById('dec-pw').value = '';
  document.getElementById('dec-out').textContent = 'El texto descifrado aparecerá aquí...';
  document.getElementById('dec-status').style.display = 'none';
}
window.clrDec = clrDec;

// ─── ABECEDARIO TAB ───────────────────────────────────────────────────────────
function buildABC() {
  // Grid de letras
  const grid = document.getElementById('abc-grid');
  if (grid.children.length > 0) return; // ya construido
  grid.innerHTML = ABC.map((letra, i) =>
    `<div class="abc-cell">
      <span class="idx">${i}</span>
      <span class="ltr">${letra}</span>
    </div>`
  ).join('');

  // Filas de demostración
  const demos = ['a', 'b', 'e', 'l', 'll', 'm', 'n', 'ñ', 'z'];
  const dr = document.getElementById('demo-rows');
  dr.innerHTML = demos.map(letra => {
    const orig = ABC.indexOf(letra);
    const pos7  = ((orig - 7) % N + N) % N;
    const pos73 = ((pos7 + 3) % N + N) % N;
    return `<div class="demo-row">
      <span class="dv">${letra}</span>
      <span class="dm">[${orig}]</span>
      <span class="da">−7 →</span>
      <span class="dv">${ABC[pos7]}</span>
      <span class="dm">[${pos7}]</span>
      <span class="da">+3 →</span>
      <span class="dfinal">${ABC[pos73]}</span>
      <span class="dm">[${pos73}]</span>
    </div>`;
  }).join('');
}

// Prueba de letra
window.testLetra = function (val) {
  const out    = document.getElementById('test-out');
  const detail = document.getElementById('test-detail');
  if (!val) { out.textContent = '—'; detail.textContent = 'Escribe una letra'; return; }

  const low = val.toLowerCase();
  const idx = ABC.indexOf(low);

  if (idx === -1) {
    out.textContent    = '?';
    detail.textContent = `"${val}" no está en el abecedario español.`;
    return;
  }

  const pos7  = ((idx - 7) % N + N) % N;
  const pos73 = ((pos7 + 3) % N + N) % N;

  out.textContent    = ABC[pos73];
  detail.textContent = `[${idx}] → −7 → [${pos7}]=${ABC[pos7]} → +3 → [${pos73}]=${ABC[pos73]}`;
};

// ─── ENTER SHORTCUTS ─────────────────────────────────────────────────────────
document.getElementById('enc-pw').addEventListener('keydown', e => {
  if (e.key === 'Enter') doEncrypt();
});
document.getElementById('dec-pw').addEventListener('keydown', e => {
  if (e.key === 'Enter') doDecrypt();
});
