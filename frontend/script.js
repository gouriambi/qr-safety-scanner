const ICONS = {
  shield: '<path d="M12 2L3 6v6c0 5 3.8 8.7 9 10 5.2-1.3 9-5 9-10V6l-9-4z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  warn: '<path d="M12 3l9 16H3l9-16z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 10v4M12 17h.01" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
  danger: '<path d="M12 2L3 6v6c0 5 3.8 8.7 9 10 5.2-1.3 9-5 9-10V6l-9-4z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M9.5 9.5l5 5M14.5 9.5l-5 5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
  clock: '<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><path d="M12 7v5l3 3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>'
};

const CIRC = 2 * Math.PI * 60;

function iconSvg(name){ return ICONS[name]; }

function symbolFor(status){
  if(status === 'pass') return '✓';
  if(status === 'warn') return '⚠';
  return '✕';
}

// ---------------------------------------------------------
// Draws whatever result object is passed in onto the card.
// Only ever called with a REAL backend result now — there is
// no fake/demo data left in this file.
// ---------------------------------------------------------
function renderCase(c){
  const card = document.getElementById('resultCard');
  card.style.setProperty('--verdict-color', c.color);
  card.style.setProperty('--verdict-glow', c.glow);

  document.getElementById('verdictText').textContent = c.verdict;
  document.getElementById('verdictIcon').innerHTML = iconSvg(c.icon);
  document.getElementById('verdictMsg').textContent = c.msg;
  document.getElementById('detectedUrl').textContent = c.url;

  const offset = CIRC - (c.score/100) * CIRC;
  const fill = document.getElementById('gaugeFill');
  fill.style.strokeDashoffset = offset;
  document.getElementById('gaugeScore').textContent = c.score;
  document.getElementById('gaugeLabel').textContent = c.gaugeLabel;

  document.getElementById('indicatorsList').innerHTML = c.indicators.map(i => `
    <div class="indicator-row ${i.s}">
      <span class="icon">${symbolFor(i.s)}</span>
      <span>${i.t}</span>
    </div>`).join('');

  const actionBtn = document.getElementById('actionBtn');
  actionBtn.textContent = c.actionLabel;
  actionBtn.style.background = c.actionColor;
  actionBtn.disabled = false;

  document.getElementById('a-url').textContent = c.url;
  document.getElementById('a-domain').textContent = c.domain;
  document.getElementById('a-protocol').textContent = c.protocol;
  document.getElementById('a-length').textContent = c.length;
  document.getElementById('a-redirect').textContent = c.redirect;

  document.getElementById('secIndicatorsGrid').innerHTML = c.secGrid.map(i => `
    <div class="indicator-row ${i.s}">
      <span class="icon">${symbolFor(i.s)}</span>
      <span>${i.t}</span>
    </div>`).join('');

  const statusEl = document.getElementById('scanStatus');
  statusEl.className = 'status-pill';
  document.getElementById('scanStatusText').textContent = c.verdict;
}

function setScanning(){
  const statusEl = document.getElementById('scanStatus');
  statusEl.className = 'status-pill';
  document.getElementById('scanStatusText').textContent = 'Scanning…';

  const verdict = document.getElementById('verdictBadge');
  verdict.style.removeProperty('--verdict-color');
  document.getElementById('verdictIcon').innerHTML = iconSvg('clock');
  document.getElementById('verdictText').textContent = 'SCANNING';
  document.getElementById('verdictMsg').textContent = 'Contacting the security scanner…';
}


// ---------------------------------------------------------
// REAL SCAN: QR upload -> jsQR decode -> backend /scan
// ---------------------------------------------------------

const API_BASE = "http://127.0.0.1:8000";

const fileInput = document.getElementById("fileInput");
const scannerDrop = document.getElementById("scannerDrop");

fileInput.addEventListener("change", (e) => {
  if (!e.target.files.length) return;
  handleQrFile(e.target.files[0]);
});

["dragover", "dragenter"].forEach(evt =>
  scannerDrop.addEventListener(evt, e => { e.preventDefault(); scannerDrop.classList.add('dragover'); })
);
["dragleave", "drop"].forEach(evt =>
  scannerDrop.addEventListener(evt, e => { e.preventDefault(); scannerDrop.classList.remove('dragover'); })
);
scannerDrop.addEventListener("drop", (e) => {
  if (e.dataTransfer.files.length) handleQrFile(e.dataTransfer.files[0]);
});

function handleQrFile(file){
  const img = new Image();
  const reader = new FileReader();
  reader.onload = ev => { img.src = ev.target.result; };
  reader.readAsDataURL(file);

  img.onload = () => {
    const canvas = document.getElementById("hiddenCanvas");
    canvas.width = img.width;
    canvas.height = img.height;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(img, 0, 0);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const decoded = jsQR(imageData.data, imageData.width, imageData.height);

    if (!decoded || !decoded.data) {
      alert("No QR code detected in that image. Try a clearer photo, or make sure the file you picked actually contains a QR code.");
      return;
    }
    scanWithBackend(decoded.data);
  };
  img.onerror = () => alert("That file does not look like a valid image.");
}

async function scanWithBackend(url){
  setScanning();
  document.getElementById("results")?.scrollIntoView({behavior:"smooth"});
  try {
    const resp = await fetch(API_BASE + "/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: url })
    });
    if (!resp.ok) throw new Error("Server responded with status " + resp.status);
    const data = await resp.json();
    renderCase(mapBackendToCase(data));
  } catch (err) {
    alert(
      "Could not reach the QR Safe Scanner backend at " + API_BASE +
      ". Make sure uvicorn is running.\n\n(" + err.message + ")"
    );
    document.getElementById("scanStatusText").textContent = "Backend unreachable";
  }
}

// Converts your FastAPI /scan response (verdict, score, sources.heuristics,
// sources.google_safe_browsing) into the shape renderCase() draws.
function mapBackendToCase(data){
  const level = (data.verdict || "Suspicious").toUpperCase();

  const styleByLevel = {
    SAFE:       { color: "var(--safe)",   glow: "var(--safe-glow)",   icon: "shield", actionLabel: "Continue Safely", actionColor: "var(--safe)",   gaugeLabel: "LOW RISK",    msg: "This QR code appears safe to visit." },
    SUSPICIOUS: { color: "var(--warn)",   glow: "var(--warn-glow)",   icon: "warn",   actionLabel: "Review URL",      actionColor: "var(--warn)",   gaugeLabel: "MEDIUM RISK", msg: "This QR code contains indicators that require caution." },
    DANGER:     { color: "var(--danger)", glow: "var(--danger-glow)", icon: "danger", actionLabel: "DO NOT OPEN",     actionColor: "var(--danger)", gaugeLabel: "HIGH RISK",   msg: "This QR code may lead to a malicious or phishing destination." }
  };
  const style = styleByLevel[level] || styleByLevel.SUSPICIOUS;

  const url = data.url || "";
  const heuristics = (data.sources && data.sources.heuristics) || {};
  const reasons = heuristics.reasons || [];

  let domain = url;
  try { domain = new URL(url).hostname; } catch(e){ /* leave as full url if it doesn't parse */ }

  const indicators = reasons.length
    ? reasons.map(r => ({ t: r, s: "warn" }))
    : [{ t: "No suspicious patterns detected", s: "pass" }];

  const gsb = data.sources && data.sources.google_safe_browsing;
  const secGrid = [
    { t: "HTTPS Connection", s: url.startsWith("https") ? "pass" : "warn" },
    { t: "IP Address Check", s: reasons.some(r => /ip address/i.test(r)) ? "fail" : "pass" },
    { t: "URL Length", s: reasons.some(r => /long url/i.test(r)) ? "warn" : "pass" },
    { t: "Keyword Pattern", s: reasons.some(r => /urgency|credential/i.test(r)) ? "warn" : "pass" },
    { t: "Google Safe Browsing", s: gsb && gsb.flagged ? "fail" : "pass" }
  ];

  return {
    verdict: level,
    ...style,
    score: typeof data.score === "number" ? data.score : 0,
    url,
    domain,
    protocol: url.startsWith("https") ? "HTTPS" : "HTTP",
    length: url.length + " characters",
    redirect: "Not checked",
    indicators,
    secGrid
  };
}