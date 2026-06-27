package challenge

// interstitialHTML is rendered with __C__ (token), __DIFF__ (difficulty),
// __TO__ (escaped return path) and __SUBMIT__ (verify path) substituted in.
// The browser solves a SHA-256 proof-of-work, then redirects to __SUBMIT__.
const interstitialHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Checking your browser…</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         display:flex; min-height:100vh; align-items:center; justify-content:center;
         margin:0; background:#0b1220; color:#e5e9f0; }
  .card { max-width:30rem; padding:2.5rem; text-align:center; }
  .spinner { width:2.5rem; height:2.5rem; margin:0 auto 1.25rem; border:3px solid #2b3650;
             border-top-color:#5b8cff; border-radius:50%; animation:spin 0.9s linear infinite; }
  @keyframes spin { to { transform:rotate(360deg); } }
  h1 { font-size:1.25rem; font-weight:600; margin:0 0 0.5rem; }
  p { color:#9aa6c0; font-size:0.9rem; margin:0.25rem 0; }
  code { color:#7d8bb0; font-size:0.75rem; }
</style>
</head>
<body data-c="__C__" data-diff="__DIFF__" data-to="__TO__" data-submit="__SUBMIT__">
  <div class="card">
    <div class="spinner"></div>
    <h1>Checking your browser</h1>
    <p>This automated check verifies you are not a bot. It takes a moment and runs once.</p>
    <p><code>proof-of-work · attempts <span id="n">0</span></code></p>
    <noscript><p>JavaScript is required to complete this check.</p></noscript>
  </div>
<script>
(function(){
  var b = document.body.dataset;
  var C = b.c, DIFF = parseInt(b.diff, 10), TO = b.to, SUBMIT = b.submit;
  function lz(buf){
    var n = 0, v = new Uint8Array(buf);
    for (var i = 0; i < v.length; i++){
      var x = v[i];
      if (x === 0){ n += 8; continue; }
      var c = 0, t = x;
      while ((t & 0x80) === 0){ c++; t = (t << 1) & 0xff; }
      n += c; break;
    }
    return n;
  }
  async function solve(){
    var enc = new TextEncoder(), nonce = 0;
    while (true){
      var d = await crypto.subtle.digest('SHA-256', enc.encode(C + nonce));
      if (lz(d) >= DIFF) return nonce;
      nonce++;
      if ((nonce & 1023) === 0){
        document.getElementById('n').textContent = nonce;
        await new Promise(function(r){ setTimeout(r, 0); });
      }
    }
  }
  solve().then(function(nonce){
    window.location = SUBMIT + '?c=' + encodeURIComponent(C) + '&nonce=' + nonce + '&to=' + encodeURIComponent(TO);
  });
})();
</script>
</body>
</html>`

// captchaHTML renders a pluggable CAPTCHA widget. __SCRIPT__ (provider api.js),
// __WIDGET__ (widget element class), __SITEKEY__, __SUBMIT__ (verify path) and
// __TO__ (escaped return path) are substituted in. The widget's callback
// auto-submits the form, whose POST carries the provider response field.
const captchaHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verify you are human</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         display:flex; min-height:100vh; align-items:center; justify-content:center;
         margin:0; background:#0b1220; color:#e5e9f0; }
  .card { max-width:30rem; padding:2.5rem; text-align:center; }
  h1 { font-size:1.25rem; font-weight:600; margin:0 0 0.5rem; }
  p { color:#9aa6c0; font-size:0.9rem; margin:0.25rem 0 1.25rem; }
  .widget { display:flex; justify-content:center; }
</style>
<script src="__SCRIPT__" async defer></script>
</head>
<body>
  <div class="card">
    <h1>Verify you are human</h1>
    <p>Complete the check below to continue.</p>
    <form id="aegis-cap" method="POST" action="__SUBMIT__?to=__TO__">
      <div class="widget __WIDGET__" data-sitekey="__SITEKEY__" data-callback="aegisCaptchaDone"></div>
      <noscript><p>JavaScript is required to complete this check.</p></noscript>
    </form>
  </div>
<script>
  function aegisCaptchaDone(){ document.getElementById('aegis-cap').submit(); }
</script>
</body>
</html>`
