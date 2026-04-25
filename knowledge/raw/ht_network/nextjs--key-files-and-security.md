# NextJS - Key Files And Security

## Key Files and Their Roles


### `middleware.ts` / `middleware.js`

**Location:** Root of the project or within `src/`.

**Purpose:** Executes code in the server-side serverless function before a request is processed, allowing for tasks like authentication, redirects, or modifying responses.

**Execution Flow:**

1. **Incoming Request:** The middleware intercepts the request.
2. **Processing:** Performs operations based on the request (e.g., check authentication).
3. **Response Modification:** Can alter the response or pass control to the next handler.

**Example Use Cases:**

- Redirecting unauthenticated users.
- Adding custom headers.
- Logging requests.

**Sample Configuration:**

```typescript
// middleware.ts
import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"

export function middleware(req: NextRequest) {
  const url = req.nextUrl.clone()
  if (!req.cookies.has("token")) {
    url.pathname = "/login"
    return NextResponse.redirect(url)
  }
  return NextResponse.next()
}

export const config = {
  matcher: ["/protected/:path*"],
}
```

### Middleware authorization bypass (CVE-2025-29927)

If authorization is enforced in middleware, affected Next.js releases (<12.3.5 / 13.5.9 / 14.2.25 / 15.2.3) can be bypassed by injecting the `x-middleware-subrequest` header. The framework will skip middleware recursion and return the protected page.

- Baseline behavior is typically a 307 redirect to a login route like `/api/auth/signin`.
- Send a long `x-middleware-subrequest` value (repeat `middleware` to hit `MAX_RECURSION_DEPTH`) to flip the response to 200:

```bash
curl -i "http://target/docs" \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware"
```

- Because authenticated pages pull many subresources, add the header to every request (e.g., Burp Match/Replace with an empty match string) to keep assets from redirecting.

### `next.config.js`

**Location:** Root of the project.

**Purpose:** Configures Next.js behavior, enabling or disabling features, customizing webpack configurations, setting environment variables, and configuring several security features.

**Key Security Configurations:**

<details>

<summary>Security Headers</summary>

Security headers enhance the security of your application by instructing browsers on how to handle content. They help mitigate various attacks like Cross-Site Scripting (XSS), Clickjacking, and MIME type sniffing:

- Content Security Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security (HSTS)
- Referrer Policy

**Examples:**

```javascript
// next.config.js

module.exports = {
  async headers() {
    return [
      {
        source: "/(.*)", // Apply to all routes
        headers: [
          {
            key: "X-Frame-Options",
            value: "DENY",
          },
          {
            key: "Content-Security-Policy",
            value:
              "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval';",
          },
          {
            key: "X-Content-Type-Options",
            value: "nosniff",
          },
          {
            key: "Strict-Transport-Security",
            value: "max-age=63072000; includeSubDomains; preload", // Enforces HTTPS
          },
          {
            key: "Referrer-Policy",
            value: "no-referrer", // Completely hides referrer
          },
          // Additional headers...
        ],
      },
    ]
  },
}
```

</details>

<details>

<summary>Image Optimization Settings</summary>

Next.js optimizes images for performance, but misconfigurations can lead to security vulnerabilities, such as allowing untrusted sources to inject malicious content.

**Bad Configuration Example:**

```javascript
// next.config.js

module.exports = {
  images: {
    domains: ["*"], // Allows images from any domain
  },
}
```

**Problem:**

- **`'*'`:** Permits images to be loaded from any external source, including untrusted or malicious domains. Attackers can host images containing malicious payloads or content that misleads users.
- Another problem might be to allow a domain **where anyone can upload an image** (like `raw.githubusercontent.com`)

**How attackers abuse it:**

By injecting images from malicious sources, attackers can perform phishing attacks, display misleading information, or exploit vulnerabilities in image rendering libraries.

</details>

<details>

<summary>Environment Variables Exposure</summary>

Manage sensitive information like API keys and database credentials securely without exposing them to the client.

#### a. Exposing Sensitive Variables

**Bad Configuration Example:**

```javascript
// next.config.js

module.exports = {
  env: {
    SECRET_API_KEY: process.env.SECRET_API_KEY, // Not exposed to the client
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL, // Correctly prefixed for exposure to client
  },
}
```

**Problem:**

- **`SECRET_API_KEY`:** Without the `NEXT_PUBLIC_` prefix, Next.js does not expose variables to the client. However, if mistakenly prefixed (e.g., `NEXT_PUBLIC_SECRET_API_KEY`), it becomes accessible on the client side.

**How attackers abuse it:**

If sensitive variables are exposed to the client, attackers can retrieve them by inspecting the client-side code or network requests, gaining unauthorized access to APIs, databases, or other services.

</details>

<details>

<summary>Redirects</summary>

Manage URL redirections and rewrites within your application, ensuring that users are directed appropriately without introducing open redirect vulnerabilities.

#### a. Open Redirect Vulnerability

**Bad Configuration Example:**

```javascript
// next.config.js

module.exports = {
  async redirects() {
    return [
      {
        source: "/redirect",
        destination: (req) => req.query.url, // Dynamically redirects based on query parameter
        permanent: false,
      },
    ]
  },
}
```

**Problem:**

- **Dynamic Destination:** Allows users to specify any URL, enabling open redirect attacks.
- **Trusting User Input:** Redirects to URLs provided by users without validation can lead to phishing, malware distribution, or credential theft.

**How attackers abuse it:**

Attackers can craft URLs that appear to originate from your domain but redirect users to malicious sites. For example:

```bash
https://yourdomain.com/redirect?url=https://malicious-site.com
```

Users trusting the original domain might unknowingly navigate to harmful websites.

</details>

<details>

<summary>Webpack Configuration</summary>

Customize Webpack configurations for your Next.js application, which can inadvertently introduce security vulnerabilities if not handled cautiously.

#### a. Exposing Sensitive Modules

**Bad Configuration Example:**

```javascript
// next.config.js

module.exports = {
  webpack: (config, { isServer }) => {
    if (!isServer) {
      config.resolve.alias["@sensitive"] = path.join(__dirname, "secret-folder")
    }
    return config
  },
}
```

**Problem:**

- **Exposing Sensitive Paths:** Aliasing sensitive directories and allowing client-side access can leak confidential information.
- **Bundling Secrets:** If sensitive files are bundled for the client, their contents become accessible through source maps or inspecting the client-side code.

**How attackers abuse it:**

Attackers can access or reconstruct the application's directory structure, potentially finding and exploiting sensitive files or data.

</details>

### `pages/_app.js` and `pages/_document.js`

#### **`pages/_app.js`**

**Purpose:** Overrides the default App component, allowing for global state, styles, and layout components.

**Use Cases:**

- Injecting global CSS.
- Adding layout wrappers.
- Integrating state management libraries.

**Example:**

```jsx
// pages/_app.js
import "../styles/globals.css"

function MyApp({ Component, pageProps }) {
  return <Component {...pageProps} />
}

export default MyApp
```

#### **`pages/_document.js`**

**Purpose:** Overrides the default Document, enabling customization of the HTML and Body tags.

**Use Cases:**

- Modifying the `<html>` or `<body>` tags.
- Adding meta tags or custom scripts.
- Integrating third-party fonts.

**Example:**

```jsx
// pages/_document.js
import Document, { Html, Head, Main, NextScript } from "next/document"

class MyDocument extends Document {
  render() {
    return (
      <Html lang="en">
        <Head>{/* Custom fonts or meta tags */}</Head>
        <body>
          <Main />
          <NextScript />
        </body>
      </Html>
    )
  }
}

export default MyDocument
```

### Custom Server (Optional)

**Purpose:** While Next.js comes with a built-in server, you can create a custom server for advanced use cases like custom routing or integrating with existing backend services.

**Note:** Using a custom server can limit deployment options, especially on platforms like Vercel that optimize for Next.js's built-in server.

**Example:**

```javascript
// server.js
const express = require("express")
const next = require("next")

const dev = process.env.NODE_ENV !== "production"
const app = next({ dev })
const handle = app.getRequestHandler()

app.prepare().then(() => {
  const server = express()

  // Custom route
  server.get("/a", (req, res) => {
    return app.render(req, res, "/a")
  })

  // Default handler
  server.all("*", (req, res) => {
    return handle(req, res)
  })

  server.listen(3000, (err) => {
    if (err) throw err
    console.log("> Ready on http://localhost:3000")
  })
})
```

---


## Additional Architectural and Security Considerations


### Environment Variables and Configuration

**Purpose:** Manage sensitive information and configuration settings outside of the codebase.

**Best Practices:**

- **Use `.env` Files:** Store variables like API keys in `.env.local` (excluded from version control).
- **Access Variables Securely:** Use `process.env.VARIABLE_NAME` to access environment variables.
- **Never Expose Secrets on the Client:** Ensure that sensitive variables are only used server-side.

**Example:**

```javascript
// next.config.js
module.exports = {
  env: {
    API_KEY: process.env.API_KEY, // Accessible on both client and server
    SECRET_KEY: process.env.SECRET_KEY, // Be cautious if accessible on the client
  },
}
```

**Note:** To restrict variables to server-side only, omit them from the `env` object or prefix them with `NEXT_PUBLIC_` for client exposure.

### Useful server artifacts to target via LFI/download endpoints

If you find a path traversal or download API in a Next.js app, target compiled artifacts that leak server-side secrets and auth logic:

- `.env` / `.env.local` for session secrets and provider credentials.
- `.next/routes-manifest.json` and `.next/build-manifest.json` for a complete route list.
- `.next/server/pages/api/auth/[...nextauth].js` to recover the compiled NextAuth configuration (often contains fallback passwords when `process.env` values are unset).
- `next.config.js` / `next.config.mjs` to review rewrites, redirects and middleware routing.

### Authentication and Authorization

**Approach:**

- **Session-Based Authentication:** Use cookies to manage user sessions.
- **Token-Based Authentication:** Implement JWTs for stateless authentication.
- **Third-Party Providers:** Integrate with OAuth providers (e.g., Google, GitHub) using libraries like `next-auth`.

**Security Practices:**

- **Secure Cookies:** Set `HttpOnly`, `Secure`, and `SameSite` attributes.
- **Password Hashing:** Always hash passwords before storing them.
- **Input Validation:** Prevent injection attacks by validating and sanitizing inputs.

**Example:**

```javascript
// pages/api/login.js
import { sign } from "jsonwebtoken"
import { serialize } from "cookie"

export default async function handler(req, res) {
  const { username, password } = req.body

  // Validate user credentials
  if (username === "admin" && password === "password") {
    const token = sign({ username }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    })
    res.setHeader(
      "Set-Cookie",
      serialize("auth", token, {
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "strict",
      })
    )
    res.status(200).json({ message: "Logged in" })
  } else {
    res.status(401).json({ error: "Invalid credentials" })
  }
}
```

### Performance Optimization

**Strategies:**

- **Image Optimization:** Use Next.js's `next/image` component for automatic image optimization.
- **Code Splitting:** Leverage dynamic imports to split code and reduce initial load times.
- **Caching:** Implement caching strategies for API responses and static assets.
- **Lazy Loading:** Load components or assets only when they are needed.

**Example:**

```jsx
// Dynamic Import with Code Splitting
import dynamic from "next/dynamic"

const HeavyComponent = dynamic(() => import("../components/HeavyComponent"), {
  loading: () => <p>Loading...</p>,
})
```


## References


- [Pentesting Next.js Server Actions — A Burp Extension for Hash-to-Function Mapping](https://www.adversis.io/blogs/pentesting-next-js-server-actions)
- [NextjsServerActionAnalyzer (Burp extension)](https://github.com/Adversis/NextjsServerActionAnalyzer)
- [CVE-2025-55182 React Server Components Remote Code Execution Exploit Tool](https://github.com/Spritualkb/CVE-2025-55182-exp)
- [CVE-2025-55182 & CVE-2025-66478 React2Shell – All You Need to Know](https://jfrog.com/blog/2025-55182-and-2025-66478-react2shell-all-you-need-to-know/)
- [0xdf – HTB Previous (Next.js middleware bypass, static export recon, NextAuth config leak)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [assetnote/react2shell-scanner](https://github.com/assetnote/react2shell-scanner)
- [Next.js Security Update: December 11, 2025 (CVE-2025-55183/55184/67779)](https://nextjs.org/blog/security-update-2025-12-11)
- [GHSA-r2fc-ccr8-96c4 / CVE-2025-49005: App Router cache poisoning](https://github.com/advisories/GHSA-r2fc-ccr8-96c4)
