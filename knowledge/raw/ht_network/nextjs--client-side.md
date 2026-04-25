# NextJS - Client Side

## Client-Side in Next.js


### File-Based Routing in the `app` Directory

The `app` directory is the cornerstone of routing in the latest Next.js versions. It leverages the filesystem to define routes, making route management intuitive and scalable.

<details>

<summary>Handling the Root Path /</summary>

**File Structure:**

```arduino
my-nextjs-app/
├── app/
│   ├── layout.tsx
│   └── page.tsx
├── public/
├── next.config.js
└── ...
```

**Key Files:**

- **`app/page.tsx`**: Handles requests to the root path `/`.
- **`app/layout.tsx`**: Defines the layout for the application, wrapping around all pages.

**Implementation:**

```tsx
tsxCopy code// app/page.tsx

export default function HomePage() {
  return (
    <div>
      <h1>Welcome to the Home Page!</h1>
      <p>This is the root route.</p>
    </div>
  );
}
```

**Explanation:**

- **Route Definition:** The `page.tsx` file directly under the `app` directory corresponds to the `/` route.
- **Rendering:** This component renders the content for the home page.
- **Layout Integration:** The `HomePage` component is wrapped by the `layout.tsx`, which can include headers, footers, and other common elements.

</details>

<details>

<summary>Handling Other Static Paths</summary>

**Example: `/about` Route**

**File Structure:**

```arduino
arduinoCopy codemy-nextjs-app/
├── app/
│   ├── about/
│   │   └── page.tsx
│   ├── layout.tsx
│   └── page.tsx
├── public/
├── next.config.js
└── ...
```

**Implementation:**

```tsx
// app/about/page.tsx

export default function AboutPage() {
  return (
    <div>
      <h1>About Us</h1>
      <p>Learn more about our mission and values.</p>
    </div>
  )
}
```

**Explanation:**

- **Route Definition:** The `page.tsx` file inside the `about` folder corresponds to the `/about` route.
- **Rendering:** This component renders the content for the about page.

</details>

<details>

<summary>Dynamic Routes</summary>

Dynamic routes allow handling paths with variable segments, enabling applications to display content based on parameters like IDs, slugs, etc.

**Example: `/posts/[id]` Route**

**File Structure:**

```arduino
arduinoCopy codemy-nextjs-app/
├── app/
│   ├── posts/
│   │   └── [id]/
│   │       └── page.tsx
│   ├── layout.tsx
│   └── page.tsx
├── public/
├── next.config.js
└── ...
```

**Implementation:**

```tsx
tsxCopy code// app/posts/[id]/page.tsx

import { useRouter } from 'next/navigation';

interface PostProps {
  params: { id: string };
}

export default function PostPage({ params }: PostProps) {
  const { id } = params;
  // Fetch post data based on 'id'

  return (
    <div>
      <h1>Post #{id}</h1>
      <p>This is the content of post {id}.</p>
    </div>
  );
}
```

**Explanation:**

- **Dynamic Segment:** `[id]` denotes a dynamic segment in the route, capturing the `id` parameter from the URL.
- **Accessing Parameters:** The `params` object contains the dynamic parameters, accessible within the component.
- **Route Matching:** Any path matching `/posts/*`, such as `/posts/1`, `/posts/abc`, etc., will be handled by this component.

</details>

<details>

<summary>Nested Routes</summary>

Next.js supports nested routing, allowing for hierarchical route structures that mirror the directory layout.

**Example: `/dashboard/settings/profile` Route**

**File Structure:**

```arduino
arduinoCopy codemy-nextjs-app/
├── app/
│   ├── dashboard/
│   │   ├── settings/
│   │   │   └── profile/
│   │   │       └── page.tsx
│   │   └── page.tsx
│   ├── layout.tsx
│   └── page.tsx
├── public/
├── next.config.js
└── ...
```

**Implementation:**

```tsx
tsxCopy code// app/dashboard/settings/profile/page.tsx

export default function ProfileSettingsPage() {
  return (
    <div>
      <h1>Profile Settings</h1>
      <p>Manage your profile information here.</p>
    </div>
  );
}
```

**Explanation:**

- **Deep Nesting:** The `page.tsx` file inside `dashboard/settings/profile/` corresponds to the `/dashboard/settings/profile` route.
- **Hierarchy Reflection:** The directory structure reflects the URL path, enhancing maintainability and clarity.

</details>

<details>

<summary>Catch-All Routes</summary>

Catch-all routes handle multiple nested segments or unknown paths, providing flexibility in route handling.

**Example: `/*` Route**

**File Structure:**

```arduino
my-nextjs-app/
├── app/
│   ├── [...slug]/
│   │   └── page.tsx
│   ├── layout.tsx
│   └── page.tsx
├── public/
├── next.config.js
└── ...
```

**Implementation:**

```tsx
// app/[...slug]/page.tsx

interface CatchAllProps {
  params: { slug: string[] }
}

export default function CatchAllPage({ params }: CatchAllProps) {
  const { slug } = params
  const fullPath = `/${slug.join("/")}`

  return (
    <div>
      <h1>Catch-All Route</h1>
      <p>You have navigated to: {fullPath}</p>
    </div>
  )
}
```

**Explanation:**

- **Catch-All Segment:** `[...slug]` captures all remaining path segments as an array.
- **Usage:** Useful for handling dynamic routing scenarios like user-generated paths, nested categories, etc.
- **Route Matching:** Paths like `/anything/here`, `/foo/bar/baz`, etc., are handled by this component.

</details>

### Potential Client-Side Vulnerabilities

While Next.js provides a secure foundation, improper coding practices can introduce vulnerabilities. Key client-side vulnerabilities include:

<details>

<summary>Cross-Site Scripting (XSS)</summary>

XSS attacks occur when malicious scripts are injected into trusted websites. Attackers can execute scripts in users' browsers, stealing data or performing actions on behalf of the user.

**Example of Vulnerable Code:**

```jsx
// Dangerous: Injecting user input directly into HTML
function Comment({ userInput }) {
  return <div dangerouslySetInnerHTML={{ __html: userInput }} />
}
```

**Why It's Vulnerable:** Using `dangerouslySetInnerHTML` with untrusted input allows attackers to inject malicious scripts.

</details>

<details>

<summary>Client-Side Template Injection</summary>

Occurs when user inputs are improperly handled in templates, allowing attackers to inject and execute templates or expressions.

**Example of Vulnerable Code:**

```jsx
import React from "react"
import ejs from "ejs"

function RenderTemplate({ template, data }) {
  const html = ejs.render(template, data)
  return <div dangerouslySetInnerHTML={{ __html: html }} />
}
```

**Why It's Vulnerable:** If `template` or `data` includes malicious content, it can lead to execution of unintended code.

</details>

<details>

<summary>Client Path Traversal</summary>

It's a vulnerability that allows attackers to manipulate client-side paths to perform unintended actions, such as Cross-Site Request Forgery (CSRF). Unlike server-side path traversal, which targets the server's filesystem, CSPT focuses on exploiting client-side mechanisms to reroute legitimate API requests to malicious endpoints.

**Example of Vulnerable Code:**

A Next.js application allows users to upload and download files. The download feature is implemented on the client side, where users can specify the file path to download.

```jsx
// pages/download.js
import { useState } from "react"

export default function DownloadPage() {
  const [filePath, setFilePath] = useState("")

  const handleDownload = () => {
    fetch(`/api/files/${filePath}`)
      .then((response) => response.blob())
      .then((blob) => {
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement("a")
        a.href = url
        a.download = filePath
        a.click()
      })
  }

  return (
    <div>
      <h1>Download File</h1>
      <input
        type="text"
        value={filePath}
        onChange={(e) => setFilePath(e.target.value)}
        placeholder="Enter file path"
      />
      <button onClick={handleDownload}>Download</button>
    </div>
  )
}
```

#### Attack Scenario

1. **Attacker's Objective**: Perform a CSRF attack to delete a critical file (e.g., `admin/config.json`) by manipulating the `filePath`.
2. **Exploiting CSPT**:
   - **Malicious Input**: The attacker crafts a URL with a manipulated `filePath` such as `../deleteFile/config.json`.
   - **Resulting API Call**: The client-side code makes a request to `/api/files/../deleteFile/config.json`.
   - **Server's Handling**: If the server does not validate the `filePath`, it processes the request, potentially deleting or exposing sensitive files.
3. **Executing CSRF**:
   - **Crafted Link**: The attacker sends the victim a link or embeds a malicious script that triggers the download request with the manipulated `filePath`.
   - **Outcome**: The victim unknowingly executes the action, leading to unauthorized file access or deletion.

#### Why It's Vulnerable

- **Lack of Input Validation**: The client-side allows arbitrary `filePath` inputs, enabling path traversal.
- **Trusting Client Inputs**: The server-side API trusts and processes the `filePath` without sanitization.
- **Potential API Actions**: If the API endpoint performs state-changing actions (e.g., delete, modify files), it can be exploited via CSPT.

</details>

### Recon: static export route discovery via _buildManifest

When `nextExport`/`autoExport` are true (static export), Next.js exposes the `buildId` in the HTML and serves a build manifest at `/_next/static/<buildId>/_buildManifest.js`. The `sortedPages` array and route→chunk mapping there enumerate every prerendered page without brute force.

- Grab the buildId from the root response (often printed at the bottom) or from `<script>` tags loading `/_next/static/<buildId>/...`.
- Fetch the manifest and extract routes:

```bash
build=$(curl -s http://target/ | grep -oE '"buildId":"[^"]+"' | cut -d: -f2 | tr -d '"')
curl -s "http://target/_next/static/${build}/_buildManifest.js" | grep -oE '"(/[a-zA-Z0-9_\[\]\-/]+)"' | tr -d '"'
```

- Use the discovered paths (for example `/docs`, `/docs/content/examples`, `/signin`) to drive auth testing and endpoint discovery.
