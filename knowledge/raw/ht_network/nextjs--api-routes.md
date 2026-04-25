# NextJS - Api Routes

## API Routes in the `pages` Directory (Next.js 12 and Earlier)


Before Next.js 13 introduced the `app` directory and enhanced routing capabilities, API routes were primarily defined within the `pages` directory. This approach is still widely used and supported in Next.js 12 and earlier versions.

#### Basic API Route

**File Structure:**

```go
goCopy codemy-nextjs-app/
├── pages/
│   └── api/
│       └── hello.js
├── package.json
└── ...
```

**Implementation:**

```javascript
javascriptCopy code// pages/api/hello.js

export default function handler(req, res) {
  res.status(200).json({ message: 'Hello, World!' });
}
```

**Explanation:**

- **Location:** API routes reside under the `pages/api/` directory.
- **Export:** Use `export default` to define the handler function.
- **Function Signature:** The handler receives `req` (HTTP request) and `res` (HTTP response) objects.
- **Routing:** The file name (`hello.js`) maps to the endpoint `/api/hello`.

#### Dynamic API Routes

**File Structure:**

```bash
bashCopy codemy-nextjs-app/
├── pages/
│   └── api/
│       └── users/
│           └── [id].js
├── package.json
└── ...
```

**Implementation:**

```javascript
javascriptCopy code// pages/api/users/[id].js

export default function handler(req, res) {
  const {
    query: { id },
    method,
  } = req;

  switch (method) {
    case 'GET':
      // Fetch user data based on 'id'
      res.status(200).json({ userId: id, name: 'John Doe' });
      break;
    case 'PUT':
      // Update user data based on 'id'
      res.status(200).json({ message: `User ${id} updated.` });
      break;
    case 'DELETE':
      // Delete user based on 'id'
      res.status(200).json({ message: `User ${id} deleted.` });
      break;
    default:
      res.setHeader('Allow', ['GET', 'PUT', 'DELETE']);
      res.status(405).end(`Method ${method} Not Allowed`);
  }
}
```

**Explanation:**

- **Dynamic Segments:** Square brackets (`[id].js`) denote dynamic route segments.
- **Accessing Parameters:** Use `req.query.id` to access the dynamic parameter.
- **Handling Methods:** Utilize conditional logic to handle different HTTP methods (`GET`, `PUT`, `DELETE`, etc.).

#### Handling Different HTTP Methods

While the basic API route example handles all HTTP methods within a single function, you can structure your code to handle each method explicitly for better clarity and maintainability.

**Example:**

```javascript
javascriptCopy code// pages/api/posts.js

export default async function handler(req, res) {
  const { method } = req;

  switch (method) {
    case 'GET':
      // Handle GET request
      res.status(200).json({ message: 'Fetching posts.' });
      break;
    case 'POST':
      // Handle POST request
      res.status(201).json({ message: 'Post created.' });
      break;
    default:
      res.setHeader('Allow', ['GET', 'POST']);
      res.status(405).end(`Method ${method} Not Allowed`);
  }
}
```

**Best Practices:**

- **Separation of Concerns:** Clearly separate logic for different HTTP methods.
- **Response Consistency:** Ensure consistent response structures for ease of client-side handling.
- **Error Handling:** Gracefully handle unsupported methods and unexpected errors.

</details>

### CORS Configuration

Control which origins can access your API routes, mitigating Cross-Origin Resource Sharing (CORS) vulnerabilities.

**Bad Configuration Example:**

```javascript
// app/api/data/route.js

export async function GET(request) {
  return new Response(JSON.stringify({ data: "Public Data" }), {
    status: 200,
    headers: {
      "Access-Control-Allow-Origin": "*", // Allows any origin
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
    },
  })
}
```

Note that **CORS can also be configured in all the API routes** inside the **`middleware.ts`** file:

```javascript
// app/middleware.ts

import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"

export function middleware(request: NextRequest) {
  const allowedOrigins = [
    "https://yourdomain.com",
    "https://sub.yourdomain.com",
  ]
  const origin = request.headers.get("Origin")

  const response = NextResponse.next()

  if (allowedOrigins.includes(origin || "")) {
    response.headers.set("Access-Control-Allow-Origin", origin || "")
    response.headers.set(
      "Access-Control-Allow-Methods",
      "GET, POST, PUT, DELETE, OPTIONS"
    )
    response.headers.set(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization"
    )
    // If credentials are needed:
    // response.headers.set('Access-Control-Allow-Credentials', 'true');
  }

  // Handle preflight requests
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: response.headers,
    })
  }

  return response
}

export const config = {
  matcher: "/api/:path*", // Apply to all API routes
}
```

**Problem:**

- **`Access-Control-Allow-Origin: '*'`:** Permits any website to access the API, potentially allowing malicious sites to interact with your API without restrictions.
- **Wide Method Allowance:** Allowing all methods can enable attackers to perform unwanted actions.

**How attackers exploit it:**

Attackers can craft malicious websites that make requests to your API, potentially abusing functionalities like data retrieval, data manipulation, or triggering unwanted actions on behalf of authenticated users.

### Server code exposure in Client Side

It's can easy to **use code used by the server also in code exposed and used by the client side**, the best way to ensure that a file of code is never exposed in the client side is by using this import at the beginning of the file:

```js
import "server-only"
```
