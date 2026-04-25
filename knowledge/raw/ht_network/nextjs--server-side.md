# NextJS - Server Side

## Server-Side in Next.js


### Server-Side Rendering (SSR)

Pages are rendered on the server on each request, ensuring that the user receives fully rendered HTML. In this case you should create your own custom server to process the requests.

**Use Cases:**

- Dynamic content that changes frequently.
- SEO optimization, as search engines can crawl the fully rendered page.

**Implementation:**

```jsx
// pages/index.js
export async function getServerSideProps(context) {
  const res = await fetch("https://api.example.com/data")
  const data = await res.json()
  return { props: { data } }
}

function HomePage({ data }) {
  return <div>{data.title}</div>
}

export default HomePage
```

### Static Site Generation (SSG)

Pages are pre-rendered at build time, resulting in faster load times and reduced server load.

**Use Cases:**

- Content that doesn't change frequently.
- Blogs, documentation, marketing pages.

**Implementation:**

```jsx
// pages/index.js
export async function getStaticProps() {
  const res = await fetch("https://api.example.com/data")
  const data = await res.json()
  return { props: { data }, revalidate: 60 } // Revalidate every 60 seconds
}

function HomePage({ data }) {
  return <div>{data.title}</div>
}

export default HomePage
```

### Serverless Functions (API Routes)

Next.js allows the creation of API endpoints as serverless functions. These functions run on-demand without the need for a dedicated server.

**Use Cases:**

- Handling form submissions.
- Interacting with databases.
- Processing data or integrating with third-party APIs.

**Implementation:**

With the introduction of the `app` directory in Next.js 13, routing and API handling have become more flexible and powerful. This modern approach aligns closely with the file-based routing system but introduces enhanced capabilities, including support for server and client components.

#### Basic Route Handler

**File Structure:**

```go
my-nextjs-app/
├── app/
│   └── api/
│       └── hello/
│           └── route.js
├── package.json
└── ...
```

**Implementation:**

```javascript
// app/api/hello/route.js

export async function POST(request) {
  return new Response(JSON.stringify({ message: "Hello from App Router!" }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  })
}

// Client-side fetch to access the API endpoint
fetch("/api/submit", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name: "John Doe" }),
})
  .then((res) => res.json())
  .then((data) => console.log(data))
```

**Explanation:**

- **Location:** API routes are placed under the `app/api/` directory.
- **File Naming:** Each API endpoint resides in its own folder containing a `route.js` or `route.ts` file.
- **Exported Functions:** Instead of a single default export, specific HTTP method functions (e.g., `GET`, `POST`) are exported.
- **Response Handling:** Use the `Response` constructor to return responses, allowing more control over headers and status codes.

#### How to handle other paths and methods:

<details>

<summary>Handling Specific HTTP Methods</summary>

Next.js 13+ allows you to define handlers for specific HTTP methods within the same `route.js` or `route.ts` file, promoting clearer and more organized code.

**Example:**

```javascript
// app/api/users/[id]/route.js

export async function GET(request, { params }) {
  const { id } = params
  // Fetch user data based on 'id'
  return new Response(JSON.stringify({ userId: id, name: "Jane Doe" }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  })
}

export async function PUT(request, { params }) {
  const { id } = params
  // Update user data based on 'id'
  return new Response(JSON.stringify({ message: `User ${id} updated.` }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  })
}

export async function DELETE(request, { params }) {
  const { id } = params
  // Delete user based on 'id'
  return new Response(JSON.stringify({ message: `User ${id} deleted.` }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  })
}
```

**Explanation:**

- **Multiple Exports:** Each HTTP method (`GET`, `PUT`, `DELETE`) has its own exported function.
- **Parameters:** The second argument provides access to route parameters via `params`.
- **Enhanced Responses:** Greater control over response objects, enabling precise header and status code management.

</details>

<details>

<summary>Catch-All and Nested Routes</summary>

Next.js 13+ supports advanced routing features like catch-all routes and nested API routes, allowing for more dynamic and scalable API structures.

**Catch-All Route Example:**

```javascript
// app/api/[...slug]/route.js

export async function GET(request, { params }) {
  const { slug } = params
  // Handle dynamic nested routes
  return new Response(JSON.stringify({ slug }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  })
}
```

**Explanation:**

- **Syntax:** `[...]` denotes a catch-all segment, capturing all nested paths.
- **Usage:** Useful for APIs that need to handle varying route depths or dynamic segments.

**Nested Routes Example:**

```javascript
// app/api/posts/[postId]/comments/[commentId]/route.js

export async function GET(request, { params }) {
  const { postId, commentId } = params
  // Fetch specific comment for a post
  return new Response(
    JSON.stringify({ postId, commentId, comment: "Great post!" }),
    {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }
  )
}
```

**Explanation:**

- **Deep Nesting:** Allows for hierarchical API structures, reflecting resource relationships.
- **Parameter Access:** Easily access multiple route parameters via the `params` object.

</details>

<details>

<summary>Handling API routes in Next.js 12 and Earlier</summary>
