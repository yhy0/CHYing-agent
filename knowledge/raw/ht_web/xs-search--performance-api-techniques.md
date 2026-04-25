# XS-Search/XS-Leaks - Performance Api Techniques

## Performance API Techniques


The [`Performance API`](https://developer.mozilla.org/en-US/docs/Web/API/Performance) offers insights into the performance metrics of web applications, further enriched by the [`Resource Timing API`](https://developer.mozilla.org/en-US/docs/Web/API/Resource_Timing_API). The Resource Timing API enables the monitoring of detailed network request timings, such as the duration of the requests. Notably, when servers include the `Timing-Allow-Origin: *` header in their responses, additional data like the transfer size and domain lookup time becomes available.

This wealth of data can be retrieved via methods like [`performance.getEntries`](https://developer.mozilla.org/en-US/docs/Web/API/Performance/getEntries) or [`performance.getEntriesByName`](https://developer.mozilla.org/en-US/docs/Web/API/Performance/getEntriesByName), providing a comprehensive view of performance-related information. Additionally, the API facilitates the measurement of execution times by calculating the difference between timestamps obtained from [`performance.now()`](https://developer.mozilla.org/en-US/docs/Web/API/Performance/now). However, it's worth noting that for certain operations in browsers like Chrome, the precision of `performance.now()` may be limited to milliseconds, which could affect the granularity of timing measurements.

Beyond timing measurements, the Performance API can be leveraged for security-related insights. For instance, the presence or absence of pages in the `performance` object in Chrome can indicate the application of `X-Frame-Options`. Specifically, if a page is blocked from rendering in a frame due to `X-Frame-Options`, it will not be recorded in the `performance` object, providing a subtle clue about the page's framing policies.

### Error Leak

- **Inclusion Methods**: Frames, HTML Elements
- **Detectable Difference**: Status Code
- **More info**: [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf) (5.2)
- **Summary:** A request that results in errors will not create a resource timing entry.
- **Code Example**: [https://xsinator.com/testing.html#Performance%20API%20Error%20Leak](https://xsinator.com/testing.html#Performance%20API%20Error%20Leak)

It is possible to **differentiate between HTTP response status codes** because requests that lead to an **error** do **not create a performance entry**.

### Style Reload Error

- **Inclusion Methods**: HTML Elements
- **Detectable Difference**: Status Code
- **More info**: [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf) (5.2)
- **Summary:** Due to a browser bug, requests that result in errors are loaded twice.
- **Code Example**: [https://xsinator.com/testing.html#Style%20Reload%20Error%20Leak](https://xsinator.com/testing.html#Style%20Reload%20Error%20Leak)

In the previous technique it was also identified two cases where browser bugs in GC lead to **resources being loaded twice when they fail to load**. This will result in multiple entries in the Performance API and can thus be detected.

### Request Merging Error

- **Inclusion Methods**: HTML Elements
- **Detectable Difference**: Status Code
- **More info**: [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf) (5.2)
- **Summary:** Requests that result in an error can not be merged.
- **Code Example**: [https://xsinator.com/testing.html#Request%20Merging%20Error%20Leak](https://xsinator.com/testing.html#Request%20Merging%20Error%20Leak)

The technique was found in a table in the mentioned paper but no description of the technique was found on it. However, you can find the source code checking for it in [https://xsinator.com/testing.html#Request%20Merging%20Error%20Leak](https://xsinator.com/testing.html#Request%20Merging%20Error%20Leak)

### Empty Page Leak

- **Inclusion Methods**: Frames
- **Detectable Difference**: Page Content
- **More info**: [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf) (5.2)
- **Summary:** Empty responses do not create resource timing entries.
- **Code Example**: [https://xsinator.com/testing.html#Performance%20API%20Empty%20Page%20Leak](https://xsinator.com/testing.html#Performance%20API%20Empty%20Page%20Leak)

An attacker can detect if a request resulted in an empty HTTP response body because e**mpty pages do not create a performance entry in some browsers**.

### **XSS-Auditor Leak**

- **Inclusion Methods**: Frames
- **Detectable Difference**: Page Content
- **More info**: [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf) (5.2)
- **Summary:** Using the XSS Auditor in Security Assertions, attackers can detect specific webpage elements by observing alterations in responses when crafted payloads trigger the auditor's filtering mechanism.
- **Code Example**: [https://xsinator.com/testing.html#Performance%20API%20XSS%20Auditor%20Leak](https://xsinator.com/testing.html#Performance%20API%20XSS%20Auditor%20Leak)

In Security Assertions (SA), the XSS Auditor, originally intended to prevent Cross-Site Scripting (XSS) attacks, can paradoxically be exploited to leak sensitive information. Although this built-in feature was removed from Google Chrome (GC), it's still present in SA. In 2013, Braun and Heiderich demonstrated that the XSS Auditor could inadvertently block legitimate scripts, leading to false positives. Building on this, researchers developed techniques to extract information and detect specific content on cross-origin pages, a concept known as XS-Leaks, initially reported by Terada and elaborated by Heyes in a blog post. Although these techniques were specific to the XSS Auditor in GC, it was discovered that in SA, pages blocked by the XSS Auditor do not generate entries in the Performance API, revealing a method through which sensitive information might still be leaked.

### X-Frame Leak

- **Inclusion Methods**: Frames
- **Detectable Difference**: Header
- **More info**: [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf) (5.2), [https://xsleaks.github.io/xsleaks/examples/x-frame/index.html](https://xsleaks.github.io/xsleaks/examples/x-frame/index.html), [https://xsleaks.dev/docs/attacks/timing-attacks/performance-api/#detecting-x-frame-options](https://xsleaks.dev/docs/attacks/timing-attacks/performance-api/#detecting-x-frame-options)
- **Summary:** Resource with X-Frame-Options header does not create resource timing entry.
- **Code Example**: [https://xsinator.com/testing.html#Performance%20API%20X-Frame%20Leak](https://xsinator.com/testing.html#Performance%20API%20X-Frame%20Leak)

If a page is **not allowed** to be **rendered** in an **iframe** it does **not create a performance entry**. As a result, an attacker can detect the response header **`X-Frame-Options`**.\
Same happens if you use an **embed** **tag.**

### Download Detection

- **Inclusion Methods**: Frames
- **Detectable Difference**: Header
- **More info**: [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf) (5.2)
- **Summary:** Downloads do not create resource timing entries in the Performance API.
- **Code Example**: [https://xsinator.com/testing.html#Performance%20API%20Download%20Detection](https://xsinator.com/testing.html#Performance%20API%20Download%20Detection)

Similar, to the XS-Leak described, a **resource that is downloaded** because of the ContentDisposition header, also does **not create a performance entry**. This technique works in all major browsers.

### Redirect Start Leak

- **Inclusion Methods**: Frames
- **Detectable Difference**: Redirect
- **More info**: [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf) (5.2)
- **Summary:** Resource timing entry leaks the start time of a redirect.
- **Code Example**: [https://xsinator.com/testing.html#Redirect%20Start%20Leak](https://xsinator.com/testing.html#Redirect%20Start%20Leak)

We found one XS-Leak instance that abuses the behavior of some browsers which log too much information for cross-origin requests. The standard defines a subset of attributes that should be set to zero for cross-origin resources. However, in **SA** it is possible to detect if the user is **redirected** by the target page, by querying the **Performance API** and checking for the **redirectStart timing data**.

### Duration Redirect Leak

- **Inclusion Methods**: Fetch API
- **Detectable Difference**: Redirect
- **More info**: [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf) (5.2)
- **Summary:** The duration of timing entries is negative when a redirect occurs.
- **Code Example**: [https://xsinator.com/testing.html#Duration%20Redirect%20Leak](https://xsinator.com/testing.html#Duration%20Redirect%20Leak)

In GC, the **duration** for requests that result in a **redirect** is **negative** and can thus be **distinguished** from requests that do not result in a redirect.

### CORP Leak

- **Inclusion Methods**: Frames
- **Detectable Difference**: Header
- **More info**: [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf) (5.2)
- **Summary:** Resource protected with CORP do not create resource timing entries.
- **Code Example**: [https://xsinator.com/testing.html#Performance%20API%20CORP%20Leak](https://xsinator.com/testing.html#Performance%20API%20CORP%20Leak)

In some cases, the **nextHopProtocol entry** can be used as a leak technique. In GC, when the **CORP header** is set, the nextHopProtocol will be **empty**. Note that SA will not create a performance entry at all for CORP-enabled resources.

### Service Worker

- **Inclusion Methods**: Frames
- **Detectable Difference**: API Usage
- **More info**: [https://www.ndss-symposium.org/ndss-paper/awakening-the-webs-sleeper-agents-misusing-service-workers-for-privacy-leakage/](https://www.ndss-symposium.org/ndss-paper/awakening-the-webs-sleeper-agents-misusing-service-workers-for-privacy-leakage/)
- **Summary:** Detect if a service worker is registered for a specific origin.
- **Code Example**:

Service workers are event-driven script contexts that run at an origin. They run in the background of a web page and can intercept, modify, and **cache resources** to create offline web application.\
If a **resource cached** by a **service worker** is accessed via **iframe**, the resource will be **loaded from the service worker cache**.\
To detect if the resource was **loaded from the service worker** cache the **Performance API** can be used.\
This could also be done with a Timing attack (check the paper for more info).

### Cache

- **Inclusion Methods**: Fetch API
- **Detectable Difference**: Timing
- **More info**: [https://xsleaks.dev/docs/attacks/timing-attacks/performance-api/#detecting-cached-resources](https://xsleaks.dev/docs/attacks/timing-attacks/performance-api/#detecting-cached-resources)
- **Summary:** It is possible to check if a resource was stored in the cache.
- **Code Example**: [https://xsleaks.dev/docs/attacks/timing-attacks/performance-api/#detecting-cached-resources](https://xsleaks.dev/docs/attacks/timing-attacks/performance-api/#detecting-cached-resources), [https://xsinator.com/testing.html#Cache%20Leak%20(POST)](<https://xsinator.com/testing.html#Cache%20Leak%20(POST)>)

Using the [Performance API](xs-search.md#performance-api) it's possible to check if a resource is cached.

### Network Duration

- **Inclusion Methods**: Fetch API
- **Detectable Difference**: Page Content
- **More info**: [https://xsleaks.dev/docs/attacks/timing-attacks/performance-api/#network-duration](https://xsleaks.dev/docs/attacks/timing-attacks/performance-api/#network-duration)
- **Summary:** It is possible to retrieve the network duration of a request from the `performance` API.
- **Code Example**: [https://xsleaks.dev/docs/attacks/timing-attacks/performance-api/#network-duration](https://xsleaks.dev/docs/attacks/timing-attacks/performance-api/#network-duration)
