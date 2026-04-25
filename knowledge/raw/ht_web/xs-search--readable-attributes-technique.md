# XS-Search/XS-Leaks - Readable Attributes Technique

## Readable Attributes Technique


### Fetch Redirect

- **Inclusion Methods**: Fetch API
- **Detectable Difference**: Status Code
- **More info**: [https://web-in-security.blogspot.com/2021/02/security-and-privacy-of-social-logins-part3.html](https://web-in-security.blogspot.com/2021/02/security-and-privacy-of-social-logins-part3.html)
- **Summary:** GC and SA allow to check the response’s type (opaque-redirect) after the redirect is finished.
- **Code Example**: [https://xsinator.com/testing.html#Fetch%20Redirect%20Leak](https://xsinator.com/testing.html#Fetch%20Redirect%20Leak)

Submitting a request using the Fetch API with `redirect: "manual"` and other params, it's possible to read the `response.type` attribute and if it's equals to `opaqueredirect` then the response was a redirect.

### COOP

- **Inclusion Methods**: Pop-ups
- **Detectable Difference**: Header
- **More info**: [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf) (5.4), [https://xsleaks.dev/docs/attacks/window-references/](https://xsleaks.dev/docs/attacks/window-references/)
- **Summary:** Pages safeguarded by Cross-Origin Opener Policy (COOP) prevent access from cross-origin interactions.
- **Code Example**: [https://xsinator.com/testing.html#COOP%20Leak](https://xsinator.com/testing.html#COOP%20Leak)

An attacker is capable of deducing the presence of the Cross-Origin Opener Policy (COOP) header in a cross-origin HTTP response. COOP is utilized by web applications to hinder external sites from obtaining arbitrary window references. The visibility of this header can be discerned by attempting to access the **`contentWindow` reference**. In scenarios where COOP is applied conditionally, the **`opener` property** becomes a telltale indicator: it's **undefined** when COOP is active, and **defined** in its absence.

### URL Max Length - Server Side

- **Inclusion Methods**: Fetch API, HTML Elements
- **Detectable Difference**: Status Code / Content
- **More info**: [https://xsleaks.dev/docs/attacks/navigations/#server-side-redirects](https://xsleaks.dev/docs/attacks/navigations/#server-side-redirects)
- **Summary:** Detect differences in responses because of the redirect response length migt be too large that the server replays with an error and an alert is generated.
- **Code Example**: [https://xsinator.com/testing.html#URL%20Max%20Length%20Leak](https://xsinator.com/testing.html#URL%20Max%20Length%20Leak)

If a server-side redirect uses **user input inside the redirection** and **extra data**. It's possible to detect this behaviour because usually **servers** has a **limit request length**. If the **user data** is that **length - 1**, because the **redirect** is using **that data** and **adding** something **extra**, it will trigger an **error detectable via Error Events**.

If you can somehow set cookies to a user, you can also perform this attack by **setting enough cookies** ([**cookie bomb**](hacking-with-cookies/cookie-bomb.md)) so with the **response increased size** of the **correct response** an **error** is triggered. In this case, remember that is you trigger this request from a same site, `<script>` will automatically send the cookies (so you can check for errors).\
An example of the **cookie bomb + XS-Search** can be found in the Intended solution of this writeup: [https://blog.huli.tw/2022/05/05/en/angstrom-ctf-2022-writeup-en/#intended](https://blog.huli.tw/2022/05/05/en/angstrom-ctf-2022-writeup-en/#intended)

`SameSite=None` or to be in the same context is usually needed for this type of attack.

### URL Max Length - Client Side

- **Inclusion Methods**: Pop-ups
- **Detectable Difference**: Status Code / Content
- **More info**: [https://ctf.zeyu2001.com/2023/hacktm-ctf-qualifiers/secrets#unintended-solution-chromes-2mb-url-limit](https://ctf.zeyu2001.com/2023/hacktm-ctf-qualifiers/secrets#unintended-solution-chromes-2mb-url-limit)
- **Summary:** Detect differences in responses because of the redirect response length might too large for a request that a difference can be noticed.
- **Code Example**: [https://ctf.zeyu2001.com/2023/hacktm-ctf-qualifiers/secrets#unintended-solution-chromes-2mb-url-limit](https://ctf.zeyu2001.com/2023/hacktm-ctf-qualifiers/secrets#unintended-solution-chromes-2mb-url-limit)

According to [Chromium documentation](https://chromium.googlesource.com/chromium/src/+/main/docs/security/url_display_guidelines/url_display_guidelines.md#URL-Length), Chrome's maximum URL length is 2MB.

> In general, the _web platform_ does not have limits on the length of URLs (although 2^31 is a common limit). _Chrome_ limits URLs to a maximum length of **2MB** for practical reasons and to avoid causing denial-of-service problems in inter-process communication.

Therefore if the **redirect URL responded is larger in one of the cases**, it's possible to make it redirect with a **URL larger than 2MB** to hit the **length limit**. When this happens, Chrome shows an **`about:blank#blocked`** page.

The **noticeable difference**, is that if the **redirect** was **completed**, `window.origin` throws an **error** because a cross origin cannot access that info. However, if the **limit** was  hit and the loaded page was **`about:blank#blocked`** the window's **`origin`** remains that of the **parent**, which is an **accessible information.**

All the extra info needed to reach the **2MB** can be added via a **hash** in the initial URL so it will be **used in the redirect**.

### Max Redirects

- **Inclusion Methods**: Fetch API, Frames
- **Detectable Difference**: Status Code
- **More info**: [https://docs.google.com/presentation/d/1rlnxXUYHY9CHgCMckZsCGH4VopLo4DYMvAcOltma0og/edit#slide=id.g63edc858f3_0_76](https://docs.google.com/presentation/d/1rlnxXUYHY9CHgCMckZsCGH4VopLo4DYMvAcOltma0og/edit#slide=id.g63edc858f3_0_76)
- **Summary:** User the browser's redirect limit to ascertain the occurrence of URL redirections.
- **Code Example**: [https://xsinator.com/testing.html#Max%20Redirect%20Leak](https://xsinator.com/testing.html#Max%20Redirect%20Leak)

If the **max** number of **redirects** to follow of a browser is **20**, an attacker could try to load his page with **19 redirects** and finally **send the victim** to the tested page. If an **error** is triggered, then the page was trying to **redirect the victim**.

### History Length

- **Inclusion Methods**: Frames, Pop-ups
- **Detectable Difference**: Redirects
- **More info**: [https://xsleaks.dev/docs/attacks/navigations/](https://xsleaks.dev/docs/attacks/navigations/)
- **Summary:** JavaScript code manipulates the browser history and can be accessed by the length property.
- **Code Example**: [https://xsinator.com/testing.html#History%20Length%20Leak](https://xsinator.com/testing.html#History%20Length%20Leak)

The **History API** allows JavaScript code to manipulate the browser history, which **saves the pages visited by a user**. An attacker can use the length property as an inclusion method: to detect JavaScript and HTML navigation.\
**Checking `history.length`**, making a user **navigate** to a page, **change** it **back** to the same-origin and **checking** the new value of **`history.length`**.

### History Length with same URL

- **Inclusion Methods**: Frames, Pop-ups
- **Detectable Difference**: If URL is the same as the guessed one
- **Summary:** It's possible to guess if the location of a frame/popup is in an specific URL abusing the history length.
- **Code Example**: Below

An attacker could use JavaScript code to **manipulate the frame/pop-up location to a guessed one** and **immediately** **change it to `about:blank`**. If the history length increased it means the URL was correct and it had time to **increase because the URL isn't reloaded if it's the same**. If it didn't increased it means it **tried to load the guessed URL** but because we **immediately after** loaded **`about:blank`**, the **history length did never increase** when loading the guessed url.

```javascript
async function debug(win, url) {
  win.location = url + "#aaa"
  win.location = "about:blank"
  await new Promise((r) => setTimeout(r, 500))
  return win.history.length
}

win = window.open("https://example.com/?a=b")
await new Promise((r) => setTimeout(r, 2000))
console.log(await debug(win, "https://example.com/?a=c"))

win.close()
win = window.open("https://example.com/?a=b")
await new Promise((r) => setTimeout(r, 2000))
console.log(await debug(win, "https://example.com/?a=b"))
```

### Frame Counting

- **Inclusion Methods**: Frames, Pop-ups
- **Detectable Difference**: Page Content
- **More info**: [https://xsleaks.dev/docs/attacks/frame-counting/](https://xsleaks.dev/docs/attacks/frame-counting/)
- **Summary:** Evaluate the quantity of iframe elements by inspecting the `window.length` property.
- **Code Example**: [https://xsinator.com/testing.html#Frame%20Count%20Leak](https://xsinator.com/testing.html#Frame%20Count%20Leak)

Counting the **number of frames in a web** opened via `iframe` or `window.open` might help to identify the **status of the user over that page**.\
Moreover, if the page has always the same number of frames, checking **continuously** the number of frames might help to identify a **pattern** that might leak info.

An example of this technique is that in chrome, a **PDF** can be **detected** with **frame counting** because an `embed` is used internally. There are [Open URL Parameters](https://bugs.chromium.org/p/chromium/issues/detail?id=64309#c113) that allow some control over the content such as `zoom`, `view`, `page`, `toolbar` where this technique could be interesting.

### HTMLElements

- **Inclusion Methods**: HTML Elements
- **Detectable Difference**: Page Content
- **More info**: [https://xsleaks.dev/docs/attacks/element-leaks/](https://xsleaks.dev/docs/attacks/element-leaks/)
- **Summary:** Read the leaked value to distinguish between 2 possible states
- **Code Example**: [https://xsleaks.dev/docs/attacks/element-leaks/](https://xsleaks.dev/docs/attacks/element-leaks/), [https://xsinator.com/testing.html#Media%20Dimensions%20Leak](https://xsinator.com/testing.html#Media%20Dimensions%20Leak), [https://xsinator.com/testing.html#Media%20Duration%20Leak](https://xsinator.com/testing.html#Media%20Duration%20Leak)

Information leakage through HTML elements is a concern in web security, particularly when dynamic media files are generated based on user information, or when watermarks are added, altering the media size. This can be exploited by attackers to differentiate between possible states by analyzing the information exposed by certain HTML elements.

### Information Exposed by HTML Elements

- **HTMLMediaElement**: This element reveals the media's `duration` and `buffered` times, which can be accessed via its API. [Read more about HTMLMediaElement](https://developer.mozilla.org/en-US/docs/Web/API/HTMLMediaElement)
- **HTMLVideoElement**: It exposes `videoHeight` and `videoWidth`. In some browsers, additional properties like `webkitVideoDecodedByteCount`, `webkitAudioDecodedByteCount`, and `webkitDecodedFrameCount` are available, offering more in-depth information about the media content. [Read more about HTMLVideoElement](https://developer.mozilla.org/en-US/docs/Web/API/HTMLVideoElement)
- **getVideoPlaybackQuality()**: This function provides details about video playback quality, including `totalVideoFrames`, which can indicate the amount of video data processed. [Read more about getVideoPlaybackQuality()](https://developer.mozilla.org/en-US/docs/Web/API/VideoPlaybackQuality)
- **HTMLImageElement**: This element leaks the `height` and `width` of an image. However, if an image is invalid, these properties will return 0, and the `image.decode()` function will be rejected, indicating the failure to load the image properly. [Read more about HTMLImageElement](https://developer.mozilla.org/en-US/docs/Web/API/HTMLImageElement)

### CSS Property

- **Inclusion Methods**: HTML Elements
- **Detectable Difference**: Page Content
- **More info**: [https://xsleaks.dev/docs/attacks/element-leaks/#abusing-getcomputedstyle](https://xsleaks.dev/docs/attacks/element-leaks/#abusing-getcomputedstyle), [https://scarybeastsecurity.blogspot.com/2008/08/cross-domain-leaks-of-site-logins.html](https://scarybeastsecurity.blogspot.com/2008/08/cross-domain-leaks-of-site-logins.html)
- **Summary:** Identify variations in website styling that correlate with the user's state or status.
- **Code Example**: [https://xsinator.com/testing.html#CSS%20Property%20Leak](https://xsinator.com/testing.html#CSS%20Property%20Leak)

Web applications may change w**ebsite styling depending on the status of the use**. Cross-origin CSS files can be embedded on the attacker page with the **HTML link element**, and the **rules** will be **applied** to the attacker page. If a page dynamically changes these rules, an attacker can **detect** these **differences** depending on the user state.\
As a leak technique, the attacker can use the `window.getComputedStyle` method to **read CSS** properties of a specific HTML element. As a result, an attacker can read arbitrary CSS properties if the affected element and property name is known.

### CSS History

- **Inclusion Methods**: HTML Elements
- **Detectable Difference**: Page Content
- **More info**: [https://xsleaks.dev/docs/attacks/css-tricks/#retrieving-users-history](https://xsleaks.dev/docs/attacks/css-tricks/#retrieving-users-history)
- **Summary:** Detect if the `:visited` style is applied to an URL indicating it was already visited
- **Code Example**: [http://blog.bawolff.net/2021/10/write-up-pbctf-2021-vault.html](http://blog.bawolff.net/2021/10/write-up-pbctf-2021-vault.html)

> [!TIP]
> According to [**this**](https://blog.huli.tw/2022/05/05/en/angstrom-ctf-2022-writeup-en/), this is not working in headless Chrome.

The CSS `:visited` selector is utilized to style URLs differently if they have been previously visited by the user. In the past, the `getComputedStyle()` method could be employed to identify these style differences. However, modern browsers have implemented security measures to prevent this method from revealing the state of a link. These measures include always returning the computed style as if the link were visited and restricting the styles that can be applied with the `:visited` selector.

Despite these restrictions, it's possible to discern the visited state of a link indirectly. One technique involves tricking the user into interacting with an area affected by CSS, specifically utilizing the `mix-blend-mode` property. This property allows the blending of elements with their background, potentially revealing the visited state based on user interaction.

Furthermore, detection can be achieved without user interaction by exploiting the rendering timings of links. Since browsers may render visited and unvisited links differently, this can introduce a measurable time difference in rendering. A proof of concept (PoC) was mentioned in a Chromium bug report, demonstrating this technique using multiple links to amplify the timing difference, thereby making the visited state detectable through timing analysis.

For further details on these properties and methods, visit their documentation pages:

- `:visited`: [MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/CSS/:visited)
- `getComputedStyle()`: [MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/Window/getComputedStyle)
- `mix-blend-mode`: [MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/CSS/mix-blend-mode)

### ContentDocument X-Frame Leak

- **Inclusion Methods**: Frames
- **Detectable Difference**: Headers
- **More info**: [https://www.ndss-symposium.org/wp-content/uploads/2020/02/24278-paper.pdf](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24278-paper.pdf)
- **Summary:** In Google Chrome, a dedicated error page is displayed when a page is blocked from being embedded on a cross-origin site due to X-Frame-Options restrictions.
- **Code Example**: [https://xsinator.com/testing.html#ContentDocument%20X-Frame%20Leak](https://xsinator.com/testing.html#ContentDocument%20X-Frame%20Leak)

In Chrome, if a page with the `X-Frame-Options` header set to "deny" or "same-origin" is embedded as an object, an error page appears. Chrome uniquely returns an empty document object (instead of `null`) for the `contentDocument` property of this object, unlike in iframes or other browsers. Attackers could exploit this by detecting the empty document, potentially revealing information about the user's state, especially if developers inconsistently set the X-Frame-Options header, often overlooking error pages. Awareness and consistent application of security headers are crucial for preventing such leaks.

### Download Detection

- **Inclusion Methods**: Frames, Pop-ups
- **Detectable Difference**: Headers
- **More info**: [https://xsleaks.dev/docs/attacks/navigations/#download-trigger](https://xsleaks.dev/docs/attacks/navigations/#download-trigger)
- **Summary:** An attacker can discern file downloads by leveraging iframes; continued accessibility of the iframe implies successful file download.
- **Code Example**: [https://xsleaks.dev/docs/attacks/navigations/#download-bar](https://xsleaks.dev/docs/attacks/navigations/#download-bar)

The `Content-Disposition` header, specifically `Content-Disposition: attachment`, instructs the browser to download content rather than display it inline. This behavior can be exploited to detect whether a user has access to a page that triggers a file download. In Chromium-based browsers, there are a few techniques to detect this download behavior:

1. **Download Bar Monitoring**:
   - When a file is downloaded in Chromium-based browsers, a download bar appears at the bottom of the browser window.
   - By monitoring changes in the window height, attackers can infer the appearance of the download bar, suggesting that a download has been initiated.
2. **Download Navigation with Iframes**:
   - When a page triggers a file download using the `Content-Disposition: attachment` header, it does not cause a navigation event.
   - By loading the content in an iframe and monitoring for navigation events, it's possible to check if the content disposition causes a file download (no navigation) or not.
3. **Download Navigation without Iframes**:
   - Similar to the iframe technique, this method involves using `window.open` instead of an iframe.
   - Monitoring navigation events in the newly opened window can reveal whether a file download was triggered (no navigation) or if the content is displayed inline (navigation occurs).

In scenarios where only logged-in users can trigger such downloads, these techniques can be used to indirectly infer the user's authentication state based on the browser's response to the download request.

### Partitioned HTTP Cache Bypass <a href="#partitioned-http-cache-bypass" id="partitioned-http-cache-bypass"></a>

- **Inclusion Methods**: Pop-ups
- **Detectable Difference**: Timing
- **More info**: [https://xsleaks.dev/docs/attacks/navigations/#partitioned-http-cache-bypass](https://xsleaks.dev/docs/attacks/navigations/#partitioned-http-cache-bypass)
- **Summary:** An attacker can discern file downloads by leveraging iframes; continued accessibility of the iframe implies successful file download.
- **Code Example**: [https://xsleaks.dev/docs/attacks/navigations/#partitioned-http-cache-bypass](https://xsleaks.dev/docs/attacks/navigations/#partitioned-http-cache-bypass), [https://gist.github.com/aszx87410/e369f595edbd0f25ada61a8eb6325722](https://gist.github.com/aszx87410/e369f595edbd0f25ada61a8eb6325722) (from [https://blog.huli.tw/2022/05/05/en/angstrom-ctf-2022-writeup-en/](https://blog.huli.tw/2022/05/05/en/angstrom-ctf-2022-writeup-en/))

> [!WARNING]
> This is why this technique is interesting: Chrome now has **cache partitioning**, and the cache key of the newly opened page is: `(https://actf.co, https://actf.co, https://sustenance.web.actf.co/?m =xxx)`, but if I open an ngrok page and use fetch in it, the cache key will be: `(https://myip.ngrok.io, https://myip.ngrok.io, https://sustenance.web.actf.co/?m=xxx)`, the **cache key is different**, so the cache cannot be shared. You can find more detail here: [Gaining security and privacy by partitioning the cache](https://developer.chrome.com/blog/http-cache-partitioning/)\
> (Comment from [**here**](https://blog.huli.tw/2022/05/05/en/angstrom-ctf-2022-writeup-en/))

If a site `example.com` includes a resource from `*.example.com/resource` then that resource will have the **same caching key** as if the resource was directly **requested through top-level navigation**. That is because the caching key is consisted of top-level _eTLD+1_ and frame _eTLD+1_.

Because accessing the cache is faster than loading a resource, it's possible to try to change the location of a page and cancel it 20ms (for example) after. If the origin was changed after the stop, it means that the resource was cached.\
Or could just **send some fetch to the pontentially cached page and measure the time it takes**.

### Manual Redirect <a href="#fetch-with-abortcontroller" id="fetch-with-abortcontroller"></a>

- **Inclusion Methods**: Fetch API
- **Detectable Difference**: Redirects
- **More info**: [ttps://docs.google.com/presentation/d/1rlnxXUYHY9CHgCMckZsCGH4VopLo4DYMvAcOltma0og/edit#slide=id.gae7bf0b4f7_0_1234](https://docs.google.com/presentation/d/1rlnxXUYHY9CHgCMckZsCGH4VopLo4DYMvAcOltma0og/edit#slide=id.gae7bf0b4f7_0_1234)
- **Summary:** It's possible to find out if a response to a fetch request is a redirect
- **Code Example**:

.png>)

### Fetch with AbortController <a href="#fetch-with-abortcontroller" id="fetch-with-abortcontroller"></a>

- **Inclusion Methods**: Fetch API
- **Detectable Difference**: Timing
- **More info**: [https://xsleaks.dev/docs/attacks/cache-probing/#fetch-with-abortcontroller](https://xsleaks.dev/docs/attacks/cache-probing/#fetch-with-abortcontroller)
- **Summary:** It's possible to try to load a resource and about before it's loaded the loading is interrupted. Depending on if an error is triggered, the resource was or wasn't cached.
- **Code Example**: [https://xsleaks.dev/docs/attacks/cache-probing/#fetch-with-abortcontroller](https://xsleaks.dev/docs/attacks/cache-probing/#fetch-with-abortcontroller)

Use _**fetch**_ and _**setTimeout**_ with an **AbortController** to both detect whether the **resource is cached** and to evict a specific resource from the browser cache. Moreover, the process occurs without caching new content.

### Script Pollution

- **Inclusion Methods**: HTML Elements (script)
- **Detectable Difference**: Page Content
- **More info**: [https://xsleaks.dev/docs/attacks/element-leaks/#script-tag](https://xsleaks.dev/docs/attacks/element-leaks/#script-tag)
- **Summary:** It's possible to **overwrite built-in functions** and read their arguments which even from **cross-origin script** (which cannot be read directly), this might **leak valuable information**.
- **Code Example**: [https://xsleaks.dev/docs/attacks/element-leaks/#script-tag](https://xsleaks.dev/docs/attacks/element-leaks/#script-tag)

### Service Workers <a href="#service-workers" id="service-workers"></a>

- **Inclusion Methods**: Pop-ups
- **Detectable Difference**: Page Content
- **More info**: [https://xsleaks.dev/docs/attacks/timing-attacks/execution-timing/#service-workers](https://xsleaks.dev/docs/attacks/timing-attacks/execution-timing/#service-workers)
- **Summary:** Measure execution time of a web using service workers.
- **Code Example**:

In the given scenario, the attacker takes the initiative to register a **service worker** within one of their domains, specifically "attacker.com". Next, the attacker opens a new window in the target website from the main document and instructs the **service worker** to commence a timer. As the new window begins to load, the attacker navigates the reference obtained in the previous step to a page managed by the **service worker**.

Upon arrival of the request initiated in the preceding step, the **service worker** responds with a **204 (No Content)** status code, effectively terminating the navigation process. At this point, the **service worker** captures a measurement from the timer initiated earlier in step two. This measurement is influenced by the duration of JavaScript causing delays in the navigation process.

> [!WARNING]
> In an execution timing it's possible to **eliminate** **network factors** to obtain **more precise measurements**. For example, by loading the resources used by the page before loading it.

### Fetch Timing

- **Inclusion Methods**: Fetch API
- **Detectable Difference**: Timing (generally due to Page Content, Status Code)
- **More info**: [https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#modern-web-timing-attacks](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#modern-web-timing-attacks)
- **Summary:** Use [performance.now()](https://xsleaks.dev/docs/attacks/timing-attacks/clocks/#performancenow) to measure the time it takes to perform a request. Other clocks could be used.
- **Code Example**: [https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#modern-web-timing-attacks](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#modern-web-timing-attacks)

### Cross-Window Timing

- **Inclusion Methods**: Pop-ups
- **Detectable Difference**: Timing (generally due to Page Content, Status Code)
- **More info**: [https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#cross-window-timing-attacks](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#cross-window-timing-attacks)
- **Summary:** se [performance.now()](https://xsleaks.dev/docs/attacks/timing-attacks/clocks/#performancenow) to measure the time it takes to perform a request using `window.open`. Other clocks could be used.
- **Code Example**: [https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#cross-window-timing-attacks](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#cross-window-timing-attacks)
