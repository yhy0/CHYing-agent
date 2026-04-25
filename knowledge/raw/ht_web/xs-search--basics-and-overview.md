# XS-Search/XS-Leaks


## Basic Information


XS-Search is a method used for **extracting cross-origin information** by leveraging **side channel vulnerabilities**.

Key components involved in this attack include:

- **Vulnerable Web**: The target website from which information is intended to be extracted.
- **Attacker's Web**: The malicious website created by the attacker, which the victim visits, hosting the exploit.
- **Inclusion Method**: The technique employed to incorporate the Vulnerable Web into the Attacker's Web (e.g., window.open, iframe, fetch, HTML tag with href, etc.).
- **Leak Technique**: Techniques used to discern differences in the state of the Vulnerable Web based on information gathered through the inclusion method.
- **States**: The two potential conditions of the Vulnerable Web, which the attacker aims to distinguish.
- **Detectable Differences**: Observable variations that the attacker relies on to infer the state of the Vulnerable Web.

### Detectable Differences

Several aspects can be analyzed to differentiate the states of the Vulnerable Web:

- **Status Code**: Distinguishing between **various HTTP response status codes** cross-origin, like server errors, client errors, or authentication errors.
- **API Usage**: Identifying **usage of Web APIs** across pages, revealing whether a cross-origin page employs a specific JavaScript Web API.
- **Redirects**: Detecting navigations to different pages, not just HTTP redirects but also those triggered by JavaScript or HTML.
- **Page Content**: Observing **variations in the HTTP response body** or in page sub-resources, such as the **number of embedded frames** or size disparities in images.
- **HTTP Header**: Noting the presence or possibly the value of a **specific HTTP response header**, including headers like X-Frame-Options, Content-Disposition, and Cross-Origin-Resource-Policy.
- **Timing**: Noticing consistent time disparities between the two states.

### Inclusion Methods

- **HTML Elements**: HTML offers various elements for **cross-origin resource inclusion**, like stylesheets, images, or scripts, compelling the browser to request a non-HTML resource. A compilation of potential HTML elements for this purpose can be found at [https://github.com/cure53/HTTPLeaks](https://github.com/cure53/HTTPLeaks).
- **Frames**: Elements such as **iframe**, **object**, and **embed** can embed HTML resources directly into the attacker's page. If the page **lacks framing protection**, JavaScript can access the framed resource’s window object via the contentWindow property.
- **Pop-ups**: The **`window.open`** method opens a resource in a new tab or window, providing a **window handle** for JavaScript to interact with methods and properties following the SOP. Pop-ups, often used in single sign-on, circumvent framing and cookie restrictions of a target resource. However, modern browsers restrict pop-up creation to certain user actions.
- **JavaScript Requests**: JavaScript permits direct requests to target resources using **XMLHttpRequests** or the **Fetch API**. These methods offer precise control over the request, like opting to follow HTTP redirects.

### Leak Techniques

- **Event Handler**: A classical leak technique in XS-Leaks, where event handlers like **onload** and **onerror** provide insights about resource loading success or failure.
- **Error Messages**: JavaScript exceptions or special error pages can provide leak information either directly from the error message or by differentiating between its presence and absence.
- **Global Limits**: Physical limitations of a browser, like memory capacity or other enforced browser limits, can signal when a threshold is reached, serving as a leak technique.
- **Global State**: Detectable interactions with browsers' **global states** (e.g., the History interface) can be exploited. For instance, the **number of entries** in a browser's history can offer clues about cross-origin pages.
- **Performance API**: This API provides **performance details of the current page**, including network timing for the document and loaded resources, enabling inferences about requested resources.
- **Readable Attributes**: Some HTML attributes are **readable cross-origin** and can be used as a leak technique. For instance, the `window.frame.length` property allows JavaScript to count the frames included in a webpage cross-origin.


## XSinator Tool & Paper


XSinator is an automatic tool to **check browsers against several know XS-Leaks** explained in its paper: [**https://xsinator.com/paper.pdf**](https://xsinator.com/paper.pdf)

You can **access the tool in** [**https://xsinator.com/**](https://xsinator.com/)

> [!WARNING]
> **Excluded XS-Leaks**: We had to exclude XS-Leaks that rely on **service workers** as they would interfere with other leaks in XSinator. Furthermore, we chose to **exclude XS-Leaks that rely on misconfiguration and bugs in a specific web application**. For example, CrossOrigin Resource Sharing (CORS) misconfigurations, postMessage leakage or Cross-Site Scripting. Additionally, we excluded timebased XS-Leaks since they often suffer from being slow, noisy and inaccurate.
