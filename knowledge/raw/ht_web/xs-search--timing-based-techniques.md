# XS-Search/XS-Leaks - Timing Based Techniques

## **Timing Based techniques**


Some of the following techniques are going to use timing to as part of the process to detect differences in the possible states of the web pages. There are different ways to measure time in a web browser.

**Clocks**: The [performance.now()](https://developer.mozilla.org/en-US/docs/Web/API/Performance/now) API allows developers to get high-resolution timing measurements.\
There are a considerable number of APIs attackers can abuse to create implicit clocks: [Broadcast Channel API](https://developer.mozilla.org/en-US/docs/Web/API/Broadcast_Channel_API), [Message Channel API](https://developer.mozilla.org/en-US/docs/Web/API/MessageChannel), [requestAnimationFrame](https://developer.mozilla.org/en-US/docs/Web/API/window/requestAnimationFrame), [setTimeout](https://developer.mozilla.org/en-US/docs/Web/API/WindowOrWorkerGlobalScope/setTimeout), CSS animations, and others.\
For more info: [https://xsleaks.dev/docs/attacks/timing-attacks/clocks](https://xsleaks.dev/docs/attacks/timing-attacks/clocks/).
