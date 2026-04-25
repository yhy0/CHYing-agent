# XS-Search/XS-Leaks - Global Limits Techniques

## Global Limits Techniques


### WebSocket API

- **Inclusion Methods**: Frames, Pop-ups
- **Detectable Difference**: API Usage
- **More info**: [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf) (5.1)
- **Summary**: Exhausting the WebSocket connection limit leaks the number of WebSocket connections of a cross-origin page.
- **Code Example**: [https://xsinator.com/testing.html#WebSocket%20Leak%20(FF)](<https://xsinator.com/testing.html#WebSocket%20Leak%20(FF)>), [https://xsinator.com/testing.html#WebSocket%20Leak%20(GC)](<https://xsinator.com/testing.html#WebSocket%20Leak%20(GC)>)

It is possible to identify if, and how many, **WebSocket connections a target page uses**. It allows an attacker to detect application states and leak information tied to the number of WebSocket connections.

If one **origin** uses the **maximum amount of WebSocket** connection objects, regardless of their connections state, the creation of **new objects will result in JavaScript exceptions**. To execute this attack, the attacker website opens the target website in a pop-up or iframe and then, after the target web has been loaded, attempts to create the maximum number of WebSockets connections possible. The **number of thrown exceptions** is the **number of WebSocket connections used by the target website** window.

### Payment API

- **Inclusion Methods**: Frames, Pop-ups
- **Detectable Difference**: API Usage
- **More info**: [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf) (5.1)
- **Summary**: Detect Payment Request because only one can be active at a time.
- **Code Example**: [https://xsinator.com/testing.html#Payment%20API%20Leak](https://xsinator.com/testing.html#Payment%20API%20Leak)

This XS-Leak enables an attacker to **detect when a cross-origin page initiates a payment request**.

Because **only one request payment can be active** at the same time, if the target website is using the Payment Request API, any f**urther attempts to show use this API will fail**, and cause a **JavaScript exception**. The attacker can exploit this by **periodically attempting to show the Payment API UI**. If one attempt causes an exception, the target website is currently using it. The attacker can hide these periodical attempts by immediately closing the UI after creation.

### Timing the Event Loop <a href="#timing-the-event-loop" id="timing-the-event-loop"></a>

- **Inclusion Methods**:
- **Detectable Difference**: Timing (generally due to Page Content, Status Code)
- **More info**: [https://xsleaks.dev/docs/attacks/timing-attacks/execution-timing/#timing-the-event-loop](https://xsleaks.dev/docs/attacks/timing-attacks/execution-timing/#timing-the-event-loop)
- **Summary:** Measure execution time of a web abusing the single-threaded JS event loop.
- **Code Example**:

JavaScript operates on a [single-threaded event loop](https://developer.mozilla.org/en-US/docs/Web/JavaScript/EventLoop) concurrency model, signifying that **it can only execute one task at a time**. This characteristic can be exploited to gauge **how long code from a different origin takes to execute**. An attacker can measure the execution time of their own code in the event loop by continuously dispatching events with fixed properties. These events will be processed when the event pool is empty. If other origins are also dispatching events to the same pool, an **attacker can infer the time it takes for these external events to execute by observing delays in the execution of their own tasks**. This method of monitoring the event loop for delays can reveal the execution time of code from different origins, potentially exposing sensitive information.

> [!WARNING]
> In an execution timing it's possible to **eliminate** **network factors** to obtain **more precise measurements**. For example, by loading the resources used by the page before loading it.

### Busy Event Loop <a href="#busy-event-loop" id="busy-event-loop"></a>

- **Inclusion Methods**:
- **Detectable Difference**: Timing (generally due to Page Content, Status Code)
- **More info**: [https://xsleaks.dev/docs/attacks/timing-attacks/execution-timing/#busy-event-loop](https://xsleaks.dev/docs/attacks/timing-attacks/execution-timing/#busy-event-loop)
- **Summary:** One method to measure the execution time of a web operation involves intentionally blocking the event loop of a thread and then timing **how long it takes for the event loop to become available again**. By inserting a blocking operation (such as a long computation or a synchronous API call) into the event loop, and monitoring the time it takes for subsequent code to begin execution, one can infer the duration of the tasks that were executing in the event loop during the blocking period. This technique leverages the single-threaded nature of JavaScript's event loop, where tasks are executed sequentially, and can provide insights into the performance or behavior of other operations sharing the same thread.
- **Code Example**:

A significant advantage of the technique of measuring execution time by locking the event loop is its potential to circumvent **Site Isolation**. **Site Isolation** is a security feature that separates different websites into separate processes, aiming to prevent malicious sites from directly accessing sensitive data from other sites. However, by influencing the execution timing of another origin through the shared event loop, an attacker can indirectly extract information about that origin's activities. This method does not rely on direct access to the other origin's data but rather observes the impact of that origin's activities on the shared event loop, thus evading the protective barriers established by **Site Isolation**.

> [!WARNING]
> In an execution timing it's possible to **eliminate** **network factors** to obtain **more precise measurements**. For example, by loading the resources used by the page before loading it.

### Connection Pool

- **Inclusion Methods**: JavaScript Requests
- **Detectable Difference**: Timing (generally due to Page Content, Status Code)
- **More info**: [https://xsleaks.dev/docs/attacks/timing-attacks/connection-pool/](https://xsleaks.dev/docs/attacks/timing-attacks/connection-pool/)
- **Summary:** An attacker could lock all the sockets except 1, load the target web and at the same time load another page, the time until the last page is starting to load is the time the target page took to load.
- **Code Example**:

Browsers utilize sockets for server communication, but due to the limited resources of the operating system and hardware, **browsers are compelled to impose a limit** on the number of concurrent sockets. Attackers can exploit this limitation through the following steps:

1. Ascertain the browser's socket limit, for instance, 256 global sockets.
2. Occupy 255 sockets for an extended duration by initiating 255 requests to various hosts, designed to keep the connections open without completing.
3. Employ the 256th socket to send a request to the target page.
4. Attempt a 257th request to a different host. Given that all sockets are in use (as per steps 2 and 3), this request will be queued until a socket becomes available. The delay before this request proceeds provides the attacker with timing information about the network activity related to the 256th socket (the target page's socket). This inference is possible because the 255 sockets from step 2 are still engaged, implying that any newly available socket must be the one released from step 3. The time taken for the 256th socket to become available is thus directly linked to the time required for the request to the target page to complete.

For more info: [https://xsleaks.dev/docs/attacks/timing-attacks/connection-pool/](https://xsleaks.dev/docs/attacks/timing-attacks/connection-pool/)

### Connection Pool by Destination

- **Inclusion Methods**: JavaScript Requests
- **Detectable Difference**: Timing (generally due to Page Content, Status Code)
- **More info**:
- **Summary:** It's like the previous technique but instead of using all the sockets, Google **Chrome** puts a limit of **6 concurrent request to the same origin**. If we **block 5** and then **launch a 6th** request we can **time** it and if we managed to make the **victim page send** more **requests** to the same endpoint to detect a **status** of the **page**, the **6th request** will take **longer** and we can detect it.
