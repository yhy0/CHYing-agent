# CORS - DNS Rebinding, Bypasses, and Tools

## Bypass

### XSSI (Cross-Site Script Inclusion) / JSONP

XSSI, also known as Cross-Site Script Inclusion, is a type of vulnerability that takes advantage of the fact that the Same Origin Policy (SOP) does not apply when including resources using the script tag. This is because scripts need to be able to be included from different domains. This vulnerability allows an attacker to access and read any content that was included using the script tag.

This vulnerability becomes particularly significant when it comes to dynamic JavaScript or JSONP (JSON with Padding), especially when ambient-authority information like cookies are used for authentication. When requesting a resource from a different host, the cookies are included, making them accessible to the attacker.

To better understand and mitigate this vulnerability, you can use the BurpSuite plugin available at [https://github.com/kapytein/jsonp](https://github.com/kapytein/jsonp). This plugin can help identify and address potential XSSI vulnerabilities in your web applications.

[**Read more about the difefrent types of XSSI and how to exploit them here.**](xssi-cross-site-script-inclusion.md)

Try to add a **`callback`** **parameter** in the request. Maybe the page was prepared to send the data as JSONP. In that case the page will send back the data with `Content-Type: application/javascript` which will bypass the CORS policy.

.png>)

### Easy (useless?) bypass

One way to bypass the `Access-Control-Allow-Origin` restriction is by requesting a web application to make a request on your behalf and send back the response. However, in this scenario, the credentials of the final victim won't be sent as the request is made to a different domain.

1. [**CORS-escape**](https://github.com/shalvah/cors-escape): This tool provides a proxy that forwards your request along with its headers, while also spoofing the Origin header to match the requested domain. This effectively bypasses the CORS policy. Here's an example usage with XMLHttpRequest:
2. [**simple-cors-escape**](https://github.com/shalvah/simple-cors-escape): This tool offers an alternative approach to proxying requests. Instead of passing on your request as-is, the server makes its own request with the specified parameters.

### Iframe + Popup Bypass

You can **bypass CORS checks** such as `e.origin === window.origin` by **creating an iframe** and **from it opening a new window**. More information in the following page:

### DNS Rebinding via TTL

DNS rebinding via TTL is a technique used to bypass certain security measures by manipulating DNS records. Here's how it works:

1. The attacker creates a web page and makes the victim access it.
2. The attacker then changes the DNS (IP) of their own domain to point to the victim's web page.
3. The victim's browser caches the DNS response, which may have a TTL (Time to Live) value indicating how long the DNS record should be considered valid.
4. When the TTL expires, the victim's browser makes a new DNS request, allowing the attacker to execute JavaScript code on the victim's page.
5. By maintaining control over the IP of the victim, the attacker can gather information from the victim without sending any cookies to the victim server.

It's important to note that browsers have caching mechanisms that may prevent immediate abuse of this technique, even with low TTL values.

DNS rebinding can be useful for bypassing explicit IP checks performed by the victim or for scenarios where a user or bot remains on the same page for an extended period, allowing the cache to expire.

If you need a quick way to abuse DNS rebinding, you can use services like [https://lock.cmpxchg8b.com/rebinder.html](https://lock.cmpxchg8b.com/rebinder.html).

To run your own DNS rebinding server, you can utilize tools like **DNSrebinder** ([https://github.com/mogwailabs/DNSrebinder](https://github.com/mogwailabs/DNSrebinder)). This involves exposing your local port 53/udp, creating an A record pointing to it (e.g., ns.example.com), and creating an NS record pointing to the previously created A subdomain (e.g., ns.example.com). Any subdomain of the ns.example.com subdomain will then be resolved by your host.

You can also explore a publicly running server at [http://rebind.it/singularity.html](http://rebind.it/singularity.html) for further understanding and experimentation.

### DNS Rebinding via **DNS Cache Flooding**

DNS rebinding via DNS cache flooding is another technique used to bypass the caching mechanism of browsers and force a second DNS request. Here's how it works:

1. Initially, when the victim makes a DNS request, it is responded with the attacker's IP address.
2. To bypass the caching defense, the attacker leverages a service worker. The service worker floods the DNS cache, which effectively deletes the cached attacker server name.
3. When the victim's browser makes a second DNS request, it is now responded with the IP address 127.0.0.1, which typically refers to the localhost.

By flooding the DNS cache with the service worker, the attacker can manipulate the DNS resolution process and force the victim's browser to make a second request, this time resolving to the attacker's desired IP address.

### DNS Rebinding via **Cache**

Another way to bypass the caching defense is by utilizing multiple IP addresses for the same subdomain in the DNS provider. Here's how it works:

1. The attacker sets up two A records (or a single A record with two IPs) for the same subdomain in the DNS provider.
2. When a browser checks for these records, it receives both IP addresses.
3. If the browser decides to use the attacker's IP address first, the attacker can serve a payload that performs HTTP requests to the same domain.
4. However, once the attacker obtains the victim's IP address, they stop responding to the victim's browser.
5. The victim's browser, upon realizing that the domain is unresponsive, moves on to use the second given IP address.
6. By accessing the second IP address, the browser bypasses the Same Origin Policy (SOP), allowing the attacker to abuse this and gather and exfiltrate information.

This technique leverages the behavior of browsers when multiple IP addresses are provided for a domain. By strategically controlling the responses and manipulating the browser's choice of IP address, an attacker can exploit the SOP and access information from the victim.

> [!WARNING]
> Note that in order to access localhost you should try to rebind **127.0.0.1** in Windows and **0.0.0.0** in linux.\
> Providers such as godaddy or cloudflare didn't allow me to use the ip 0.0.0.0, but AWS route53 allowed me to create one A record with 2 IPs being one of them "0.0.0.0"
>
> <img src="../images/image (140).png" alt="" data-size="original">

For more info you can check [https://unit42.paloaltonetworks.com/dns-rebinding/](https://unit42.paloaltonetworks.com/dns-rebinding/)

### Other Common Bypasses

- If **internal IPs aren't allowed**, they might **forgot forbidding 0.0.0.0** (works on Linux and Mac)
- If **internal IPs aren't allowed**, respond with a **CNAME** to **localhost** (works on Linux and Ma
- If **internal IPs aren't allowed** as DNS responses, you can respond **CNAMEs to internal services** such as www.corporate.internal.

### DNS Rebidding Weaponized

You can find more information about the previous bypass techniques and how to use the following tool in the talk [Gerald Doussot - State of DNS Rebinding Attacks & Singularity of Origin - DEF CON 27 Conference](https://www.youtube.com/watch?v=y9-0lICNjOQ).

[**`Singularity of Origin`**](https://github.com/nccgroup/singularity) is a tool to perform [DNS rebinding](https://en.wikipedia.org/wiki/DNS_rebinding) attacks. It includes the necessary components to rebind the IP address of the attack server DNS name to the target machine's IP address and to serve attack payloads to exploit vulnerable software on the target machine.

### DNS Rebinding over DNS-over-HTTPS (DoH)

DoH simply tunnels the classic RFC1035 DNS wire format inside HTTPS (usually a POST with `Content-Type: application/dns-message`). The resolver still answers with the same resource records, so SOP-breaking techniques continue to work even when browsers resolve the attacker-controlled hostname via TLS.

#### Key observations

- Chrome (Windows/macOS) and Firefox (Linux) successfully rebind when configured for Cloudflare, Google, or OpenDNS DoH resolvers. Transport encryption neither delays nor blocks the attack-flow for **first-then-second**, **multiple-answers**, or **DNS cache flooding** strategies.
- Public resolvers still see every query, but they rarely enforce the host-to-IP mapping a browser must honor. Once the authoritative server returns the rebinding sequence, the browser keeps the original origin tuple while connecting to the new IP.

#### Singularity strategies and timing over DoH

- **First-then-second** remains the most reliable option: the first lookup returns the attacker IP that serves the payload, every later lookup returns the internal/localhost IP. With typical browser DNS caches this flips traffic in ~40–60 seconds, even when the recursive resolver is only reachable over HTTPS.
- **Multiple answers (fast rebinding)** still reaches localhost in <3 seconds by answering with two A records (attacker IP + `0.0.0.0` on Linux/macOS or `127.0.0.1` on Windows) and programmatically blackholing the first IP (for example, `iptables -I OUTPUT -d <attacker_ip> -j DROP`) shortly after the page loads. Firefox’s DoH implementation may emit repeated DNS queries, so the Singularity fix is to schedule the firewall rule relative to the **first** query timestamp instead of refreshing the timer on every query.

#### Beating “rebind protection” in DoH providers

- Some providers (e.g., NextDNS) replace private/loopback answers with `0.0.0.0`, but Linux and macOS happily route that destination to local services. Intentionally returning `0.0.0.0` as the second record therefore still pivots the origin to localhost.
- Filtering only the direct A/AAAA response is ineffective: returning a **CNAME** to an internal-only hostname makes the public DoH resolver forward the alias while browsers such as Firefox fall back to the system DNS for the internal zone, completing the resolution to a private IP that is still treated as the attacker origin.

#### Browser-specific DoH behavior

- **Firefox DoH** operates in fallback mode: any DoH failure (including an unresolved CNAME target) triggers a plaintext lookup via the OS resolver, which is typically an enterprise DNS server that knows the internal namespace. This behavior is what makes the CNAME bypass reliable inside corporate networks.
- **Chrome DoH** only activates when the OS DNS points to a whitelisted DoH-capable recursive resolver (Cloudflare, Google, Quad9, etc.) and does not provide the same fallback chain. Internal hostnames that only exist on corporate DNS therefore fail to resolve, but rebinding toward localhost or any routable address still succeeds because the attacker controls the entire response set.

#### Testing and monitoring DoH flows

- Firefox: `Settings ➜ Network Settings ➜ Enable DNS over HTTPS` and provide the DoH endpoint (Cloudflare and NextDNS are built in). Chrome/Chromium: enable `chrome://flags/#dns-over-https` and configure the OS DNS servers to one of Chrome’s supported resolvers (e.g., `1.1.1.1`/`1.0.0.1`).
- You can query public DoH APIs directly, e.g. `curl -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name=example.com&type=A' | jq` to confirm the exact records browsers will cache.
- Intercepting DoH in Burp/ZAP still works because it is just HTTPS (binary DNS payload in the body). For packet-level inspection, export TLS keys (`export SSLKEYLOGFILE=~/SSLKEYLOGFILE.txt`) before launching the browser and let Wireshark decrypt the DoH sessions with the `dns` display filter to see when the browser stays on DoH or falls back to classic DNS.

### Real Protection against DNS Rebinding

- Use TLS in internal services
- Request authentication to access data
- Validate the Host header
- [https://wicg.github.io/private-network-access/](https://wicg.github.io/private-network-access/): Proposal to always send a pre-flight request when public servers want to access internal servers

## **Tools**

**Fuzz possible misconfigurations in CORS policies**

- [https://portswigger.net/bappstore/420a28400bad4c9d85052f8d66d3bbd8](https://portswigger.net/bappstore/420a28400bad4c9d85052f8d66d3bbd8)
- [https://github.com/chenjj/CORScanner](https://github.com/chenjj/CORScanner)
- [https://github.com/lc/theftfuzzer](https://github.com/lc/theftfuzzer)
- [https://github.com/s0md3v/Corsy](https://github.com/s0md3v/Corsy)
- [https://github.com/Shivangx01b/CorsMe](https://github.com/Shivangx01b/CorsMe)
- [https://github.com/omranisecurity/CorsOne](https://github.com/omranisecurity/CorsOne)

## References

- [https://portswigger.net/web-security/cors](https://portswigger.net/web-security/cors)
- [https://portswigger.net/web-security/cors/access-control-allow-origin](https://portswigger.net/web-security/cors/access-control-allow-origin)
- [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#CORS)
- [https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
- [https://www.codecademy.com/articles/what-is-cors](https://www.codecademy.com/articles/what-is-cors)
- [https://www.we45.com/blog/3-ways-to-exploit-misconfigured-cross-origin-resource-sharing-cors](https://www.we45.com/blog/3-ways-to-exploit-misconfigured-cross-origin-resource-sharing-cors)
- [https://medium.com/netscape/hacking-it-out-when-cors-wont-let-you-be-great-35f6206cc646](https://medium.com/netscape/hacking-it-out-when-cors-wont-let-you-be-great-35f6206cc646)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration)
- [https://medium.com/entersoftsecurity/every-bug-bounty-hunter-should-know-the-evil-smile-of-the-jsonp-over-the-browsers-same-origin-438af3a0ac3b](https://medium.com/entersoftsecurity/every-bug-bounty-hunter-should-know-the-evil-smile-of-the-jsonp-over-the-browsers-same-origin-438af3a0ac3b)
- [NCC Group - Impact of DNS over HTTPS (DoH) on DNS Rebinding Attacks](https://www.nccgroup.com/research-blog/impact-of-dns-over-https-doh-on-dns-rebinding-attacks/)
