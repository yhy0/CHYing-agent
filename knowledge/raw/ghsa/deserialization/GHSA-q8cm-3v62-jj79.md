# Remote code execution in Apache Jackrabbit

**GHSA**: GHSA-q8cm-3v62-jj79 | **CVE**: CVE-2023-37895 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.jackrabbit:jackrabbit-webapp** (maven): >= 2.21.0, < 2.21.18
- **org.apache.jackrabbit:jackrabbit-webapp** (maven): >= 1.0.0, < 2.20.11
- **org.apache.jackrabbit:jackrabbit-standalone** (maven): >= 2.21.0, < 2.21.18
- **org.apache.jackrabbit:jackrabbit-standalone** (maven): >= 1.0.0, < 2.20.11
- **org.apache.jackrabbit:jackrabbit-standalone-components** (maven): >= 2.21.0, < 2.21.18
- **org.apache.jackrabbit:jackrabbit-standalone-components** (maven): >= 1.0.0, < 2.20.11

## Description

Java object deserialization issue in Jackrabbit webapp/standalone on all platforms allows attacker to remotely execute code via RMIVersions up to (including) 2.20.10 (stable branch) and 2.21.17 (unstable branch) use the component "commons-beanutils", which contains a class that can be used for remote code execution over RMI.

Users are advised to immediately update to versions 2.20.11 or 2.21.18. Note that earlier stable branches (1.0.x .. 2.18.x) have been EOLd already and do not receive updates anymore.

In general, RMI support can expose vulnerabilities by the mere presence of an exploitable class on the classpath. Even if Jackrabbit itself does not contain any code known to be exploitable anymore, adding other components to your server can expose the same type of problem. We therefore recommend to disable RMI access altogether (see further below), and will discuss deprecating RMI support in future Jackrabbit releases.

How to check whether RMI support is enabledRMI support can be over an RMI-specific TCP port, and over an HTTP binding. Both are by default enabled in Jackrabbit webapp/standalone.

The native RMI protocol by default uses port 1099. To check whether it is enabled, tools like "netstat" can be used to check.

RMI-over-HTTP in Jackrabbit by default uses the path "/rmi". So when running standalone on port 8080, check whether an HTTP GET request on localhost:8080/rmi returns 404 (not enabled) or 200 (enabled). Note that the HTTP path may be different when the webapp is deployed in a container as non-root context, in which case the prefix is under the user's control.

Turning off RMIFind web.xml (either in JAR/WAR file or in unpacked web application folder), and remove the declaration and the mapping definition for the RemoteBindingServlet:

        <servlet>
            <servlet-name>RMI</servlet-name>
            <servlet-class>org.apache.jackrabbit.servlet.remote.RemoteBindingServlet</servlet-class>
        </servlet>

        <servlet-mapping>
            <servlet-name>RMI</servlet-name>
            <url-pattern>/rmi</url-pattern>
        </servlet-mapping>

Find the bootstrap.properties file (in $REPOSITORY_HOME), and set

         rmi.enabled=false

    and also remove

         rmi.host
         rmi.port
         rmi.url-pattern

 If there is no file named bootstrap.properties in $REPOSITORY_HOME, it is located somewhere in the classpath. In this case, place a copy in $REPOSITORY_HOME and modify it as explained.

 
