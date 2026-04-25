# Administration Console authentication bypass in openfire xmppserver

**GHSA**: GHSA-gw42-f939-fhvm | **CVE**: CVE-2023-32315 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-22

**Affected Packages**:
- **org.igniterealtime.openfire:xmppserver** (maven): >= 3.10.0, < 4.6.8
- **org.igniterealtime.openfire:xmppserver** (maven): >= 4.7.0, < 4.7.5

## Description

An important security issue affects a range of versions of Openfire, the cross-platform real-time collaboration server based on the XMPP protocol that is created by the Ignite Realtime community. 

### Impact
Openfire's administrative console (the Admin Console), a web-based application, was found to be vulnerable to a path traversal attack via the setup environment. This permitted an unauthenticated user to use the unauthenticated Openfire Setup Environment in an already configured Openfire environment to access restricted pages in the Openfire Admin Console reserved for administrative users.

### Cause
Path traversal protections were already in place to protect against exactly this kind of attack, but didn’t defend against certain non-standard URL encoding for UTF-16 characters, that were not supported by the embedded webserver that was in use at the time.

A later upgrade of the embedded webserver included support for non-standard URL encoding of UTF-16 characters. The path traversal protections in place in Openfire were not updated to include protection against this new encoding. 

Openfire's API defines a mechanism for certain URLs to be excluded from web authentication (this, for example, is used for the login page). This mechanism allows for wildcards to be used, to allow for flexible URL pattern matching.

The combination of the wildcard pattern matching and path traversal vulnerability allows a malicious user to bypass authentication requirements for Admin Console pages.

### Affected versions
This vulnerability affects all versions of Openfire that have been released since April 2015, starting with version 3.10.0. The problem has been patched in Openfire release 4.7.5 and 4.6.8, and further improvements will be included in the yet-to-be released first version on the 4.8 branch (which is expected to be version 4.8.0).

### Problem Reproduction
To test if an instance of Openfire is affected, follow these steps. Open a browser in incognito mode, or otherwise ensure that there is no authenticated session with the Openfire admin console. Open the following URL (possibly modified for the hostname of the server that is running Openfire):

```http://localhost:9090/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp```

If this shows part of the openfire logfiles, then the instance of Openfire is affected by this vulnerability. Note that different versions of Openfire will show a different layout. Newer versions of Openfire can be expected to show log files on a dark background, while older versions will show a largely white page. (Depending on the content of the log file, this page might be empty, apart from a header!)

If there's a redirect to the login page, the instance is likely unaffected.

### Problem Resolution
The problem has been patched in [Openfire release 4.7.5 and 4.6.8](https://www.igniterealtime.org/downloads/#openfire), and further improvements will be included in the yet-to-be released first version on the 4.8 branch (which is expected to be version 4.8.0).

- In Openfire 4.6.8, 4.7.5 and 4.8.0, Path Traversal pattern detection has been improved to include detection of non-standard URL encodings, preventing any non UTF-8 characters.
- In Openfire 4.6.8, 4.7.5 and 4.8.0, a new configuration property (`adminConsole.access.allow-wildcards-in-excludes`) is introduced that controls the permissibility of using wildcards in URL-patterns that define exclusions to authentication.
- In Openfire 4.6.8, 4.7.5 and 4.8.0, the existing value that uses a wildcard in URL-patterns that define exclusions to authentication has been replaced by values that do not depend on a wildcard.
- In Openfire 4.6.8, 4.7.5 and 4.8.0, Setup-specific URL-patterns that define exclusions to authentication are no longer active after the setup process has finished.
- In Openfire 4.8.0, the embedded webserver will be updated to a version that no longer supports the non-standard URL encoding of UTF-16 characters.
- In Openfire 4.8.0, the embedded webserver that serves the Openfire administrative console will bind to the loopback network interface by default.

Be aware that the new configuration properties can interfere with the functionality of certain Openfire plugins. This is especially true for plugins that bind a (web)endpoint to the embedded webserver that serves the Openfire administrative console, like current versions of the REST API plugin do. For these plugins to remain functional and/or reachable, it might be required to toggle the property `adminConsole.access.allow-wildcards-in-excludes` to `true`, and to avoid binding the embedded webserver to the loopback network interface only.

When your server uses older versions of the following plugins, make sure to upgrade them:

- [Random Avatar plugin](https://www.igniterealtime.org/projects/openfire/plugin-archive.jsp?plugin=randomavatar), update to version 1.1.0 or later.
- [Monitoring Service plugin](https://www.igniterealtime.org/projects/openfire/plugin-archive.jsp?plugin=monitoring), update to version 2.5.0 or later.
- [HTTP File Upload plugin](https://www.igniterealtime.org/projects/openfire/plugin-archive.jsp?plugin=httpfileupload), update to version 1.3.0 or later.

### Mitigation
If an Openfire upgrade isn’t available for your release, or isn’t quickly actionable, you can take any of the following steps to mitigate the risk for your Openfire environment.

Be aware: through Openfire plugins, the effectiveness of some mitigations listed below can be reduced, while other mitigations might affect the functionality of plugins. Particular care should be taken when using the Monitoring Service plugin, REST API plugin, User Service plugin and/or Random Avatar plugin.

#### Restrict network access
Use network security measures (network ACLs and/or firewalls, VPNs) to ensure only trusted members of your community have access to the Openfire Admin Console. As a general rule, never expose the Openfire Admin Console to the general internet.

Examples:
* On a linux machine running `ufw`, deny ports 9090 and 9091 on non-loopback interfaces
* On a Windows machine, restrict the rules that open ports 9090 and 9091 to only allow traffic from the IPv4 and/or IPv6 loopback addresses
* On AWS cloud infrastructure, use EC2 Security Groups to restrict ports 9090 and 9091 to trusted IP addresses. If the trusted range is necessarily too broad, consider opening and closing the ports only as necessary
* If using Docker, instead of `docker run ... -p 5222:5222 -p 9090:9090 -p 9091:9091 openfire` prevent remote access to the Admin Console with `docker run ... -p 5222:5222 -p 127.0.0.1:9090:9090 -p 127.0.0.1:9091:9091 openfire`


#### Modify runtime configuration file
To close the avenue of potential attack, a runtime configuration file of Openfire can be modified.

In Openfire's installation directory, find the file `plugins/admin/webapp/WEB-INF/web.xml`. After creating a backup of this file, edit the original file.

The content of this file is XML. Find a `<filter>` element, that contains the `<filter-name>AuthCheck</filter-name>` child element. Depending on your version of Openfire, it will look similar to this:

```xml
<filter>
    <filter-name>AuthCheck</filter-name>
    <filter-class>org.jivesoftware.admin.AuthCheckFilter</filter-class>
    <init-param>
        <param-name>excludes</param-name>
        <param-value>
            login.jsp,index.jsp?logout=true,setup/index.jsp,setup/setup-*,.gif,.png,error-serverdown.jsp,loginToken.jsp
        </param-value>
    </init-param>
</filter>
```
The value inside of the `param-value` element is a comma-separated list of values. From this list, remove all `*` (asterisk) characters.

Save the file, and restart Openfire for the change to take effect.

Note that no guarantees can be given that this runtime configuration change persists over time. Ensure to monitor the presence of the fix. It is recommended to upgrade to a safe version of Openfire as soon as possible.

A side-effect of this change is that the Openfire web-based setup wizard will not function properly (functionality can be restored by reverting the change). This wizard is typically used only when initially installing Openfire.

#### Bind admin console to loopback interface
The Openfire admin console is a web-based application. By default, the corresponding webserver (that is embedded in Openfire) binds to all network interfaces of the host that it is running on.

The admin console can be configured to bind to a specific network interface. This will prevent it from being accessed through other network interfaces. By configuring the admin console to bind to the local loopback interface, it is accessible only to users on the server itself. This reduces the avenue of attack.

Note that several Openfire plugins expose part or all of their functionality through the admin console webserver. The REST API plugin, for example, serves its endpoints via this webserver. Availability of this functionality will be affected by binding the webserver to a specific network interface.

To bind the webserver of the Openfire admin console to a specific network interface, the 'openfire.xml' configuration file can be used.

In Openfire's installation directory, locate the file `conf/openfire.xml`. After creating a backup of this file, edit the original file.

The content of this file is XML. Find the `<adminConsole>` element that is a direct child element of the root `<jive>` element. Add a new element, named `<interface>` as a child element of `<adminConsole>`. The value of the `<interface>` element should be the name of the loopback interface or interface address. Setting value to `127.0.0.1` works on all tested environments (using values like  `lo` on most Linux systems or `lo0` on macOS will have the same effect).

The resulting fragment of the `openfire.xml` file will look similar to this:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<jive>
  <adminConsole>
      <interface>127.0.0.1</interface>
      <port>9090</port>
      <securePort>9091</securePort>
  </adminConsole>

  ...
```

Save the file, and restart Openfire for the change to take effect.

#### Use AuthFilterSanitizer plugin

The Ignite Realtime community has made available a new plugin, called the AuthFilterSanitizer plugin. The plugin can be installed from the Openfire admin console, or can be downloaded from [the plugin's archive page](https://www.igniterealtime.org/projects/openfire/plugin-archive.jsp?plugin=authfiltersanitizer) on the IgniteRealtime.org community website.

This plugin periodically removes entries for Openfire's authentication filter that are susceptible to abuse, closing the avenue of potential attack.

Note that this plugin might interfere with functionality that depends on the abuse-susceptible entries in the authentication filter that might be provided by plugins.

### Credit

This issue was originally reported by Siebene@ who has our gratitude for the responsible and detailed disclosure of the issue! 

We are grateful for the resources made available by Surevine ltd. They were instrumental in addressing the issue listed in this advisory.

### References
- [Ignite Realtime community site](https://www.igniterealtime.org/)
- [Openfire releases download page](https://www.igniterealtime.org/downloads/#openfire)
- [Openfire AuthFilter Sanitizer plugin releases download page](https://www.igniterealtime.org/projects/openfire/plugin-archive.jsp?plugin=authfiltersanitizer)
- [Openfire HTTP File Upload plugin releases download page](https://www.igniterealtime.org/projects/openfire/plugin-archive.jsp?plugin=httpfileupload)
- [Openfire Monitoring Service plugin releases download page](https://www.igniterealtime.org/projects/openfire/plugin-archive.jsp?plugin=monitoring)
- [Openfire Random Avatar plugin releases download page](https://www.igniterealtime.org/projects/openfire/plugin-archive.jsp?plugin=randomavatar)
- [OWASP: Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Wikipedia: URL encoding, section 'Non-standard implementations'](https://en.wikipedia.org/wiki/URL_encoding#Non-standard_implementations)
- [Issue OF-2595 in Openfire's issue tracker](https://igniterealtime.atlassian.net/browse/OF-2595)
- [Jetty CVE-2021-34429](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34429)
