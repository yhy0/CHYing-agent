# WordPress - Rce Techniques

## **Panel RCE**


**Modifying a php from the theme used (admin credentials needed)**

Appearance → Theme Editor → 404 Template (at the right)

Change the content for a php shell:

![](<../../images/image (384).png>)

Search in internet how can you access that updated page. In this case you have to access here: [http://10.11.1.234/wp-content/themes/twentytwelve/404.php](http://10.11.1.234/wp-content/themes/twentytwelve/404.php)

### MSF

You can use:

```bash
use exploit/unix/webapp/wp_admin_shell_upload
```

to get a session.


## Plugin RCE


### PHP plugin

It may be possible to upload .php files as a plugin.\
Create your php backdoor using for example:

![](<../../images/image (183).png>)

Then add a new plugin:

![](<../../images/image (722).png>)

Upload plugin and press Install Now:

![](<../../images/image (249).png>)

Click on Procced:

![](<../../images/image (70).png>)

Probably this won't do anything apparently, but if you go to Media, you will see your shell uploaded:

![](<../../images/image (462).png>)

Access it and you will see the URL to execute the reverse shell:

![](<../../images/image (1006).png>)

### Uploading and activating malicious plugin

This method involves the installation of a malicious plugin known to be vulnerable and can be exploited to obtain a web shell. This process is carried out through the WordPress dashboard as follows:

1. **Plugin Acquisition**: The plugin is obtained from a source like Exploit DB like [**here**](https://www.exploit-db.com/exploits/36374).
2. **Plugin Installation**:
   - Navigate to the WordPress dashboard, then go to `Dashboard > Plugins > Upload Plugin`.
   - Upload the zip file of the downloaded plugin.
3. **Plugin Activation**: Once the plugin is successfully installed, it must be activated through the dashboard.
4. **Exploitation**:
   - With the plugin "reflex-gallery" installed and activated, it can be exploited as it is known to be vulnerable.
   - The Metasploit framework provides an exploit for this vulnerability. By loading the appropriate module and executing specific commands, a meterpreter session can be established, granting unauthorized access to the site.
   - It's noted that this is just one of the many methods to exploit a WordPress site.

The content includes visual aids depicting the steps in the WordPress dashboard for installing and activating the plugin. However, it's important to note that exploiting vulnerabilities in this manner is illegal and unethical without proper authorization. This information should be used responsibly and only in a legal context, such as penetration testing with explicit permission.

**For more detailed steps check:** [**https://www.hackingarticles.in/wordpress-reverse-shell/**](https://www.hackingarticles.in/wordpress-reverse-shell/)


## From XSS to RCE


- [**WPXStrike**](https://github.com/nowak0x01/WPXStrike): _**WPXStrike**_ is a script designed to escalate a **Cross-Site Scripting (XSS)** vulnerability to **Remote Code Execution (RCE)** or other's criticals vulnerabilities in WordPress. For more info check [**this post**](https://nowak0x01.github.io/papers/76bc0832a8f682a7e0ed921627f85d1d.html). It provides **support for Wordpress Versions 6.X.X, 5.X.X and 4.X.X. and allows to:**
  - _**Privilege Escalation:**_ Creates an user in WordPress.
  - _**(RCE) Custom Plugin (backdoor) Upload:**_ Upload your custom plugin (backdoor) to WordPress.
  - _**(RCE) Built-In Plugin Edit:**_ Edit a Built-In Plugins in WordPress.
  - _**(RCE) Built-In Theme Edit:**_ Edit a Built-In Themes in WordPress.
  - _**(Custom) Custom Exploits:**_ Custom Exploits for Third-Party WordPress Plugins/Themes.
