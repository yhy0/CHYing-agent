# Cookies are sent to external images in rendered diff (and server side request forgery)

**GHSA**: GHSA-7rfg-6273-f5wp | **CVE**: CVE-2023-48240 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-201, CWE-918

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-diff-xml** (maven): >= 11.10.1, < 14.10.15
- **org.xwiki.platform:xwiki-platform-diff-xml** (maven): >= 15.0-rc-1, < 15.5.1
- **org.xwiki.platform:xwiki-platform-diff-xml** (maven): >= 15.6-rc-1, < 15.6

## Description

### Impact
The rendered diff in XWiki embeds images to be able to compare the contents and not display a difference for an actually unchanged image. For this, XWiki requests all embedded images on the server side. These requests are also sent for images from other domains and include all cookies that were sent in the original request to ensure that images with restricted view right can be compared. This allows an attacker to steal login and session cookies that allow impersonating the current user who views the diff. The attack can be triggered with an image that references the rendered diff, thus making it easy to trigger.

More concretely, to reproduce, add 101 different images with references to the attacker's server. In any place add an image with a reference to `/xwiki/bin/view/Image%20Cookie%20Test/?xpage=changes&rev1=1.1&rev2=2.1&include=renderedChanges` where `Image%20Cookie%20Test` needs to be replaced by the path to the document with the images and the two revisions should match the revision before/after adding the images. Whenever a user views that image, the user's login cookies should be sent to the attacker's server. The 101 images are to circumvent the cache that has a default maximum size of 100 entries.

Apart from stealing login cookies, this also allows server-side request forgery (the result of any successful request is returned in the image's source) and viewing protected content as once a resource is cached, it is returned for all users. As only successful requests are cached, the cache will be filled by the first user who is allowed to access the resource.

### Patches
This has been patched in XWiki 14.10.15, 15.5.1 and 15.6. The rendered diff now only downloads images from trusted domains. Further, cookies are only sent when the image's domain is the same the requested domain. The cache has been changed to be specific for each user.

### Workarounds
As a workaround, the image embedding feature can be disabled by deleting `xwiki-platform-diff-xml-<version>.jar` in `WEB-INF/lib/`.

### References
* https://jira.xwiki.org/browse/XWIKI-20818
* https://github.com/xwiki/xwiki-platform/commit/bff0203e739b6e3eb90af5736f04278c73c2a8bb
