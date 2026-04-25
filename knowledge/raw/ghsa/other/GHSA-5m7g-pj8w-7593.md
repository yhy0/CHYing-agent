# Vela Insecure Defaults

**GHSA**: GHSA-5m7g-pj8w-7593 | **CVE**: CVE-2022-39395 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-269

**Affected Packages**:
- **github.com/go-vela/server** (go): < 0.16.0
- **github.com/go-vela/worker** (go): < 0.16.0

## Description

### Impact
Some current default configurations for Vela allow exploitation and container breakouts.

#### Default Privileged Images

Running Vela plugins as privileged Docker containers allows a malicious user to easily break out of the container and gain access to the worker host operating system. On a fresh install of Vela without any additional configuration, the `target/vela-docker` plugin will run as a privileged container, even if the Vela administrators did not intend to allow for any privileged plugins, and even if the `vela.yml` configuration file does not use the `privileged = True` flag.

Privileged containers permit trivial breakouts, which can pose significant risk to the environment in which Vela is running.

#### Default Allowed Repositories

On a fresh install of Vela, anyone with a GitHub account (or other enabled source control management solution) is allowed to enable a repository within Vela and run builds. This means that, if a Vela instance is accessible to the public, a third party could add their own malicious repos to the Vela instance and run arbitrary code.

An example of a publicly accessible Vela instance would be one not protected behind a VPN. Whether Vela is publicly accessible depends on how Vela is set up, NOT how it is connected to GitHub.

#### Default Enabled Events allows Pull Requests

By default, Vela currently enables pull request events when a repository is Vela-enabled. Unless this default was changed when enabling each repository, anyone who can issue a pull request against a repository can trigger a Vela job.

This not only permits a third party to run arbitrary code in a Vela environment, but also poses an additional risk when secrets within Vela are configured to be available in pull requests, permitting anyone with access to create pull requests to access these secrets.

### Patches

Upgrade to 0.16.0 or later. After upgrading, Vela administrators will need to explicitly change the default settings to configure Vela as desired.

Some of the fixes will interrupt existing workflows and will require Vela administrators to modify default settings (see release notes for more information). However, not applying the patch (or workarounds) will continue existing risk exposure.

### Workarounds

#### Default Privileged Images

Instead of upgrading, the Vela administrators can adjust the worker's `VELA_RUNTIME_PRIVILEGED_IMAGES` setting to be explicitly empty:

`VELA_RUNTIME_PRIVILEGED_IMAGES=""`

By assigning `VELA_RUNTIME_PRIVILEGED_IMAGES` to an empty value it disallows any images from running as privileged containers in Vela.

#### Default Allowed Repositories

Instead of upgrading, the Vela administrators can leverage the `VELA_REPO_ALLOWLIST` setting on the server component to restrict access to a list of repositories that are allowed to be enabled.

By changing it from the default empty list (currently interpreted by Vela as "all repositories") to a list explicitly allowing specific repositories, Vela administrators can control what repositories are allowed to be enabled in Vela.

Vela's current default list of approved repositories that can be added to a Vela instance is an empty list. However this is currently interpreted as allowing all repositories.

In the updated version, a null value (the empty list) will be interpreted as permitting no repositories to be added to a Vela instance.

#### Default Enabled Events allows Pull Requests

Audit enabled repositories and disable `pull_requests` if they are not needed.

Instead of upgrading, the pull request trigger can be disabled on a per-repository basis.

Additional protection can be provided by preventing unauthorized users from submitting pull requests in GitHub (or other source control management solution).

### Residual Risk

#### Default Privileged Images

After applying the update, any repos that Vela administrators manually define as "trusted repos" will be able to run the manually-specified images that are allowed to run as privileged. Those repos will continue to be vulnerable to breakout, but applying the update will help protect against the risk of trivial breakout arising from an image running as a privileged container.

The recommendation is to utilize plugins that do not require privileged capabilities.

For example, utilize `target/vela-kaniko` instead of `target/vela-docker` as the Kaniko plugin does not require privileged access.

#### Default Allowed Repositories

Applying this update (or workaround) will protect against the risk of Vela interpreting the default empty list of approved repositories as "all repositories" rather than "no repositories" (the current default).

#### Default Enabled Events allows Pull Requests

Since this change only impacts newly enabled repositories, the update will not address the risk to existing enabled repositories resulting from Vela enabling pull request events when a repository is Vela-enabled.

Additionally, this change only impacts defaults; users can still configure their repositories to allow pull requests as triggering events.

In order to monitor risk going forward, refer to the `Workaround` section with the heading `Default Enabled Events allows Pull Requests`.

### For more information
If you have any questions or comments about this advisory:
* Email us at [vela@target.com](mailto:vela@target.com)

Affected products: `go-vela/worker`, `go-vela/server`, `go-vela/ui`, `go-vela/documentation`
