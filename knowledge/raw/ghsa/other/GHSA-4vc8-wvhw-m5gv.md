# Juju allows arbitrary executable uploads via authenticated endpoint without authorization

**GHSA**: GHSA-4vc8-wvhw-m5gv | **CVE**: CVE-2025-0928 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-285, CWE-434

**Affected Packages**:
- **github.com/juju/juju** (go): < 0.0.0-20250619215741-4034aa13c7cf

## Description

### Summary
You can affect the agent binaries used in a Juju controller and the code that is run in the binaries by simply having a user account on a controller. You aren't required to have a model or any permissions. This just requires a user account in the controller database.

### Details
Because of the way Juju upload tools code works in the controller it only checks that the user uploading agent binaries is authenticated and is a user tag. No more checks are performed and it allows that user to upload binaries to any model they like (as long as they know the model uuid) or upload binaries to the controller (attacker doesn't need to know any uuid's for controller or controller model).

Once the poison binaries have been uploaded any new machine that is started in the affected model or controller will get started with the poison binaries. Alternatively administrator's of the controller running either `juju upgrade-controller` or `juju upgrade-model` will force distribution of the poisoned binaries to all machines in either the model or poison the controllers themselves.

On top of this the exploit can be done with the Juju client tooling itself and no real knowledge on constructing raw API requests is required.

The tools handler is the main piece of code that is used in the APIServer for handling upload requests and persisting the data uploaded: The following code references is how Juju uses and defines this:
- The tools upload handler is defined here (https://github.com/juju/juju/blob/3.6/apiserver/apiserver.go#L972)
- The tools upload handler is created in the api server here (https://github.com/juju/juju/blob/4bcbd094097016b2fde926afd8c9e590eabb3f0c/apiserver/apiserver.go#L766C2-L766C25).
- The main authoriser that is used for the upload handler is created here (https://github.com/juju/juju/blob/4bcbd094097016b2fde926afd8c9e590eabb3f0c/apiserver/apiserver.go#L770C2-L770C28)
- The upload handler is registered for the model here (https://github.com/juju/juju/blob/4bcbd094097016b2fde926afd8c9e590eabb3f0c/apiserver/apiserver.go#L902)
- The upload handler is registered for the controller here (https://github.com/juju/juju/blob/4bcbd094097016b2fde926afd8c9e590eabb3f0c/apiserver/apiserver.go#L972)

The authoriser that is used (https://github.com/juju/juju/blame/4bcbd094097016b2fde926afd8c9e590eabb3f0c/apiserver/httpcontext.go#L209) only confirms that the logged in user is authenticated and authenticated as a user tag. No other checks are performed.

The `toolsUploaderHandler` also uses another server func for getting the Mongo state. This also confirms a logged in user but the state that is returned to the caller is scoped to whatever model the requester has asked for. No checks are performed to make sure that the user in question actually has access to this model or the controller. See code here (https://github.com/juju/juju/blob/4e50a28cdde17832aa31634915fbe7442dca6ab3/apiserver/httpcontext.go#L38). We end up here through a few layers of indirection of https://github.com/juju/juju/blob/4bcbd094097016b2fde926afd8c9e590eabb3f0c/apiserver/apiserver.go#L768

We can also see that when handlers are registered with no model uuid scope in the handler like the controller registration of the tools upload handler, the model uuid gets defaulted to that of the controller model. See (https://github.com/juju/juju/blob/4bcbd094097016b2fde926afd8c9e590eabb3f0c/apiserver/apiserver.go#L690).

### PoC
This proof of concept was done with the latest tip of the `juju/juju` 3.6 branch (https://github.com/juju/juju/commit/cd12b4951d657a980e113564bf2ea82f167589fd). Pull this code and work from inside of the root of the code base. It is expected that this security issue applies to 2.9 onwards as well.

Repo steps:

1. Bootstrap a new controller to lxd. This was done with a compiled client from the branch but there is no reason performing this action from latest snap won't produce the same result.
` juju bootstrap localhost sec-demo`

2. Add a new user to the controller. This is the user with no permissions or models that we will prove the problem with.
`juju add-user poisoner poisoner`

3. From step 2 save the registration string that the `juju` client prints out.

4. We are going to remove the local `juju` admin credentials and information that was made during bootstrap. We will use this later on for confirming the attack.
`mv ~/.local/share/juju /tmp/juju-bak`

5. Run the `juju` cli registration command for the new user that was saved from step 3. Set the new password to whatever you wish and then re-enter to login into the controller. After this step we are now logged in as an unprivileged user to the controller.

6. Apply the following patch to the currently checked out `juju` code base:
```
cat <<EOF | git apply -
diff --git a/cmd/jujud/main.go b/cmd/jujud/main.go
index f268509a52..1b01a74b66 100644
--- a/cmd/jujud/main.go
+++ b/cmd/jujud/main.go
@@ -315,6 +315,16 @@ func Main(args []string) int {
 		os.Exit(exit_err)
 	}

+	logger.Criticalf("----------------------")
+	logger.Criticalf("----------------------")
+	logger.Criticalf("----------------------")
+	logger.Criticalf("----------------------")
+	logger.Criticalf("Got access to the binary")
+	logger.Criticalf("----------------------")
+	logger.Criticalf("----------------------")
+	logger.Criticalf("----------------------")
+	logger.Criticalf("----------------------")
+
 	var code int
 	commandName := filepath.Base(args[0])
 	switch commandName {
diff --git a/version/version.go b/version/version.go
index 2bbc8968c8..40af52f337 100644
--- a/version/version.go
+++ b/version/version.go
@@ -18,7 +18,7 @@ import (
 // The presence and format of this constant is very important.
 // The debian/rules build recipe uses this value for the version
 // number of the release package.
-const version = "3.6.6"
+const version = "3.6.7"

 // UserAgentVersion defines a user agent version used for communication for
 // outside resources.
EOF
```

7. Set bogus model information. To make the `sync-agent-binary` command work below we need to set a bogus model that is in use by the client. This is done through the local `models.yaml` file. The `uuid` featured here does not matter at and can be set to anything that parses as a uuid in `juju`. This is just to trick the client tooling, the attacker could just manually construct the http request their self to bypass this.
```
cat <<EOF > ~/.local/share/juju/models.yaml
controllers:
  sec-demo:
    models:
      admin/controller:
        uuid: 4dde46dd-a514-491e-8a5f-b908b5310c02
        type: iaas
        branch: ""
    current-model: admin/controller
EOF
```

8. Next build the changes with `make simplestreams`.
9. The output of step 9 will provide an export command to run. Please execute this command to point the `juju` client at your local simple streams cache.
10. Next sync the compiled agent binaries from step 9 to the controller with `juju sync-agent-binary --debug --agent-version 3.6.7`.

**At this stage the controllers agent binary cache has been poisoned and the security issue has been proven.**

11. We can now swap back to the administrator user to start forcing binary circulation. `mv ~/.local/share/juju /tmp/juju-poison` and then `mv /tmp/juju-bak ~/.local/share/juju`

At this stage the issue can be demonstrated with just a simple `juju upgrade-controller` and a controller upgrade will kick off. You can also upgrade a model. When I was testing this my `upgrade-controller` failed to shut down the controller for reasons unrelated to this security issue. I was able to log into the controller and confirm with sha256sum that the controller had downloaded the new binaries and the checksums matched. They were also symlink as the new binaries to run for `machine-0`. This was under `/var/lib/juju/tools` on the controller machine.

It would also be possible to affect new machines coming up in a model by repeating the steps above but changing the version to that of the model that you want to be poisoned.

### Impact
This is a bad vulnerability in my opinion. It allows a user with no permissions to eventually consume an entire `juju` controller with poisoned binaries and gain access to all of the infrastructure and secrets on that controller. Through model migration it would also be possible to poison other controllers that the user doesn't have access to.

This also requires that an administrator upgrade or migrate aspects of the controller. But a bad actor could affect brand new machines coming up in the system straight away.
