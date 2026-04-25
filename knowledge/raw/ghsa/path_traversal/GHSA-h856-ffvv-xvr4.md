# Jenkins Remoting library arbitrary file read vulnerability

**GHSA**: GHSA-h856-ffvv-xvr4 | **CVE**: CVE-2024-43044 | **Severity**: high (CVSS 9.1)

**CWE**: CWE-22, CWE-754

**Affected Packages**:
- **org.jenkins-ci.main:remoting** (maven): < 3206.3208
- **org.jenkins-ci.main:remoting** (maven): >= 3248, < 3248.3250
- **org.jenkins-ci.main:remoting** (maven): >= 3256, < 3256.3258
- **org.jenkins-ci.main:jenkins-core** (maven): < 2.452.4
- **org.jenkins-ci.main:jenkins-core** (maven): >= 2.460, < 2.462.1
- **org.jenkins-ci.main:jenkins-core** (maven): >= 2.470, < 2.471

## Description

Jenkins uses the Remoting library (typically `agent.jar` or `remoting.jar`) for the communication between controller and agents. This library allows agents to load classes and classloader resources from the controller, so that Java objects sent from the controller (build steps, etc.) can be executed on agents.

In addition to individual class and resource files, Remoting also allows Jenkins plugins to transmit entire jar files to agents using the `Channel#preloadJar` API. As of publication of this advisory, this feature is used by the following plugins distributed by the Jenkins project: bouncycastle API, Groovy, Ivy, TeamConcert

In Remoting 3256.v88a_f6e922152 and earlier, except 3206.3208.v409508a_675ff and 3248.3250.v3277a_8e88c9b_, included in Jenkins 2.470 and earlier, LTS 2.452.3 and earlier, calls to `Channel#preloadJar` result in the retrieval of files from the controller by the agent using `ClassLoaderProxy#fetchJar`. Additionally, the implementation of `ClassLoaderProxy#fetchJar` invoked on the controller does not restrict paths that agents could request to read from the controller file system.

This allows agent processes, code running on agents, and attackers with Agent/Connect permission to read arbitrary files from the Jenkins controller file system.

The Remoting library in Jenkins 2.471, LTS 2.452.4, LTS 2.462.1 now sends jar file contents with `Channel#preloadJar` requests, the only use case of `ClassLoaderProxy#fetchJar` in agents, so that agents do not need to request jar file contents from controllers anymore.

To retain compatibility with older versions of Remoting in combination with the plugins listed above, `ClassLoaderProxy#fetchJar` is retained and otherwise unused, just deprecated. Its implementation in Jenkins 2.471, LTS 2.452.4, LTS 2.462.1 was changed so that it is now limited to retrieving jar files referenced in the core classloader or any plugin classloader.
