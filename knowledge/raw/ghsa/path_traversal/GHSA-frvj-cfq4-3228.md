# Path traversal in Reposilite javadoc file expansion (arbitrary file creation/overwrite) (`GHSL-2024-073`)

**GHSA**: GHSA-frvj-cfq4-3228 | **CVE**: CVE-2024-36116 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-22

**Affected Packages**:
- **com.reposilite:reposilite-backend** (maven): >= 3.3.0, < 3.5.12

## Description

### Summary
Reposilite v3.5.10 is affected by an Arbitrary File Upload vulnerability via path traversal in expanding of Javadoc archives.

### Details
Reposilite provides support for JavaDocs files, which are archives that contain documentation for artifacts. Specifically, [JavadocEndpoints.kt](https://github.com/dzikoysk/reposilite/blob/68b73f19dc9811ccf10936430cf17f7b0e622bd6/reposilite-backend/src/main/kotlin/com/reposilite/javadocs/infrastructure/JavadocEndpoints.kt#L28) controller allows to expand the javadoc archive into the server's file system and return its content. The problem is in the way how the archives are expanded, specifically how the new filename is created:

[JavadocContainerService.kt#L127-L136](https://github.com/dzikoysk/reposilite/blob/68b73f19dc9811ccf10936430cf17f7b0e622bd6/reposilite-backend/src/main/kotlin/com/reposilite/javadocs/JavadocContainerService.kt#L127-L136)

```kotlin
jarFile.entries().asSequence().forEach { file ->
    if (file.isDirectory) {
        return@forEach
    }

     val path = Paths.get(javadocUnpackPath.toString() + "/" + file.name)

    path.parent?.also { parent -> Files.createDirectories(parent) }
    jarFile.getInputStream(file).copyToAndClose(path.outputStream())
}.asSuccess<Unit, ErrorResponse>()
```

The `file.name` taken from the archive can contain path traversal characters, such as '/../../../anything.txt', so the resulting extraction path can be outside the target directory.

### Impact

If the archive is taken from an untrusted source, such as Maven Central or JitPack for example, an attacker can craft a special archive to overwrite any local file on Reposilite instance. This could lead to remote code execution, for example by placing a new plugin into the '$workspace$/plugins' directory. Alternatively, an attacker can overwrite the content of any other package.

Note that the attacker can use its own malicious package from Maven Central to overwrite any other package on Reposilite.

### Steps to reproduce

1. Create a malicious javadoc archive that contains filenames with path traversal characters:
```bash
zip test-1.0-javadoc.jar ../../../../../../../../tmp/evil.txt index.html
```
Make sure that `../../../../../../../../tmp/evil.txt` and `index.html` files exist on the system where you create this archive.

2. Publish this archive to the repository which Reposilite is mirroring, such as Maven Central or JitPack. For the test purposes, I used my own server that imitates the upstream maven repository:
http://artsploit.com/maven/com/artsploit/reposilite-zipslip/1.0/reposilite-zipslip-1.0-javadoc.jar

3. Start Reposilite with 'releases' repository mirroring to 'http://artsploit.com/maven/'

4. Now, if the attacker send the request to http://localhost:8080/javadoc/releases/com/artsploit/reposilite-zipslip/1.0, the aforementioned archive will be obtained from  the http://artsploit.com/maven/com/artsploit/reposilite-zipslip/1.0/reposilite-zipslip-1.0-javadoc.jar address and its 'evil.txt' file will be expanded to '$workspace$/tmp/evil.txt'. Note that to perform this action, an attacker does not need to provide any credentials, as fetching from the mirrored repository does not require authentication.

6. Confirm that '$workspace$/tmp/evil.txt' is created on the server where Reposilite is running.

### Remediation

Normalize (remove all occurrences of `/../`) the `file.name` variable before concatenating it with `javadocUnpackPath`. E.g.:

```kotlin
val path = Paths.get(javadocUnpackPath.toString() + "/" + Paths.get(file.name).normalize().toString())
```


