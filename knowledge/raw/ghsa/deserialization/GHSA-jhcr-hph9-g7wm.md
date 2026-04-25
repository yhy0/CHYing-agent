# Deserialization vulnerability in Helix workflow and REST

**GHSA**: GHSA-jhcr-hph9-g7wm | **CVE**: CVE-2023-38647 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.helix:helix-core** (maven): < 1.3.0
- **org.apache.helix:helix-rest** (maven): < 1.3.0

## Description

An attacker can use SnakeYAML to deserialize java.net.URLClassLoader and make it load a JAR from a specified URL, and then deserialize javax.script.ScriptEngineManager to load code using that ClassLoader. This unbounded deserialization can likely lead to remote code execution. The code can be run in Helix REST start and Workflow creation.

Affect all the versions lower and include 1.2.0.

Affected products: helix-core, helix-rest

Mitigation: Short term, stop using any YAML based configuration and workflow creation.
                  Long term, all Helix version bumping up to 1.3.0 


