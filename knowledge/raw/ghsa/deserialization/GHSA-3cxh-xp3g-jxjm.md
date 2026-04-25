# Apache ShardingSphere-Agent Deserialization of Untrusted Data vulnerability

**GHSA**: GHSA-3cxh-xp3g-jxjm | **CVE**: CVE-2023-28754 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.shardingsphere:shardingsphere** (maven): <= 5.3.2

## Description

Deserialization of Untrusted Data vulnerability in Apache ShardingSphere-Agent, which allows attackers to execute arbitrary code by constructing a special YAML configuration file.

The attacker needs to have permission to modify the ShardingSphere Agent YAML configuration file on the target machine, and the target machine can access the URL with the arbitrary code JAR.
An attacker can use SnakeYAML to deserialize java.net.URLClassLoader and make it load a JAR from a specified URL, and then deserialize javax.script.ScriptEngineManager to load code using that ClassLoader. When the ShardingSphere JVM process starts and uses the ShardingSphere-Agent, the arbitrary code specified by the attacker will be executed during the deserialization of the YAML configuration file by the Agent.

This issue affects ShardingSphere-Agent: through 5.3.2. This vulnerability is fixed in Apache ShardingSphere 5.4.0.
