# Apache UIMA Java SDK Deserialization of Untrusted Data, Improper Input Validation vulnerability

**GHSA**: GHSA-5r8j-qmcm-7g7q | **CVE**: CVE-2023-39913 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-20, CWE-502

**Affected Packages**:
- **org.apache.uima:uimaj** (maven): < 3.5.0

## Description

Deserialization of Untrusted Data, Improper Input Validation vulnerability in Apache UIMA Java SDK. This issue affects Apache UIMA Java SDK before 3.5.0.

Users are recommended to upgrade to version 3.5.0, which fixes the issue.

There are several locations in the code where serialized Java objects are deserialized without verifying the data. This affects in particular:
  *  the deserialization of a Java-serialized CAS, but also other binary CAS formats that include TSI information using the CasIOUtils class;
  *  the CAS Editor Eclipse plugin which uses the the CasIOUtils class to load data;
  *  the deserialization of a Java-serialized CAS of the Vinci Analysis Engine service which can receive using Java-serialized CAS objects over network connections;
  *  the CasAnnotationViewerApplet and the CasTreeViewerApplet;
  *  the checkpointing feature of the CPE module.

Note that the UIMA framework by default does not start any remotely accessible services (i.e. Vinci) that would be vulnerable to this issue. A user or developer would need to make an active choice to start such a service. However, users or developers may use the CasIOUtils in their own applications and services to parse serialized CAS data. They are affected by this issue unless they ensure that the data passed to CasIOUtils is not a serialized Java object.

When using Vinci or using CasIOUtils in own services/applications, the unrestricted deserialization of Java-serialized CAS files may allow arbitrary (remote) code execution.

As a remedy, it is possible to set up a global or context-specific ObjectInputFilter (cf.  https://openjdk.org/jeps/290  and  https://openjdk.org/jeps/415 ) if running UIMA on a Java version that supports it. 

Note that Java 1.8 does not support the ObjectInputFilter, so there is no remedy when running on this out-of-support platform. An upgrade to a recent Java version is strongly recommended if you need to secure an UIMA version that is affected by this issue.

To mitigate the issue on a Java 9+ platform, you can configure a filter pattern through the "jdk.serialFilter" system property using a semicolon as a separator:

To allow deserializing Java-serialized binary CASes, add the classes:
  *  org.apache.uima.cas.impl.CASCompleteSerializer
  *  org.apache.uima.cas.impl.CASMgrSerializer
  *  org.apache.uima.cas.impl.CASSerializer
  *  java.lang.String

To allow deserializing CPE Checkpoint data, add the following classes (and any custom classes your application uses to store its checkpoints):
  *  org.apache.uima.collection.impl.cpm.CheckpointData
  *  org.apache.uima.util.ProcessTrace
  *  org.apache.uima.util.impl.ProcessTrace_impl
  *  org.apache.uima.collection.base_cpm.SynchPoint

Make sure to use "!*" as the final component to the filter pattern to disallow deserialization of any classes not listed in the pattern.

Apache UIMA 3.5.0 uses tightly scoped ObjectInputFilters when reading Java-serialized data depending on the type of data being expected. Configuring a global filter is not necessary with this version.
