# Remote Code Execution for 2.4.1 and earlier

**GHSA**: GHSA-76f7-9v52-v2fw | **CVE**: CVE-2023-36812 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-74

**Affected Packages**:
- **net.opentsdb:opentsdb** (maven): <= 2.4.1

## Description

### Impact
OpenTSDB is vulnerable to Remote Code Execution vulnerability by writing user-controlled input to Gnuplot configuration file and running Gnuplot with the generated configuration.

### Patches
Patched in [07c4641471c6f5c2ab5aab615969e97211eb50d9](https://github.com/OpenTSDB/opentsdb/commit/07c4641471c6f5c2ab5aab615969e97211eb50d9) and further refined in https://github.com/OpenTSDB/opentsdb/commit/fa88d3e4b5369f9fb73da384fab0b23e246309ba

### Workarounds
Disable Gunuplot via `tsd.core.enable_ui = true` and remove the shell files https://github.com/OpenTSDB/opentsdb/blob/master/src/mygnuplot.bat and https://github.com/OpenTSDB/opentsdb/blob/master/src/mygnuplot.sh.
