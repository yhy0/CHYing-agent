# Valtimo scripting engine can be used to gain access to sensitive data or resources

**GHSA**: GHSA-w48j-pp7j-fj55 | **CVE**: CVE-2025-58059 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-78, CWE-200

**Affected Packages**:
- **com.ritense.valtimo:core** (maven): < 12.16.0.RELEASE
- **com.ritense.valtimo:core** (maven): >= 13.0.0.RELEASE, < 13.1.2.RELEASE

## Description

### Impact
Any admin that can create or modify and execute process-definitions could gain access to sensitive data or resources.

This includes but is not limited to:
- Running executables on the application host
- Inspecting and extracting data from the host environment or application properties
- Spring beans (application context, database pooling)

### Attack requirements
The following conditions have to be met in order to perform this attack:
- The user must be logged in
- The user must have the admin role (ROLE_ADMIN), which is required to change process definitions
- The user must have some knowledge about running scripts via a the Camunda/Operator engine

### Patches
Version 12.16.0 and 13.1.2 have been patched. It is strongly advised to upgrade.

### Workarounds
If no scripting is needed in any of the processes, it could be possible to disable it altogether via the `ProcessEngineConfiguration`:
```
@Component
class NoScriptEnginePlugin : ProcessEnginePlugin {
    override fun preInit(processEngineConfiguration: ProcessEngineConfigurationImpl) {}

    override fun postInit(processEngineConfiguration: ProcessEngineConfigurationImpl) {
        processEngineConfiguration.scriptEngineResolver = null
    }

    override fun postProcessEngineBuild(processEngine: ProcessEngine) {}
}
```
Warning: this workaround could lead to unexpected side-effects. Please test thoroughly.

### References
- Valtimo 12 and lower: [Camunda Scripting](https://docs.camunda.org/manual/latest/user-guide/process-engine/scripting/#custom-scriptengineresolver)
- Valtimo 13 and higher: [Operaton Scripting](https://docs.operaton.org/docs/documentation/user-guide/process-engine/scripting)
