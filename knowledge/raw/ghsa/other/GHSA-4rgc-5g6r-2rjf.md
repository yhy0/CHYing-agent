# lakeFS logs S3 credentials in plain text

**GHSA**: GHSA-4rgc-5g6r-2rjf | **CVE**: N/A | **Severity**: high (CVSS 8.4)

**CWE**: CWE-312

**Affected Packages**:
- **github.com/treeverse/lakefs** (go): < 0.101.0

## Description

### Impact

S3 credentials are logged in plain text

```
S3Creds:{Key:AKIAIOSFODNN7EXAMPLE Secret:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

appears as part of the log message: 

```
time="2023-05-12T13:51:52Z" level=error msg="failed to perform diff" func="pkg/plugins/diff.(*Service).RunDiff" file="build/pkg/plugins/diff/service.go:124" error="rpc error: code = Canceled desc = stream terminated by RST_STREAM with error code: CANCEL" host="localhost:8000" method=GET operation_id=OtfDiff params="{TablePaths:{Left:{Ref:data_load@ Path:aggs/agg_variety/} Right:{Ref:data_load Path:aggs/agg_variety/} Base:{Ref: Path:}} S3Creds:{Key:AKIAIOSFODNN7EXAMPLE Secret:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY Endpoint:http://0.0.0.0:8000} Repo:example}" path="/api/v1/repositories/example/otf/refs/data_load%40/diff/data_load?table_path=aggs%2Fagg_variety%2F&type=delta" request_id=d3b6fdc7-2544-4c12-8e05-376f16e35a80 service_name=rest_api type=delta user=docker
```

Discovered when investigating [#5862](https://github.com/treeverse/lakeFS/issues/5862)


### Patches
_Has the problem been patched? What versions should users upgrade to?_

No

### Workarounds
_Is there a way for users to fix or remediate the vulnerability without upgrading?_

disable all logging? 

### References
_Are there any links users can visit to find out more?_


