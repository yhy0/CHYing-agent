# OliveTin's unsafe parsing of UniqueTrackingId can be used to write files

**GHSA**: GHSA-364q-w7vh-vhpc | **CVE**: CVE-2026-31817 | **Severity**: high (CVSS 8.5)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/OliveTin/OliveTin** (go): < 0.0.0-20260309102040-b03af0e2eca3

## Description

When the `saveLogs` feature is enabled, OliveTin persists execution log entries to disk. The filename used for these log files is constructed in part from the user-supplied `UniqueTrackingId` field in the `StartAction` API request. This value is not validated or sanitized before being used in a file path, allowing an attacker to use directory traversal sequences (e.g., `../../../`) to write files to arbitrary locations on the filesystem.
### Affected Code

**Entry point — `service/internal/api/api.go` (line 130):**

The `UniqueTrackingId` from the API request is passed directly to the executor without validation:

```go
execReq := executor.ExecutionRequest{
    Binding:    pair,
    TrackingID: req.Msg.UniqueTrackingId, // user-controlled, no validation
    // ...
}
```

**Tracking ID accepted as-is — `service/internal/executor/executor.go` (lines 508–512):**

The tracking ID is only replaced with a UUID if it is empty or a duplicate. Any other string, including one containing path separators, is accepted:

```go
_, isDuplicate := e.GetLog(req.TrackingID)

if isDuplicate || req.TrackingID == "" {
    req.TrackingID = uuid.NewString()
}
```

**Filename construction — `service/internal/executor/executor.go` (line 1042):**

The tracking ID is interpolated directly into the log filename:

```go
filename := fmt.Sprintf("%v.%v.%v",
    req.logEntry.ActionTitle,
    req.logEntry.DatetimeStarted.Unix(),
    req.logEntry.ExecutionTrackingID,
)
```

**File write — `service/internal/executor/executor.go` (lines 1068–1069 and 1082–1083):**

The filename is joined to the configured log directory using `path.Join`, which calls `path.Clean` internally. `path.Clean` resolves `..` path segments, causing the final file path to escape the intended directory:

```go
// Results file (.yaml)
filepath := path.Join(dir, filename+".yaml")
err = os.WriteFile(filepath, data, 0600)

// Output file (.log)
filepath := path.Join(dir, filename+".log")
err := os.WriteFile(filepath, []byte(data), 0600)
```

### Proof of Concept

An attacker sends the following `StartAction` request (Connect RPC or REST):

```json
{
  "bindingId": "<any-executable-action-id>",
  "uniqueTrackingId": "../../../tmp/pwned"
}
```

Assuming the action title is `Ping the Internet` and the timestamp is `1741320000`, the constructed filename becomes:

```
Ping the Internet.1741320000.../../../tmp/pwned
```

When `path.Join` processes this with a configured results directory like `/var/olivetin/logs`:

```
path.Join("/var/olivetin/logs", "Ping the Internet.1741320000.../../../tmp/pwned.yaml")
```

`path.Clean` resolves the traversal:

1. Path segments: `["var", "olivetin", "logs", "Ping the Internet.1741320000...", "..", "..", "..", "tmp", "pwned.yaml"]`
2. The `..` segments traverse upward past the log directory.
3. Final resolved path: `/tmp/pwned.yaml`

Two files are written:

- **`.yaml` file** — contains YAML-serialized `InternalLogEntry` (action title, icon, timestamps, exit code, output, tags, username, tracking ID)
- **`.log` file** — contains the raw command output (potentially attacker-influenced if the action echoes its arguments)

### Impact

- **Arbitrary file write** to any path writable by the OliveTin process.
- OliveTin frequently runs as root inside Docker containers, so the writable scope is often the entire filesystem.
- An attacker could:
  - Overwrite OliveTin's own `sessions.yaml` to inject authenticated sessions.
  - Write to entity file directories to inject malicious entity data.
  - Write to system cron directories or other locations to achieve remote code execution.
  - Cause denial of service by overwriting critical system files.

### Suggested Fix

Validate the `UniqueTrackingId` to ensure it only contains safe characters before use. A strict UUID format check is the simplest approach:

```go
import "regexp"

var validTrackingID = regexp.MustCompile(`^[a-fA-F0-9\-]+$`)

// In ExecRequest, before accepting the user-supplied ID:
if req.TrackingID == "" || !validTrackingID.MatchString(req.TrackingID) {
    req.TrackingID = uuid.NewString()
}
```

Alternatively, sanitize the filename in `stepSaveLog` by stripping or rejecting path separators and `..` sequences.
