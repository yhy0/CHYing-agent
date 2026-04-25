# Beego allows Reflected/Stored XSS in Beego's RenderForm() Function Due to Unescaped User Input

**GHSA**: GHSA-2j42-h78h-q4fg | **CVE**: CVE-2025-30223 | **Severity**: critical (CVSS 9.3)

**CWE**: CWE-79

**Affected Packages**:
- **github.com/beego/beego/v2** (go): < 2.3.6
- **github.com/beego/beego** (go): <= 1.12.14

## Description

### Summary

A Cross-Site Scripting (XSS) vulnerability exists in Beego's `RenderForm()` function due to improper HTML escaping of user-controlled data. This vulnerability allows attackers to inject malicious JavaScript code that executes in victims' browsers, potentially leading to session hijacking, credential theft, or account takeover. The vulnerability affects any application using Beego's `RenderForm()` function with user-provided data. Since it is a high-level function generating an entire form markup, many developers would assume it automatically escapes attributes (the way most frameworks do).

### Details

The vulnerability is located in the `renderFormField()` function in Beego's `templatefunc.go` file (around lines 316-356). This function directly injects user-provided values into HTML without proper escaping:

```go
return fmt.Sprintf(`%v<input%v%v name="%v" type="%v" value="%v"%v>`, 
    label, id, class, name, fType, value, requiredString)
```

None of the values (label, id, class, name, value) are properly HTML-escaped before being inserted into the HTML template. This allows attackers to break out of the attribute context or inject HTML tags directly.
The vulnerability can be exploited in two main ways:

- Attribute Injection: By injecting code into fields like DisplayName, an attacker can break out of the attribute context and execute JavaScript.
- Content Injection: By injecting HTML tags into textarea content, an attacker can execute JavaScript.

The `RenderForm()` function returns `template.HTML`, which bypasses Go's automatic HTML escaping, making this vulnerability particularly dangerous.

### PoC

Retrieve the following (secret) gist: https://gist.github.com/thevilledev/8fd0cab3f098320aa9daab04be59fd2b

To run it:

```go
go mod init beego-xss-poc
go mod tidy
go run poc.go
```

Open your browser and navigate to http://localhost:8080/

The application demonstrates the vulnerability through several examples:
- `/profile` - Shows a profile with malicious data in the Display Name and Bio fields
- `/admin` - Shows multiple user profiles, including one with malicious data
- `/submit` - Allows you to create your own profile with malicious data

In addition, you may use this Go test in `templatefunc_test.go`. The test passes, validating the vulnerability.

```go
func TestRenderFormXSSVulnerability(t *testing.T) {
	type UserProfile struct {
		DisplayName string `form:"displayName,text,Name:"`
		Bio         string `form:",textarea"`
	}

	// Test case 1: Attribute injection in input field
	maliciousUser := UserProfile{
		DisplayName: `" onmouseover="alert('XSS')" data-malicious="`,
		Bio:         "Normal bio text",
	}

	output := RenderForm(&maliciousUser)

	// The vulnerable output would contain the unescaped JavaScript
	if !strings.Contains(string(output), `onmouseover="alert('XSS')"`) {
		t.Errorf("Expected XSS vulnerability in attribute, but got safe output: %v", output)
	}

	// Test case 2: Script injection in textarea
	maliciousUser2 := UserProfile{
		DisplayName: "Normal Name",
		Bio:         `</textarea><script>alert('XSS')</script><textarea>`,
	}

	output = RenderForm(&maliciousUser2)

	// The vulnerable output would contain the unescaped script tag
	if !strings.Contains(string(output), `</textarea><script>alert('XSS')`) {
		t.Errorf("Expected XSS vulnerability in textarea content, but got safe output: %v", output)
	}
}
```

### Impact

This is a high-severity vulnerability with the following impacts:

- Cross-Site Scripting (XSS): Allows execution of arbitrary JavaScript in the context of the victim's browser.
- Session Hijacking: Attackers can steal session cookies and impersonate victims.
- Credential Theft: Attackers can create fake login forms to steal credentials.
- Account Takeover: Attackers can perform actions on behalf of the victim.
- Data Exfiltration: Sensitive data visible in the browser can be stolen.

This is particularly concerning in admin panels or user management interfaces where one user's data is displayed to another user (typically an administrator).

### Mitigation

The vulnerability can be fixed by properly escaping all user-provided values before inserting them into HTML, for example:

```go
// Convert value to string and escape it
valueStr := ""
if value != nil {
    valueStr = template.HTMLEscapeString(fmt.Sprintf("%v", value))
}

// Escape the name and label
escapedName := template.HTMLEscapeString(name)
escapedLabel := template.HTMLEscapeString(label)
escapedType := template.HTMLEscapeString(fType)

return fmt.Sprintf(`%v<input%v%v name="%v" type="%v" value="%v"%v>`, 
    escapedLabel, id, class, escapedName, escapedType, valueStr, requiredString)
```
