# Authentication bypass vulnerability in navidrome's subsonic endpoint

**GHSA**: GHSA-wq59-4q6r-635r | **CVE**: CVE-2023-51442 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-287

**Affected Packages**:
- **github.com/navidrome/navidrome** (go): <= 0.50.1

## Description

### Summary

A security vulnerability has been identified in navidrome's subsonic endpoint, allowing for authentication bypass. This exploit enables unauthorized access to any known account by utilizing a JSON Web Token (JWT) signed with the key "not so secret".

The vulnerability can only be exploited on instances that have never been restarted.

### Details

Navidrome supports an extension to the subsonic authentication scheme, where a JWT can be provided using a `jwt` query parameter instead of the traditional password or token and salt (corresponding to resp. the `p` or `t` and `s` query parameters).

During the first initialization, navidrome generates a random key that is then used by the authentication module to validate JWTs before extracting the username from the `sub` claim. If for some reason the key cannot be retrieved by the initialization code, a hardcoded value is used instead: "not so secret".

A bug in the order of operations during navidrome startup results in the authentication module initializing before the module responsible for generating and persisting the random key. As a consequence, the authentication module falls back to using the hardcoded value, which remains in use until the instance gets restarted. Additionally, an error that was meant to be logged when the fallback value is used does not get logged due to another bug, preventing the operator from becoming aware of the issue.

The flaw allows the creation of a JWT with the `sub` claim set to any existing user on the server, signed with the key "not so secret", which can then be used to authenticate against the subsonic endpoint with the chosen user's privileges.

After navidrome is restarted, the random key generated during the previous startup is loaded and the flaw becomes inexploitable.

### PoC

Generate a JWT token with the subject "admin", and key "not so secret" (e.g. online on: http://jwtbuilder.jamiekurtz.com; the other parameters can be left in, it doesn't seem that navidrome validates anything). In a shell, assign the token to the variable `JWT` (for the curl commands below).

```
$ podman run -d --name navidrome -p 127.0.0.1:4533:4533 -e ND_DEVAUTOCREATEADMINPASSWORD=password docker.io/deluan/navidrome:0.50.1
$ curl "http://localhost:4533/rest/ping.view?c=dummy&v=1&u=admin&jwt=$JWT"
<subsonic-response xmlns="http://subsonic.org/restapi" status="ok" version="1.16.1" type="navidrome" serverVersion="0.50.1 (f69c27d1)" openSubsonic="true"></subsonic-response>
```

The `ND_DEVAUTOCREATEADMINPASSWORD` parameter does not influence the bypass, it also works if the admin or extra users are created manually after starting navidrome.

Restarting navidrome prevents the bypass:

```
$ podman restart navidrome
$ curl "http://localhost:4533/rest/ping.view?c=dummy&v=1&u=admin&jwt=$JWT"
<subsonic-response xmlns="http://subsonic.org/restapi" status="failed" version="1.16.1" type="navidrome" serverVersion="0.50.1 (f69c27d1)" openSubsonic="true"><error code="40" message="Wrong username or password"></error></subsonic-response>
```

### Impact

This authentication bypass vulnerability potentially affects all instances that don't protect the subsonic endpoint `/rest/`, which is expected to be most instances in a standard deployment, and most instances in the reverse proxy setup too (as the documentation mentions to leave that endpoint unprotected).

The impact is limited by the fact that the flaw becomes inexploitable after a first restart, and the attacker needs to know the username of existing users on the instance.

For each known user, the attacker could mess with (create/delete/change) playlists, bookmarks, media annotations, shares (which are currently global) and radios. He is also able to get the user's email address (which is PII) with the `getUser` operation. And lastly he can use the media retrieval operations which could potentially affect the availability of the system.
