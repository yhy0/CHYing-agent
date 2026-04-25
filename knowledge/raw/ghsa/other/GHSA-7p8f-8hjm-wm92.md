# Lookup operations do not take into account wildcards in SpiceDB

**GHSA**: GHSA-7p8f-8hjm-wm92 | **CVE**: CVE-2022-21646 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-20, CWE-155

**Affected Packages**:
- **github.com/authzed/spicedb** (go): = 1.3.0

## Description

### Impact
Any user making use of a wildcard relationship under the right hand branch of an `exclusion` or within an `intersection` operation will see `Lookup`/`LookupResources` return a resource as "accessible" if it is *not* accessible by virtue of the inclusion of the wildcard in the intersection or the right side of the exclusion.

For example, given schema:

```zed
definition user {}

definition resource {
   relation viewer: user
   relation banned: user | user:*
   permission view = viewer - banned
}
```

If `user:*` is placed into the `banned` relation for a particular resource, `view` should return false for *all* resources. in `v1.3.0`, the wildcard is ignored entirely in lookup's dispatch, resulting in the `banned` wildcard being ignored in the exclusion.

### Workarounds
Don't make use of wildcards on the right side of intersections or within exclusions. 

### References
https://github.com/authzed/spicedb/issues/358

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [SpiceDB](https://github.com/authzed/spicedb)
* Ask a question in the [SpiceDB Discord](https://authzed.com/discord)

