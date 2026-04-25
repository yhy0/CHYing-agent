# jooby-pac4j: deserialization of untrusted data

**GHSA**: GHSA-7c5v-895v-w4q5 | **CVE**: CVE-2025-31129 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-502

**Affected Packages**:
- **io.jooby:jooby-pac4j** (maven): < 2.17.0
- **io.jooby:jooby-pac4j** (maven): >= 3.0.0.M1, < 3.7.0

## Description

### Impact

Versions after 2.x and before 3.x of io.jooby:jooby-pac4j can cause deserialization of untrusted data

### Patches

- 2.17.0 (2.x)
- 3.7.0 (3.x)

### Workarounds

- Not using io.jooby:jooby-pac4j until it gets patches.
- Check what values you put/save on session

### References

Version 2.x:

https://github.com/jooby-project/jooby/blob/v2.x/modules/jooby-pac4j/src/main/java/io/jooby/internal/pac4j/SessionStoreImpl.java#L39-L45

Version 3.x:
https://github.com/jooby-project/jooby/blob/v3.6.1/modules/jooby-pac4j/src/main/java/io/jooby/internal/pac4j/SessionStoreImpl.java#L77-L84

### Cause

In module pac4j io.jooby.internal.pac4j.SessionStoreImpl#get , it is used to handle sessions , and trying to get key value. In strToObject function ,it's trying to deserialize value when value starts with "b64~" , which might cause deserialization of untrusted data.

[modules/jooby-pac4j/src/main/java/io/jooby/internal/pac4j/SessionStoreImpl.java](https://github.com/jooby-project/jooby/blob/v3.6.1/modules/jooby-pac4j/src/main/java/io/jooby/internal/pac4j/SessionStoreImpl.java#L77-L84)

Here's a small demo using SessionStoreImpl#get to handle sessions ,and user can pass parameters.

![屏幕截图 2025-03-25 051325](https://github.com/user-attachments/assets/93039a06-d4f1-458a-8595-736b3fede345)

And following below is exploiting successfully(execute calculator)

![屏幕截图 2025-03-24 015128（1）](https://github.com/user-attachments/assets/415cf20c-dda0-4634-83ae-f8fa89677a16)
