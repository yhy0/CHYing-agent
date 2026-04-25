# Absent Input Validation in BinaryHttpParser

**GHSA**: GHSA-q8f2-hxq5-cp4h | **CVE**: CVE-2024-40642 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-20

**Affected Packages**:
- **io.netty.incubator:netty-incubator-codec-bhttp** (maven): < 0.0.13.Final

## Description

### Summary
`BinaryHttpParser` does not properly validate input values thus giving attackers almost complete control over the HTTP requests constructed from the parsed output. Attackers can abuse several issues individually to perform various injection attacks including HTTP request smuggling, desync attacks, HTTP header injections, request queue poisoning, caching attacks and Server Side Request Forgery (SSRF). Attacker could also combine several issues to create well-formed messages for other text-based protocols which may result in attacks beyond the HTTP protocol.

### Details

**Path, Authority, Scheme**
The BinaryHttpParser class implements the readRequestHead method which performs most of the relevant parsing of the received request. The data structure prefixes values with a variable length integer value. The algorithm to create a variable length integer value is below:

```
def encode_int(n):
    if n < 64:
        base = 0x00
        l = 1
    elif n in range(64, 16384):
        base = 0x4000
        l = 2
    elif n in range(16384, 1073741824):
        base = 0x80000000
        l = 4
    else:
        base = 0xc000000000000000
        l = 8
   encoded = base | n
   return encoded.to_bytes()
```

The parsing code below first gets the lengths of the values from the prefixed variable length integer. After it has all of the lengths and calculates all of the indices, the parser casts the applicable slices of the ByteBuf to String. Finally, it passes these values into a new `DefaultBinaryHttpRequest` object where no further parsing or validation occurs.

```
//netty-incubator-codec-ohttp/codec-bhttp/src/main/java/io/netty/incubator/codec/bhttp/BinaryHttpParser.java

public final class BinaryHttpParser {
   ...
    private static BinaryHttpRequest readRequestHead(ByteBuf in, boolean knownLength, int maxFieldSectionSize) {
        ...
        final long pathLength = getVariableLengthInteger(in, pathLengthIdx, pathLengthBytes);
        ...
        final int pathIdx = pathLengthIdx + pathLengthBytes;
        ...
/*417*/ String method = in.toString(methodIdx, (int) methodLength, StandardCharsets.US_ASCII);
/*418*/ String scheme = in.toString(schemeIdx, (int) schemeLength, StandardCharsets.US_ASCII);
/*419*/ String authority = in.toString(authorityIdx, (int) authorityLength, StandardCharsets.US_ASCII);
/*420*/ String path = in.toString(pathIdx, (int) pathLength, StandardCharsets.US_ASCII);

/*422*/ BinaryHttpRequest request = new DefaultBinaryHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.valueOf(method),
                scheme, authority, path, headers);
        in.skipBytes(sumBytes);
        return request;
    }
   ...
}
```

**Request Method**
On line 422 above, the parsed method value is passed into `HttpMethod.valueOf` method. The return value from this is passed to the `DefaultBinaryHttpRequest` constructor.

Below is the code for HttpMethod.valueOf:

```
    public static HttpMethod valueOf(String name) {
        // fast-path
        if (name == HttpMethod.GET.name()) {
            return HttpMethod.GET;
        }
        if (name == HttpMethod.POST.name()) {
            return HttpMethod.POST;
        }
        // "slow"-path
        HttpMethod result = methodMap.get(name);
        return result != null ? result : new HttpMethod(name);
    }
```

If the result of `methodMap.get` is not `null`, then a new arbitrary `HttpMethod` instance will be returned using the provided name value.

`methodMap` is an instance of type `EnumNameMap` which is also defined within the `HttpMethod` class:

```
        EnumNameMap(Node<T>... nodes) {
            this.values = (Node[])(new Node[MathUtil.findNextPositivePowerOfTwo(nodes.length)]);
            this.valuesMask = this.values.length - 1;
            Node[] var2 = nodes;
            int var3 = nodes.length;

            for(int var4 = 0; var4 < var3; ++var4) {
                Node<T> node = var2[var4];
                int i = hashCode(node.key) & this.valuesMask;
                if (this.values[i] != null) {
                    throw new IllegalArgumentException("index " + i + " collision between values: [" + this.values[i].key + ", " + node.key + ']');
                }

                this.values[i] = node;
            }

        }

        T get(String name) {
            Node<T> node = this.values[hashCode(name) & this.valuesMask];
            return node != null && node.key.equals(name) ? node.value : null;
        }
```

Note that `EnumNameMap.get()` returns a boolean value, which is not `null`. Therefore, any arbitrary http verb used within a `BinaryHttpRequest` will yield a valid `HttpMethod` object. When the `HttpMethod` object is constructed, the name is checked for whitespace and similar characters. Therefore, we cannot perform complete injection attacks using the HTTP verb alone. However, when combined with the other input validation issues, such as that in the path field, we can construct somewhat arbitrary data blobs that satisfy text-based protocol message formats.

### Impact
Method is partially validated while other values are not validated at all. Software that relies on netty to apply input validation for binary HTTP data may be vulnerable to various injection and protocol based attacks.


