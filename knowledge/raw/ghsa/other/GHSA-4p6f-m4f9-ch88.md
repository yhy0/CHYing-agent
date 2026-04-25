# Binary vulnerable to Slice Memory Allocation with Excessive Size Value

**GHSA**: GHSA-4p6f-m4f9-ch88 | **CVE**: CVE-2022-36078 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-400, CWE-789

**Affected Packages**:
- **github.com/gagliardetto/binary** (go): < 0.7.1

## Description

### Impact
> _What kind of vulnerability is it? Who is impacted?_

The vulnerability is a memory allocation vulnerability that can be exploited to allocate slices in memory with (arbitrary) excessive size value, which can either exhaust available memory or crash the whole program.

When using `github.com/gagliardetto/binary` to parse unchecked (or wrong type of) data from untrusted sources of input (e.g. the blockchain) into slices, it's possible to allocate memory with excessive size.

When `dec.Decode(&val)` method is used to parse data into a structure that is or contains slices of values, the length of the slice was previously read directly from the data itself without any checks on the size of it, and then a slice was allocated. This could lead to an overflow and an allocation of memory with excessive size value.

Example:

```go
package main

import (
	"github.com/gagliardetto/binary" // any version before v0.7.1 is vulnerable
	"log"
)

type MyStruct struct {
	Field1 []byte // field is a slice (could be a slice of any type)
}

func main() {
	// Let's assume that the data is coming from the blockchain:
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	
	var val MyStruct
	// - To determine the size of the val.Field1 slice, the decoder will read the length
	//   of the slice from the data itself without any checks on the size of it.
	//
	// - This could lead to an allocation of memory with excessive size value.
	//   Which means: []byte{0x01, 0x02, 0x03, 0x04} will be read as the length
	//   of the slice (= 67305985) and then an allocation of memory with 67305985 bytes will be made.
	//
	dec := binary.NewBorshDecoder(data)
	err := dec.Decode(&val)  // or binary.UnmarshalBorsh(&val, data) or binary.UnmarshalBin(&val, data) etc.
	if err != nil {
		log.Fatal(err)
	}
}
```

### Patches
> _Has the problem been patched? What versions should users upgrade to?_

The vulnerability has been patched in `github.com/gagliardetto/binary` `v0.7.1`

Users should upgrade to `v0.7.1` or higher.

To upgrade to `v0.7.1` or higher, run:

```bash
go get github.com/gagliardetto/binary@v0.7.1

# or

go get github.com/gagliardetto/binary@latest
```

### Workarounds
> _Is there a way for users to fix or remediate the vulnerability without upgrading?_

A workaround is not to rely on the `dec.Decode(&val)` function to parse the data, but to use a custom `UnmarshalWithDecoder()` method that reads and checks the length of any slice.

### References
> _Are there any links users can visit to find out more?_

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [github.com/gagliardetto/binary](https://github.com/gagliardetto/binary)
* DM me on [twitter](https://twitter.com/immaterial_ink)

