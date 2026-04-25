# Vyper vulnerable to memory corruption in certain builtins utilizing `msize`

**GHSA**: GHSA-c647-pxm2-c52w | **CVE**: CVE-2023-42443 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-787

**Affected Packages**:
- **vyper** (pip): >= 0.3.4, <= 0.3.9

## Description

### Impact
In certain conditions, the memory used by the builtins `raw_call`, `create_from_blueprint` and `create_copy_of` can be corrupted.

- For `raw_call`, the argument buffer of the call can be corrupted, leading to incorrect `calldata` in the sub-context.
- For  `create_from_blueprint` and `create_copy_of`, the buffer for the to-be-deployed bytecode can be corrupted, leading to deploying incorrect bytecode.

Below are the conditions that must be fulfilled for the corruption to happen for each builtin:

#### `raw_call`
- memory is not fully initialized, ex. all parameters to an external function live in calldata
and
- The `data` argument of the builtin is `msg.data`.
and
- The `to`, `value` or `gas` passed to the builtin is some complex expression that results in writing to uninitialized memory (e.g. calling an internal function)

#### `create_copy_of`
- memory is not fully initialized, ex. all parameters to an external function live in calldata
and
- The `value` or `salt` passed to the builtin is some complex expression that results in writing to  uninitialized memory (e.g. calling an internal function)

#### `create_from_blueprint`
- memory is not fully initialized, ex. all parameters to an external function live in calldata
and
- Either no constructor parameters are passed to the builtin or `raw_args` is set to True.
and
- The `value` or `salt` passed to the builtin is some complex expression that results in writing to uninitialized memory (e.g. calling an internal function)

Note: When the builtin is being called from an `internal` function `f` from a function `g`, the issue is not present provided that `g` has written to memory before calling `f`.
 
#### Examples


##### `raw_call`

In the following contract, calling `bar(1,1)` will return:

``` Python
ae42e95100000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000001
```
instead of:
``` Python
ae42e95100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001
```

```Python
identity: constant(address) = 0x0000000000000000000000000000000000000004

@external
def foo():
    pass

@internal
@view
def get_address()->address:
    a:uint256 = max_value(uint256) # 0xfff...fff
    return identity
@external
def bar(f:uint256, u:uint256) -> Bytes[100]:
    a: Bytes[100] = raw_call(self.get_address(), msg.data, max_outsize=100)
    return a
```

##### `create_copy_of`
In the following contract, after calling `test()`, the code deployed at `self.created_address` does not match the bytecode at `target`.

``` Vyper
created_address: public(address)

@external
def test(target: address) -> address:
    # The expression in salt= is complex and will require to store to memory
    self.created_address = create_copy_of(target, salt = keccak256(_abi_encode(target)))
    return self.created_address
```

##### `create_from_blueprint`
In the following contract, after calling `test()`, the init bytecode used to create the contract deployed at the address `self.created_address` will not match the blueprint bytecode stored at `target`.

``` Vyper
created_address: public(address)

salt: constant(bytes32) = keccak256("kebab")

@external
@payable
def test(target: address):
    # The expression in salt= is complex and will require to store to memory
    self.created_address = create_from_blueprint(target, code_offset=0, salt=keccak256(_abi_encode(target)))
```
### Patches
issue tracking in https://github.com/vyperlang/vyper/issues/3609, patched in #3610 

### Workarounds

The complex expressions that are being passed as kwargs to the builtin should be cached in memory prior to the call to the builtin. For the last example above, it would be:

``` Vyper
created_address: public(address)

salt: constant(bytes32) = keccak256("kebab")

@external
@payable
def test(target: address):
    salt: bytes32 = keccak256(_abi_encode(target))
    self.created_address = create_from_blueprint(target, code_offset=0, salt=salt)
```
### References
_Are there any links users can visit to find out more?_

