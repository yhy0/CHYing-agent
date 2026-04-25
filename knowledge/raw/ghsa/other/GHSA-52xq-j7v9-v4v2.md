# Vyper negative array index bounds checks

**GHSA**: GHSA-52xq-j7v9-v4v2 | **CVE**: CVE-2024-24563 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-129

**Affected Packages**:
- **vyper** (pip): < 0.4.0

## Description

### Summary
Arrays can be keyed by a signed integer, while they are defined for unsigned integers only. The typechecker doesn't throw when spotting the usage of an `int` as an index for an array. Typically, negative integers are filtered out at runtime by the bounds checker, but small enough (i.e. large in magnitude, ex. `-2**255 + 5`) quantities combined with large enough arrays (at least `2**255` in length) can pass the bounds checker, resulting in unexpected behavior.

A contract search was performed, and no production contracts were found to be impacted.

### Details
The typechecker allows the usage of signed integers to be used as indexes to arrays. The vulnerability is present in different forms in all versions. Here is an example from `0.3.10`:
https://github.com/vyperlang/vyper/blob/c150fc49ee9375a930d177044559b83cb95f7963/vyper/semantics/types/subscriptable.py#L127-L137

As can be seen, the validation is performed against `IntegerT.any()`.

### PoC
If the array is sufficiently large, it can be indexed with a negative value:
```python
arr: public(uint256[MAX_UINT256])

@external
def set(idx: int256, num: uint256):
    self.arr[idx] = num
```
For signed integers, the 2's complement representation is used. Because the array was declared very large, the bounds checking will pass (negative values will simply be represented as very large numbers):
https://github.com/vyperlang/vyper/blob/a1fd228cb9936c3e4bbca6f3ee3fb4426ef45490/vyper/codegen/core.py#L534-L541

### Patches
Patched in https://github.com/vyperlang/vyper/pull/3817.

### Impact
There are two potential vulnerability classes: unpredictable behavior and accessing inaccessible elements.

1. If it is possible to index an array with a negative integer without reverting, this is most likely not anticipated by the developer and such accesses can cause unpredictable behavior for the contract.

2. If a contract has an invariant in the form `assert index < x` where both `index` and `x` are signed integers, the developer might suppose that no elements on indexes `y | y >= x` are accessible. However, by using negative indexes this can be bypassed.

The contract search found no production contracts impacted by these two classes of issues.
