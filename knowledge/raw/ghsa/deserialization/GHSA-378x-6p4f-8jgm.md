# SKOPS Card.get_model happily allows arbitrary code execution

**GHSA**: GHSA-378x-6p4f-8jgm | **CVE**: CVE-2025-54886 | **Severity**: high (CVSS 8.4)

**CWE**: CWE-502

**Affected Packages**:
- **skops** (pip): < 0.13.0

## Description

## Summary

The `Card` class of `skops`, used for model documentation and sharing, allows arbitrary code execution. When a file other than `.zip` is provided to the `Card` class during instantiation, the internally invoked `Card.get_model` method silently falls back to `joblib` without warning. Unlike the `.skops` zip-based format, `joblib` permits unrestricted code execution, hence bypassing the security measures of `skops` and enabling the execution of malicious code.


## Details

The `Card` class supports loading the model linked to the card using the `get_model` method. When a `.skops` model is provided, it uses the `load` function from `skops`, which includes security mechanisms. The `Card` class also supports consistent management of the `trusted` list, which can be passed during instance creation. As expected, if a `.skops` model is provided without a `trusted` list and an untrusted type is encountered during loading, an error is raised. This behavior is consistent with the security principles of `skops`.

The problem arises when a file format other than `.zip` is provided. As shown in the code snippet below, in this case, the `joblib` library is used to load the model. This happens **silently**, without any warning or indication that `joblib` is being used. This is a significant security risk because `joblib` does not enforce the same security measures as `skops`, allowing arbitrary code execution.

```python
# from `card/_model_card.py:354-358`
try:
    if zipfile.is_zipfile(model_path):
        model = load(model_path, trusted=trusted)
    else:
        model = joblib.load(model_path)
```

To increase the concern, `get_model` is actually called internally by `skops` during card creation, so the user does not need to call it explicitly—only to create the `Card` object passing a `joblib` file.

## PoC

Consider the following example:

```python
from skops.card import Card

card = Card("model.skops")
```

An attacker could share a `model.skops` file that, despite its name, is **not** a `.zip` file. In this case, the `joblib.load` function is called, allowing arbitrary code execution if the file is actually a pickle-like object. This is difficult for the user to detect, as the check is based on the file’s format, not its extension or name.

This vulnerability exists regardless of the `trusted` list provided (or omitted) during `Card` instance creation, and is unaffected by any other parameters. Moreover, it occurs at the time of `Card` instantiation.

## Attack Scenario

An attacker can craft a malicious model file that, when used to instantiate a `Card` object, enables **arbitrary code** on the victim’s machine. This requires no user interaction beyond instantiating the `Card` object (not even explicit loading). Given that `skops` is often used in collaborative environments and is designed with security in mind, this vulnerability poses a significant threat.

## Attachments
The complete PoC is available on GitHub at [io-no/CVE-2025-54886](https://github.com/io-no/CVE-Reports/tree/main/CVE-2025-54886).
