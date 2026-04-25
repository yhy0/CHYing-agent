# Malicious Long Unicode filenames may cause a Multiple Application-level Denial of Service

**GHSA**: GHSA-w4h6-9wrp-v5jq | **CVE**: CVE-2024-32874 | **Severity**: critical (CVSS 9.3)

**CWE**: CWE-770

**Affected Packages**:
- **frigate** (pip): < 0.13.2

## Description

**Important: Exploiting this vulnerability requires the attacker to have access to your Frigate instance, which means they could also just delete all of your recordings or perform any other action. If you have configured authentication in front of Frigate via a reverse proxy, then this vulnerability is not exploitable without first getting around your authentication method. For many obvious reasons in addition to this one, please don't expose your Frigate instance publicly without any kind of authentication.**

## Summary

When uploading a file or retrieving the filename, a user may intentionally use a large Unicode filename which would lead to a application-level denial of service. This is due to no limitation set on the length of the filename and the costy use of the Unicode normalization with the form NFKD under the hood of `secure_filename()`.

I idenfied multiple vulnerable paths on [blakeblackshear/frigate](https://www.github.com/blakeblackshear/frigate/) repository. In all of those paths, it was possible for a malicious user to send a filename equals to the output of : `python3 -c "print('℀' * 1_000_000)"` which would reach the werkzeug `secure_filename()` call , which in turn under the hood uses a compatibility Unicode normalization with NFKC/NFKD form. In sum, the latter call would be costly in matter of CPU resource and may lead to the application-level denial of service. 

## Vulnerable Paths

<details>
<summary>Path with 2 steps</summary>

1. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L379C20-L379C31)
   <pre><code class="python">@MediaBp.route("/&lt;camera_name&gt;/start/&lt;int:start_ts&gt;/end/&lt;int:end_ts&gt;/clip.mp4")
   @MediaBp.route("/&lt;camera_name&gt;/start/&lt;float:start_ts&gt;/end/&lt;float:end_ts&gt;/clip.mp4")
   def recording_clip(<strong>camera_name</strong>, start_ts, end_ts):
       download = request.args.get("download", type=bool)

   </code></pre>

2. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L408C33-L408C78)
   <pre><code class="python">            playlist_lines.append(f"outpoint {int(end_ts - clip.start_time)}")

       file_name = secure_filename(<strong>f"clip_{camera_name}_{start_ts}-{end_ts}.mp4"</strong>)
       path = os.path.join(CACHE_DIR, file_name)

   </code></pre>

</details>

----------------------------------------

[frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L408C33-L408C78)

<pre><code class="python">            playlist_lines.append(f"outpoint {int(end_ts - clip.start_time)}")

    file_name = secure_filename(<strong>f"clip_{camera_name}_{start_ts}-{end_ts}.mp4"</strong>)
    path = os.path.join(CACHE_DIR, file_name)

</code></pre>

*This [user-provided value](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L379C33-L379C41) can reach a [costly Unicode normalization operation](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L408C33-L408C78).*

#### Paths

<details>
<summary>Path with 2 steps</summary>

1. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L379C33-L379C41)
   <pre><code class="python">@MediaBp.route("/&lt;camera_name&gt;/start/&lt;int:start_ts&gt;/end/&lt;int:end_ts&gt;/clip.mp4")
   @MediaBp.route("/&lt;camera_name&gt;/start/&lt;float:start_ts&gt;/end/&lt;float:end_ts&gt;/clip.mp4")
   def recording_clip(camera_name, <strong>start_ts</strong>, end_ts):
       download = request.args.get("download", type=bool)

   </code></pre>

2. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L408C33-L408C78)
   <pre><code class="python">            playlist_lines.append(f"outpoint {int(end_ts - clip.start_time)}")

       file_name = secure_filename(<strong>f"clip_{camera_name}_{start_ts}-{end_ts}.mp4"</strong>)
       path = os.path.join(CACHE_DIR, file_name)

   </code></pre>

</details>

----------------------------------------

[frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L408C33-L408C78)

<pre><code class="python">            playlist_lines.append(f"outpoint {int(end_ts - clip.start_time)}")

    file_name = secure_filename(<strong>f"clip_{camera_name}_{start_ts}-{end_ts}.mp4"</strong>)
    path = os.path.join(CACHE_DIR, file_name)

</code></pre>

*This [user-provided value](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L379C43-L379C49) can reach a [costly Unicode normalization operation](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L408C33-L408C78).*

#### Paths

<details>
<summary>Path with 2 steps</summary>

1. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L379C43-L379C49)
   <pre><code class="python">@MediaBp.route("/&lt;camera_name&gt;/start/&lt;int:start_ts&gt;/end/&lt;int:end_ts&gt;/clip.mp4")
   @MediaBp.route("/&lt;camera_name&gt;/start/&lt;float:start_ts&gt;/end/&lt;float:end_ts&gt;/clip.mp4")
   def recording_clip(camera_name, start_ts, <strong>end_ts</strong>):
       download = request.args.get("download", type=bool)

   </code></pre>

2. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L408C33-L408C78)
   <pre><code class="python">            playlist_lines.append(f"outpoint {int(end_ts - clip.start_time)}")

       file_name = secure_filename(<strong>f"clip_{camera_name}_{start_ts}-{end_ts}.mp4"</strong>)
       path = os.path.join(CACHE_DIR, file_name)

   </code></pre>

</details>

----------------------------------------

[frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L646C25-L646C47)

<pre><code class="python">        current_app.frigate_config,
        camera_name,
        secure_filename(<strong>name.replace(" ", "_")</strong>) if name else None,
        int(start_time),
        int(end_time),
</code></pre>

*This [user-provided value](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L23C5-L23C12) can reach a [costly Unicode normalization operation](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L646C25-L646C47).*

#### Paths

<details>
<summary>Path with 8 steps</summary>

1. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L23C5-L23C12)
   <pre><code class="python">    jsonify,
       make_response,
       <strong>request</strong>,
   )
   from peewee import DoesNotExist, fn
   </code></pre>

2. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L23C5-L23C12)
   <pre><code class="python">    jsonify,
       make_response,
       <strong>request</strong>,
   )
   from peewee import DoesNotExist, fn
   </code></pre>

3. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L620C28-L620C35)
   <pre><code class="python">        )

       json: dict[str, any] = <strong>request</strong>.get_json(silent=True) or {}
       playback_factor = json.get("playback", "realtime")
       name: Optional[str] = json.get("name")
   </code></pre>

4. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L620C5-L620C9)
   <pre><code class="python">        )

       <strong>json</strong>: dict[str, any] = request.get_json(silent=True) or {}
       playback_factor = json.get("playback", "realtime")
       name: Optional[str] = json.get("name")
   </code></pre>

5. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L622C27-L622C31)
   <pre><code class="python">    json: dict[str, any] = request.get_json(silent=True) or {}
       playback_factor = json.get("playback", "realtime")
       name: Optional[str] = <strong>json</strong>.get("name")

       recordings_count = (
   </code></pre>

6. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L622C27-L622C43)
   <pre><code class="python">    json: dict[str, any] = request.get_json(silent=True) or {}
       playback_factor = json.get("playback", "realtime")
       name: Optional[str] = <strong>json.get("name")</strong>

       recordings_count = (
   </code></pre>

7. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L622C5-L622C9)
   <pre><code class="python">    json: dict[str, any] = request.get_json(silent=True) or {}
       playback_factor = json.get("playback", "realtime")
       <strong>name</strong>: Optional[str] = json.get("name")

       recordings_count = (
   </code></pre>

8. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L646C25-L646C47)
   <pre><code class="python">        current_app.frigate_config,
           camera_name,
           secure_filename(<strong>name.replace(" ", "_")</strong>) if name else None,
           int(start_time),
           int(end_time),
   </code></pre>

</details>

----------------------------------------

[frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L684C9-L684C59)

<pre><code class="python">def export_rename(file_name_current, file_name_new: str):
    safe_file_name_current = secure_filename(
        <strong>export_filename_check_extension(file_name_current)</strong>
    )
    file_current = os.path.join(EXPORT_DIR, safe_file_name_current)
</code></pre>

*This [user-provided value](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L682C19-L682C36) can reach a [costly Unicode normalization operation](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L684C9-L684C59).*

#### Paths

<details>
<summary>Path with 5 steps</summary>

1. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L682C19-L682C36)
   <pre><code class="python">
   @MediaBp.route("/export/&lt;file_name_current&gt;/&lt;file_name_new&gt;", methods=["PATCH"])
   def export_rename(<strong>file_name_current</strong>, file_name_new: str):
       safe_file_name_current = secure_filename(
           export_filename_check_extension(file_name_current)
   </code></pre>

2. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L684C41-L684C58)
   <pre><code class="python">def export_rename(file_name_current, file_name_new: str):
       safe_file_name_current = secure_filename(
           export_filename_check_extension(<strong>file_name_current</strong>)
       )
       file_current = os.path.join(EXPORT_DIR, safe_file_name_current)
   </code></pre>

3. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L667C37-L667C45)
   <pre><code class="python">

   def export_filename_check_extension(<strong>filename</strong>: str):
       if filename.endswith(".mp4"):
           return filename
   </code></pre>

4. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L669C16-L669C24)
   <pre><code class="python">def export_filename_check_extension(filename: str):
       if filename.endswith(".mp4"):
           return <strong>filename</strong>
       else:
           return filename + ".mp4"
   </code></pre>

5. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L684C9-L684C59)
   <pre><code class="python">def export_rename(file_name_current, file_name_new: str):
       safe_file_name_current = secure_filename(
           <strong>export_filename_check_extension(file_name_current)</strong>
       )
       file_current = os.path.join(EXPORT_DIR, safe_file_name_current)
   </code></pre>

</details>

<details>
<summary>Path with 5 steps</summary>

1. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L682C19-L682C36)
   <pre><code class="python">
   @MediaBp.route("/export/&lt;file_name_current&gt;/&lt;file_name_new&gt;", methods=["PATCH"])
   def export_rename(<strong>file_name_current</strong>, file_name_new: str):
       safe_file_name_current = secure_filename(
           export_filename_check_extension(file_name_current)
   </code></pre>

2. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L684C41-L684C58)
   <pre><code class="python">def export_rename(file_name_current, file_name_new: str):
       safe_file_name_current = secure_filename(
           export_filename_check_extension(<strong>file_name_current</strong>)
       )
       file_current = os.path.join(EXPORT_DIR, safe_file_name_current)
   </code></pre>

3. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L667C37-L667C45)
   <pre><code class="python">

   def export_filename_check_extension(<strong>filename</strong>: str):
       if filename.endswith(".mp4"):
           return filename
   </code></pre>

4. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L671C16-L671C33)
   <pre><code class="python">        return filename
       else:
           return <strong>filename + ".mp4"</strong>


   </code></pre>

5. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L684C9-L684C59)
   <pre><code class="python">def export_rename(file_name_current, file_name_new: str):
       safe_file_name_current = secure_filename(
           <strong>export_filename_check_extension(file_name_current)</strong>
       )
       file_current = os.path.join(EXPORT_DIR, safe_file_name_current)
   </code></pre>

</details>

----------------------------------------

[frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L705C42-L705C88)

<pre><code class="python">        )

    safe_file_name_new = secure_filename(<strong>export_filename_check_extension(file_name_new)</strong>)
    file_new = os.path.join(EXPORT_DIR, safe_file_name_new)

</code></pre>

*This [user-provided value](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L682C38-L682C51) can reach a [costly Unicode normalization operation](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L705C42-L705C88).*

#### Paths

<details>
<summary>Path with 5 steps</summary>

1. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L682C38-L682C51)
   <pre><code class="python">
   @MediaBp.route("/export/&lt;file_name_current&gt;/&lt;file_name_new&gt;", methods=["PATCH"])
   def export_rename(file_name_current, <strong>file_name_new</strong>: str):
       safe_file_name_current = secure_filename(
           export_filename_check_extension(file_name_current)
   </code></pre>

2. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L705C74-L705C87)
   <pre><code class="python">        )

       safe_file_name_new = secure_filename(export_filename_check_extension(<strong>file_name_new</strong>))
       file_new = os.path.join(EXPORT_DIR, safe_file_name_new)

   </code></pre>

3. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L667C37-L667C45)
   <pre><code class="python">

   def export_filename_check_extension(<strong>filename</strong>: str):
       if filename.endswith(".mp4"):
           return filename
   </code></pre>

4. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L669C16-L669C24)
   <pre><code class="python">def export_filename_check_extension(filename: str):
       if filename.endswith(".mp4"):
           return <strong>filename</strong>
       else:
           return filename + ".mp4"
   </code></pre>

5. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L705C42-L705C88)
   <pre><code class="python">        )

       safe_file_name_new = secure_filename(<strong>export_filename_check_extension(file_name_new)</strong>)
       file_new = os.path.join(EXPORT_DIR, safe_file_name_new)

   </code></pre>

</details>

<details>
<summary>Path with 5 steps</summary>

1. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L682C38-L682C51)
   <pre><code class="python">
   @MediaBp.route("/export/&lt;file_name_current&gt;/&lt;file_name_new&gt;", methods=["PATCH"])
   def export_rename(file_name_current, <strong>file_name_new</strong>: str):
       safe_file_name_current = secure_filename(
           export_filename_check_extension(file_name_current)
   </code></pre>

2. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L705C74-L705C87)
   <pre><code class="python">        )

       safe_file_name_new = secure_filename(export_filename_check_extension(<strong>file_name_new</strong>))
       file_new = os.path.join(EXPORT_DIR, safe_file_name_new)

   </code></pre>

3. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L667C37-L667C45)
   <pre><code class="python">

   def export_filename_check_extension(<strong>filename</strong>: str):
       if filename.endswith(".mp4"):
           return filename
   </code></pre>

4. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L671C16-L671C33)
   <pre><code class="python">        return filename
       else:
           return <strong>filename + ".mp4"</strong>


   </code></pre>

5. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L705C42-L705C88)
   <pre><code class="python">        )

       safe_file_name_new = secure_filename(<strong>export_filename_check_extension(file_name_new)</strong>)
       file_new = os.path.join(EXPORT_DIR, safe_file_name_new)

   </code></pre>

</details>

----------------------------------------

[frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L728C38-L728C80)

<pre><code class="python">@MediaBp.route("/export/&lt;file_name&gt;", methods=["DELETE"])
def export_delete(file_name: str):
    safe_file_name = secure_filename(<strong>export_filename_check_extension(file_name)</strong>)
    file = os.path.join(EXPORT_DIR, safe_file_name)

</code></pre>

*This [user-provided value](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L727C19-L727C28) can reach a [costly Unicode normalization operation](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L728C38-L728C80).*

#### Paths

<details>
<summary>Path with 5 steps</summary>

1. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L727C19-L727C28)
   <pre><code class="python">
   @MediaBp.route("/export/&lt;file_name&gt;", methods=["DELETE"])
   def export_delete(<strong>file_name</strong>: str):
       safe_file_name = secure_filename(export_filename_check_extension(file_name))
       file = os.path.join(EXPORT_DIR, safe_file_name)
   </code></pre>

2. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L728C70-L728C79)
   <pre><code class="python">@MediaBp.route("/export/&lt;file_name&gt;", methods=["DELETE"])
   def export_delete(file_name: str):
       safe_file_name = secure_filename(export_filename_check_extension(<strong>file_name</strong>))
       file = os.path.join(EXPORT_DIR, safe_file_name)

   </code></pre>

3. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L667C37-L667C45)
   <pre><code class="python">

   def export_filename_check_extension(<strong>filename</strong>: str):
       if filename.endswith(".mp4"):
           return filename
   </code></pre>

4. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L669C16-L669C24)
   <pre><code class="python">def export_filename_check_extension(filename: str):
       if filename.endswith(".mp4"):
           return <strong>filename</strong>
       else:
           return filename + ".mp4"
   </code></pre>

5. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L728C38-L728C80)
   <pre><code class="python">@MediaBp.route("/export/&lt;file_name&gt;", methods=["DELETE"])
   def export_delete(file_name: str):
       safe_file_name = secure_filename(<strong>export_filename_check_extension(file_name)</strong>)
       file = os.path.join(EXPORT_DIR, safe_file_name)

   </code></pre>

</details>

<details>
<summary>Path with 5 steps</summary>

1. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L727C19-L727C28)
   <pre><code class="python">
   @MediaBp.route("/export/&lt;file_name&gt;", methods=["DELETE"])
   def export_delete(<strong>file_name</strong>: str):
       safe_file_name = secure_filename(export_filename_check_extension(file_name))
       file = os.path.join(EXPORT_DIR, safe_file_name)
   </code></pre>

2. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L728C70-L728C79)
   <pre><code class="python">@MediaBp.route("/export/&lt;file_name&gt;", methods=["DELETE"])
   def export_delete(file_name: str):
       safe_file_name = secure_filename(export_filename_check_extension(<strong>file_name</strong>))
       file = os.path.join(EXPORT_DIR, safe_file_name)

   </code></pre>

3. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L667C37-L667C45)
   <pre><code class="python">

   def export_filename_check_extension(<strong>filename</strong>: str):
       if filename.endswith(".mp4"):
           return filename
   </code></pre>

4. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L671C16-L671C33)
   <pre><code class="python">        return filename
       else:
           return <strong>filename + ".mp4"</strong>


   </code></pre>

5. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L728C38-L728C80)
   <pre><code class="python">@MediaBp.route("/export/&lt;file_name&gt;", methods=["DELETE"])
   def export_delete(file_name: str):
       safe_file_name = secure_filename(<strong>export_filename_check_extension(file_name)</strong>)
       file = os.path.join(EXPORT_DIR, safe_file_name)

   </code></pre>

</details>

----------------------------------------

[frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L1346C46-L1346C55)

<pre><code class="python">def preview_thumbnail(file_name: str):
    """Get a thumbnail from the cached preview frames."""
    safe_file_name_current = secure_filename(<strong>file_name</strong>)
    preview_dir = os.path.join(CACHE_DIR, "preview_frames")

</code></pre>

*This [user-provided value](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L1344C23-L1344C32) can reach a [costly Unicode normalization operation](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L1346C46-L1346C55).*

#### Paths

<details>
<summary>Path with 2 steps</summary>

1. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L1344C23-L1344C32)
   <pre><code class="python">@MediaBp.route("/preview/&lt;file_name&gt;/thumbnail.jpg")
   @MediaBp.route("/preview/&lt;file_name&gt;/thumbnail.webp")
   def preview_thumbnail(<strong>file_name</strong>: str):
       """Get a thumbnail from the cached preview frames."""
       safe_file_name_current = secure_filename(file_name)
   </code></pre>

2. [frigate/api/media.py](https://github.com/blakeblackshear/frigate/blob/d7ae0eedf89e14f297093ac5c8042862034cbaeb/frigate/api/media.py#L1346C46-L1346C55)
   <pre><code class="python">def preview_thumbnail(file_name: str):
       """Get a thumbnail from the cached preview frames."""
       safe_file_name_current = secure_filename(<strong>file_name</strong>)
       preview_dir = os.path.join(CACHE_DIR, "preview_frames")

   </code></pre>

</details>



## Impact

* Application-level Denial of Service, the web app would hung undefinetly and not process any further request due to the use of the malicious payload.
  

## Mitigation

* Limiting the length of the incoming filename, similar to this commit [fix](https://github.com/django/django/commit/048a9ebb6ea468426cb4e57c71572cbbd975517f).
  

## References

* Similar to [CVE-2023-46695](https://github.com/advisories/GHSA-qmf9-6jqf-j8fq "CVE-2023-46695")
