# GCP - Cloud Build Unauthenticated Enum

## Cloud Build

For more information about Cloud Build check:

### cloudbuild.yml

If you compromise write access over a repository containing a file named **`cloudbuild.yml`**, you could **backdoor** this file, which specifies the **commands that are going to be executed** inside a Cloud Build and exfiltrate the secrets, compromise what is done and also compromise the **Cloud Build service account.**

> [!NOTE]
> Note that GCP has the option to allow administrators to control the execution of build systems from external PRs via "Comment Control". Comment Control is a feature where collaborators/project owners **need to comment “/gcbrun” to trigger the build** against the PR and using this feature inherently prevents anyone on the internet from triggering your build systems.

For some related information you could check the page about how to attack Github Actions (similar to this):

### PR Approvals

When the trigger is PR because **anyone can perform PRs to public repositories** it would be very dangerous to just **allow the execution of the trigger with any PR**. Therefore, by default, the execution will only be **automatic for owners and collaborators**, and in order to execute the trigger with other users PRs an owner or collaborator must comment `/gcbrun`.

<img src="../../../images/image (339).png" alt="" width="563"><figcaption></figcaption>

> [!CAUTION]
> Therefore, is this is set to **`Not required`**, an attacker could perform a **PR to the branch** that will trigger the execution adding the malicious code execution to the **`cloudbuild.yml`** file and compromise the cloudbuild execution (note that cloudbuild will download the code FROM the PR, so it will execute the malicious **`cloudbuild.yml`**).

Moreover, it's easy to see if some cloudbuild execution needs to be performed when you send a PR because it appears in Github:

<img src="../../../images/image (340).png" alt=""><figcaption></figcaption>

> [!WARNING]
> Then, even if the cloudbuild is not executed the attacker will be able to see the **project name of a GCP project** that belongs to the company.
