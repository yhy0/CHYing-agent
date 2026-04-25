# GCP - Cloud Shell Enum

## Basic Information

Google Cloud Shell is an interactive shell environment for Google Cloud Platform (GCP) that provides you with **command-line access to your GCP resources directly from your browser or shell**. It's a managed service provided by Google, and it comes with a **pre-installed set of tools**, making it easier to manage your GCP resources without having to install and configure these tools on your local machine.\
Moreover, its offered at **no additional cost.**

**Any user of the organization** (Workspace) is able to execute **`gcloud cloud-shell ssh`** and get access to his **cloudshell** environment. However, **Service Accounts can't**, even if they are owner of the organization.

There **aren't** **permissions** assigned to this service, therefore the **aren't privilege escalation techniques**. Also there **isn't any kind of enumeration**.

Note that Cloud Shell can be **easily disabled** for the organization.

### Post Exploitation

### Persistence
