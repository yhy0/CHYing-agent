# GCP - API Keys Enum

## Basic Information

In Google Cloud Platform (GCP), API keys are a simple encrypted string that **identifies an application without any principa**l. They are used to **access Google Cloud APIs** that do not require user context. This means they are often used in scenarios where the application is accessing its own data rather than user data.

### Restrictions

You can **apply restrictions to API keys** for enhanced security. For example, you can restrict the key to be **used only by certain IP addresses, webs, android apps, iOS apps**, or restrict it to **certain APIs or services** within GCP.

### Enumeration

It's possible to **see the restriction of an API key** (including GCP API endpoints restriction) using the verbs list or describe:

```bash
gcloud services api-keys list
gcloud services api-keys describe <key-uuid>
gcloud services api-keys list --show-deleted
```

> [!NOTE]
> It's possible to recover deleted keys before 30days passes, that's why you can list deleted keys.

### Privilege Escalation & Post Exploitation

### Unauthenticated Enum

### Persistence
