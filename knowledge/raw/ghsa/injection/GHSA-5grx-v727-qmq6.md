# 1Panel has an SQL injection issue related to the orderBy clause

**GHSA**: GHSA-5grx-v727-qmq6 | **CVE**: CVE-2024-39907 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-89

**Affected Packages**:
- **github.com/1Panel-dev/1Panel** (go): < 1.10.12-tls

## Description

### Summary
There are many sql injections in the project, and some of them are not well filtered, leading to arbitrary file writes, and ultimately leading to RCEs.
The proof is as follows

### Details （one of them ）
<img width="697" alt="image" src="https://github.com/1Panel-dev/1Panel/assets/129351704/895b7b43-9bc0-44b3-9c84-24c2dcc962da">
<img width="936" alt="image" src="https://github.com/1Panel-dev/1Panel/assets/129351704/1b8eb866-9865-4bef-a359-53335d709157">
<img width="684" alt="image" src="https://github.com/1Panel-dev/1Panel/assets/129351704/e865d6d0-7ecb-49f7-b4a2-f1b0bc407986">


### PoC
curl 'http://api:30455/api/v1/hosts/command/search' {"page":1,"pageSize":10,"groupID":0,"orderBy":"**3**","order":"ascending","name":"a"}
<img width="664" alt="image" src="https://github.com/1Panel-dev/1Panel/assets/129351704/250d5a2a-cb32-44dc-9831-86dbc2f2b43f">
for example as picture . just change orderby‘s num we can know How many columns does the data table have.Parameters require strict whitelist filtering

### Impact
RCE、data leak.

