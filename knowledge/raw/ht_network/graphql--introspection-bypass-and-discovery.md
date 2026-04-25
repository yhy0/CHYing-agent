# GraphQL - Introspection Bypass and Discovery

## GraphQL Without Introspection

More and more **graphql endpoints are disabling introspection**. However, the errors that graphql throws when an unexpected request is received are enough for tools like [**clairvoyance**](https://github.com/nikitastupin/clairvoyance) to recreate most part of the schema.

Moreover, the Burp Suite extension [**GraphQuail**](https://github.com/forcesunseen/graphquail) extension **observes GraphQL API requests going through Burp** and **builds** an internal GraphQL **schema** with each new query it sees. It can also expose the schema for GraphiQL and Voyager. The extension returns a fake response when it receives an introspection query. As a result, GraphQuail shows all queries, arguments, and fields available for use within the API. For more info [**check this**](https://blog.forcesunseen.com/graphql-security-testing-without-a-schema).

A nice **wordlist** to discover [**GraphQL entities can be found here**](https://github.com/Escape-Technologies/graphql-wordlist?).

### Bypassing GraphQL introspection defences <a href="#bypassing-graphql-introspection-defences" id="bypassing-graphql-introspection-defences"></a>

To bypass restrictions on introspection queries in APIs, inserting a **special character after the `__schema` keyword** proves effective. This method exploits common developer oversights in regex patterns that aim to block introspection by focusing on the `__schema` keyword. By adding characters like **spaces, new lines, and commas**, which GraphQL ignores but might not be accounted for in regex, restrictions can be circumvented. For instance, an introspection query with a newline after `__schema` may bypass such defenses:

```bash
# Example with newline to bypass
{
    "query": "query{__schema
    {queryType{name}}}"
}
```

If unsuccessful, consider alternative request methods, such as **GET requests** or **POST with `x-www-form-urlencoded`**, since restrictions may apply only to POST requests.

### Try WebSockets

As mentioned in [**this talk**](https://www.youtube.com/watch?v=tIo_t5uUK50), check if it might be possible to connect to graphQL via WebSockets as that might allow you to bypass a potential WAF and make the websocket communication leak the schema of the graphQL:

```javascript
ws = new WebSocket("wss://target/graphql", "graphql-ws")
ws.onopen = function start(event) {
  var GQL_CALL = {
    extensions: {},
    query: `
        {
            __schema {
                _types {
                    name
                }
            }
        }`,
  }

  var graphqlMsg = {
    type: "GQL.START",
    id: "1",
    payload: GQL_CALL,
  }
  ws.send(JSON.stringify(graphqlMsg))
}
```

### **Discovering Exposed GraphQL Structures**

When introspection is disabled, examining the website's source code for preloaded queries in JavaScript libraries is a useful strategy. These queries can be found using the `Sources` tab in developer tools, providing insights into the API's schema and revealing potentially **exposed sensitive queries**. The commands to search within the developer tools are:

```javascript
Inspect/Sources/"Search all files"
file:* mutation
file:* query
```

### Error-based schema reconstruction & engine fingerprinting (InQL v6.1+)

When introspection is blocked, **InQL v6.1+** can now reconstruct the reachable schema purely from error feedback. The new *schema bruteforcer* batches candidate field/argument names from a configurable wordlist and sends them in multi-field operations to reduce HTTP chatter. Useful error patterns are then harvested automatically:

- `Field 'bugs' not found on type 'inql'` confirms the existence of the parent type while discarding invalid field names.
- `Argument 'contribution' is required` shows that an argument is mandatory and exposes its spelling.
- Suggestion hints such as `Did you mean 'openPR'?` are fed back into the queue as validated candidates.
- By intentionally sending values with the wrong primitive (e.g., integers for strings) the bruteforcer provokes type mismatch errors that leak the real type signature, including list/object wrappers like `[Episode!]`.

The bruteforcer keeps recursing over any type that yields new fields, so a wordlist that mixes generic GraphQL names with app-specific guesses will eventually map large chunks of the schema without introspection. Runtime is limited mostly by rate limiting and candidate volume, so fine-tuning the InQL settings (wordlist, batch size, throttling, retries) is critical for stealthier engagements.

In the same release, InQL ships a **GraphQL engine fingerprinter** (borrowing signatures from tools like `graphw00f`). The module dispatches deliberately invalid directives/queries and classifies the backend by matching the exact error text. For example:

```graphql
query @deprecated {
    __typename
}
```

- Apollo replies with `Directive "@deprecated" may not be used on QUERY.`
- GraphQL Ruby answers `'@deprecated' can't be applied to queries`.

Once an engine is recognized, InQL surfaces the corresponding entry from the [GraphQL Threat Matrix](https://github.com/nicholasaleks/graphql-threat-matrix), helping testers prioritize weaknesses that ship with that server family (default introspection behavior, depth limits, CSRF gaps, file uploads, etc.).

Finally, **automatic variable generation** removes a classic blocker when pivoting into Burp Repeater/Intruder. Whenever an operation requires a variables JSON, InQL now injects sane defaults so the request passes schema validation on the first send:

```text
"String"  -> "exampleString"
"Int"     -> 42
"Float"   -> 3.14
"Boolean" -> true
"ID"      -> "123"
ENUM      -> first declared value
```

Nested input objects inherit the same mapping, so you immediately get a syntactically and semantically valid payload that can be fuzzed for SQLi/NoSQLi/SSRF/logic bypasses without manually reverse-engineering every argument.
