# GraphQL - CSRF and Authorization Attacks

## CSRF in GraphQL

If you don't know what CSRF is read the following page:

Out there you are going to be able to find several GraphQL endpoints **configured without CSRF tokens.**

Note that GraphQL request are usually sent via POST requests using the Content-Type **`application/json`**.

```javascript
{"operationName":null,"variables":{},"query":"{\n  user {\n    firstName\n    __typename\n  }\n}\n"}
```

However, most GraphQL endpoints also support **`form-urlencoded` POST requests:**

```javascript
query=%7B%0A++user+%7B%0A++++firstName%0A++++__typename%0A++%7D%0A%7D%0A
```

Therefore, as CSRF requests like the previous ones are sent **without preflight requests**, it's possible to **perform** **changes** in the GraphQL abusing a CSRF.

However, note that the new default cookie value of the `samesite` flag of Chrome is `Lax`. This means that the cookie will only be sent from a third party web in GET requests.

Note that it's usually possible to send the **query** **request** also as a **GET** **request and the CSRF token might not being validated in a GET request.**

Also, abusing a [**XS-Search**](../../pentesting-web/xs-search/index.html) **attack** might be possible to exfiltrate content from the GraphQL endpoint abusing the credentials of the user.

For more information **check the** [**original post here**](https://blog.doyensec.com/2021/05/20/graphql-csrf.html).

## Cross-site WebSocket hijacking in GraphQL

Similar to CRSF vulnerabilities abusing graphQL it's also possible to perform a **Cross-site WebSocket hijacking to abuse an authentication with GraphQL with unprotected cookies** and make a user perform unexpected actions in GraphQL.

For more information check:

## Authorization in GraphQL

Many GraphQL functions defined on the endpoint might only check the authentication of the requester but not authorization.

Modifying query input variables could lead to sensitive account details [leaked](https://hackerone.com/reports/792927).

Mutation could even lead to account takeover trying to modify other account data.

```javascript
{
  "operationName":"updateProfile",
  "variables":{"username":INJECT,"data":INJECT},
  "query":"mutation updateProfile($username: String!,...){updateProfile(username: $username,...){...}}"
}
```

### Bypass authorization in GraphQL

[Chaining queries](https://s1n1st3r.gitbook.io/theb10g/graphql-query-authentication-bypass-vuln) together can bypass a weak authentication system.

In the below example you can see that the operation is "forgotPassword" and that it should only execute the forgotPassword query associated with it. This can be bypassed by adding a query to the end, in this case we add "register" and a user variable for the system to register as a new user.

<img src="../../images/GraphQLAuthBypassMethod.PNG" alt=""><figcaption></figcaption>

## Bypassing Rate Limits Using Aliases in GraphQL

In GraphQL, aliases are a powerful feature that allow for the **naming of properties explicitly** when making an API request. This capability is particularly useful for retrieving **multiple instances of the same type** of object within a single request. Aliases can be employed to overcome the limitation that prevents GraphQL objects from having multiple properties with the same name.

For a detailed understanding of GraphQL aliases, the following resource is recommended: [Aliases](https://portswigger.net/web-security/graphql/what-is-graphql#aliases).

While the primary purpose of aliases is to reduce the necessity for numerous API calls, an unintended use case has been identified where aliases can be leveraged to execute brute force attacks on a GraphQL endpoint. This is possible because some endpoints are protected by rate limiters designed to thwart brute force attacks by restricting the **number of HTTP requests**. However, these rate limiters might not account for the number of operations within each request. Given that aliases allow for the inclusion of multiple queries in a single HTTP request, they can circumvent such rate limiting measures.

Consider the example provided below, which illustrates how aliased queries can be used to verify the validity of store discount codes. This method could sidestep rate limiting since it compiles several queries into one HTTP request, potentially allowing for the verification of numerous discount codes simultaneously.

```bash
# Example of a request utilizing aliased queries to check for valid discount codes
query isValidDiscount($code: Int) {
    isvalidDiscount(code:$code){
        valid
    }
    isValidDiscount2:isValidDiscount(code:$code){
        valid
    }
    isValidDiscount3:isValidDiscount(code:$code){
        valid
    }
}
```
