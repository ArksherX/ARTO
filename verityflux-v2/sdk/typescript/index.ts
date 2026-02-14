/**
 * VerityFlux Enterprise - TypeScript/JavaScript SDK
 * Easy integration for AI agents with the VerityFlux security platform
 * 
 * @example
 * ```typescript
 * import { VerityFluxClient, ApprovalRequired } from '@verityflux/sdk';
 * 
 * const client = new VerityFluxClient({
 *   baseUrl: 'http://localhost:8000',
 *   apiKey: 'vf_your_api_key',
 *   agentName: 'my-agent'
 * });
 * 
 * // Check action before execution
 * const result = await client.checkAction({
 *   toolName: 'file_write',
 *   action: 'write',
 *   parameters: { path: '/etc/config' }
 * });
 * 
 * if (result.approved) {
 *   // Execute action
 * }
 * ```
 */

// =============================================================================
// TYPES
// =============================================================================

export interface VerityFluxConfig {
  baseUrl: string;
  apiKey?: string;
  agentId?: string;
  agentName?: string;
  timeout?: number;
  autoRegister?: boolean;
}

export interface ActionCheckRequest {
  toolName: string;
  action: string;
  parameters?: Record<string, unknown>;
  context?: Record<string, unknown>;
}

export interface ActionCheckResult {
  decision: 'allow' | 'block' | 'review';
  approved: boolean;
  approvalId?: string;
  riskScore: number;
  riskLevel: string;
  violations: string[];
  recommendations: string[];
}

export interface ApprovalRequest {
  toolName: string;
  action: string;
  parameters?: Record<string, unknown>;
  riskScore?: number;
  reasoning?: string[];
}

export interface ApprovalResult {
  id: string;
  status: 'pending' | 'approved' | 'denied' | 'expired' | 'auto_approved' | 'auto_denied';
  approved: boolean;
  decidedBy?: string;
  justification?: string;
  conditions: string[];
}

export interface SecurityEvent {
  eventType: string;
  severity?: 'info' | 'low' | 'medium' | 'high' | 'critical';
  toolName?: string;
  action?: string;
  parameters?: Record<string, unknown>;
  decision?: string;
  metadata?: Record<string, unknown>;
}

export interface AgentRegistration {
  name: string;
  agentType?: string;
  modelProvider?: string;
  modelName?: string;
  tools?: string[];
  metadata?: Record<string, unknown>;
}

export interface Agent {
  id: string;
  name: string;
  agentType: string;
  status: string;
  modelProvider?: string;
  modelName?: string;
  tools: string[];
  totalRequests: number;
  blockedRequests: number;
  healthScore: number;
  lastSeenAt?: string;
  registeredAt: string;
}

// =============================================================================
// ERRORS
// =============================================================================

export class VerityFluxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VerityFluxError';
  }
}

export class ApprovalRequired extends Error {
  approvalId: string;
  
  constructor(approvalId: string, message: string = 'Action requires approval') {
    super(`${message}: ${approvalId}`);
    this.name = 'ApprovalRequired';
    this.approvalId = approvalId;
  }
}

export class ActionDenied extends Error {
  reason: string;
  violations: string[];
  
  constructor(reason: string, violations: string[] = []) {
    super(`Action denied: ${reason}`);
    this.name = 'ActionDenied';
    this.reason = reason;
    this.violations = violations;
  }
}

// =============================================================================
// CLIENT
// =============================================================================

export class VerityFluxClient {
  private baseUrl: string;
  private apiKey?: string;
  private agentId?: string;
  private agentName: string;
  private timeout: number;
  
  constructor(config: VerityFluxConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.apiKey = config.apiKey;
    this.agentId = config.agentId;
    this.agentName = config.agentName || 'js-sdk-agent';
    this.timeout = config.timeout || 30000;
    
    if (config.autoRegister !== false && !config.agentId) {
      this.autoRegister().catch(err => {
        console.warn('Auto-registration failed:', err.message);
      });
    }
  }
  
  // ===========================================================================
  // HTTP Methods
  // ===========================================================================
  
  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    params?: Record<string, string>
  ): Promise<T> {
    let url = `${this.baseUrl}${path}`;
    
    if (params) {
      const searchParams = new URLSearchParams(params);
      url += `?${searchParams.toString()}`;
    }
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'VerityFlux-SDK-JS/1.0',
    };
    
    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    
    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      
      clearTimeout(timeoutId);
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new VerityFluxError(
          errorData.detail || `HTTP ${response.status}: ${response.statusText}`
        );
      }
      
      return await response.json();
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof VerityFluxError) throw error;
      throw new VerityFluxError(`Request failed: ${(error as Error).message}`);
    }
  }
  
  // ===========================================================================
  // Agent Management
  // ===========================================================================
  
  private async autoRegister(): Promise<void> {
    const result = await this.registerAgent({
      name: this.agentName,
      agentType: 'js-sdk',
      tools: [],
    });
    this.agentId = result.id;
  }
  
  async registerAgent(registration: AgentRegistration): Promise<Agent> {
    const result = await this.request<Agent>('POST', '/api/v1/soc/agents', {
      name: registration.name,
      agent_type: registration.agentType || 'custom',
      model_provider: registration.modelProvider,
      model_name: registration.modelName,
      tools: registration.tools || [],
      metadata: registration.metadata || {},
    });
    
    this.agentId = result.id;
    this.agentName = registration.name;
    
    return result;
  }
  
  async heartbeat(): Promise<void> {
    if (!this.agentId) {
      throw new VerityFluxError('Agent not registered');
    }
    
    await this.request('POST', `/api/v1/soc/agents/${this.agentId}/heartbeat`);
  }
  
  async getAgentStatus(): Promise<Agent> {
    if (!this.agentId) {
      throw new VerityFluxError('Agent not registered');
    }
    
    return await this.request<Agent>('GET', `/api/v1/soc/agents/${this.agentId}`);
  }
  
  // ===========================================================================
  // Action Validation
  // ===========================================================================
  
  async checkAction(request: ActionCheckRequest): Promise<ActionCheckResult> {
    if (!this.agentId) {
      throw new VerityFluxError('Agent not registered');
    }
    
    // Submit event
    const eventResult = await this.request<{
      id: string;
      alert_id?: string;
      risk_score: number;
    }>('POST', '/api/v1/soc/events', {
      agent_id: this.agentId,
      agent_name: this.agentName,
      event_type: 'tool_call',
      tool_name: request.toolName,
      action: request.action,
      parameters: request.parameters || {},
      decision: 'pending',
      risk_score: 0,
      metadata: request.context || {},
    });
    
    // Check if alert was created (high risk)
    if (eventResult.alert_id) {
      // Create approval request
      const approval = await this.request<{
        id: string;
        status: string;
        risk_score: number;
        risk_level: string;
      }>('POST', '/api/v1/approvals', {
        agent_id: this.agentId,
        agent_name: this.agentName,
        tool_name: request.toolName,
        action: request.action,
        parameters: request.parameters || {},
        risk_score: eventResult.risk_score || 50,
        risk_factors: [],
        violations: [],
        reasoning: ['Action triggered security alert'],
      });
      
      if (approval.status === 'pending') {
        throw new ApprovalRequired(
          approval.id,
          `Action requires approval: ${request.toolName}.${request.action}`
        );
      } else if (approval.status === 'auto_denied') {
        throw new ActionDenied('Action denied by policy');
      }
    }
    
    return {
      decision: 'allow',
      approved: true,
      riskScore: eventResult.risk_score || 0,
      riskLevel: 'low',
      violations: [],
      recommendations: [],
    };
  }
  
  async requestApproval(request: ApprovalRequest): Promise<string> {
    if (!this.agentId) {
      throw new VerityFluxError('Agent not registered');
    }
    
    const result = await this.request<{ id: string }>('POST', '/api/v1/approvals', {
      agent_id: this.agentId,
      agent_name: this.agentName,
      tool_name: request.toolName,
      action: request.action,
      parameters: request.parameters || {},
      risk_score: request.riskScore || 50,
      risk_factors: [],
      violations: [],
      reasoning: request.reasoning || [],
    });
    
    return result.id;
  }
  
  async getApprovalStatus(approvalId: string): Promise<ApprovalResult> {
    const result = await this.request<{
      id: string;
      status: string;
      decided_by?: string;
      justification?: string;
      conditions?: string[];
    }>('GET', `/api/v1/approvals/${approvalId}`);
    
    return {
      id: result.id,
      status: result.status as ApprovalResult['status'],
      approved: ['approved', 'auto_approved'].includes(result.status),
      decidedBy: result.decided_by,
      justification: result.justification,
      conditions: result.conditions || [],
    };
  }
  
  async waitForApproval(
    approvalId: string,
    timeout: number = 300000,
    pollInterval: number = 5000
  ): Promise<ApprovalResult> {
    const startTime = Date.now();
    
    while (true) {
      const result = await this.getApprovalStatus(approvalId);
      
      if (result.status !== 'pending') {
        if (result.approved) {
          return result;
        } else {
          throw new ActionDenied(result.justification || 'Approval denied');
        }
      }
      
      if (Date.now() - startTime >= timeout) {
        throw new VerityFluxError(`Approval timeout after ${timeout}ms`);
      }
      
      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }
  }
  
  // ===========================================================================
  // Event Reporting
  // ===========================================================================
  
  async reportEvent(event: SecurityEvent): Promise<{ id: string }> {
    if (!this.agentId) {
      throw new VerityFluxError('Agent not registered');
    }
    
    return await this.request<{ id: string }>('POST', '/api/v1/soc/events', {
      agent_id: this.agentId,
      agent_name: this.agentName,
      event_type: event.eventType,
      severity: event.severity || 'info',
      tool_name: event.toolName,
      action: event.action,
      parameters: event.parameters || {},
      decision: event.decision || 'allow',
      risk_score: 0,
      metadata: event.metadata || {},
    });
  }
  
  // ===========================================================================
  // Decorators / Wrappers
  // ===========================================================================
  
  /**
   * Wrap a function with security checks
   */
  wrapFunction<T extends (...args: unknown[]) => unknown>(
    fn: T,
    toolName: string,
    options: {
      requireApproval?: boolean;
      autoWait?: boolean;
      timeout?: number;
    } = {}
  ): T {
    const client = this;
    const { requireApproval = false, autoWait = true, timeout = 300000 } = options;
    
    return (async function(...args: unknown[]) {
      try {
        await client.checkAction({
          toolName,
          action: 'execute',
          parameters: { args: JSON.stringify(args).slice(0, 500) },
        });
      } catch (error) {
        if (error instanceof ApprovalRequired && autoWait) {
          await client.waitForApproval(error.approvalId, timeout);
        } else {
          throw error;
        }
      }
      
      return fn(...args);
    }) as T;
  }
  
  /**
   * Create a monitored version of a function
   */
  monitored<T extends (...args: unknown[]) => unknown>(
    fn: T,
    toolName: string,
    severity: SecurityEvent['severity'] = 'info'
  ): T {
    const client = this;
    
    return (async function(...args: unknown[]) {
      await client.reportEvent({
        eventType: 'tool_start',
        severity,
        toolName,
        action: 'execute',
      });
      
      try {
        const result = await fn(...args);
        
        await client.reportEvent({
          eventType: 'tool_success',
          severity,
          toolName,
          action: 'execute',
        });
        
        return result;
      } catch (error) {
        await client.reportEvent({
          eventType: 'tool_error',
          severity: 'high',
          toolName,
          action: 'execute',
          metadata: { error: (error as Error).message },
        });
        throw error;
      }
    }) as T;
  }
}

// =============================================================================
// CONVENIENCE FUNCTIONS
// =============================================================================

let defaultClient: VerityFluxClient | null = null;

export function init(config: VerityFluxConfig): VerityFluxClient {
  defaultClient = new VerityFluxClient(config);
  return defaultClient;
}

export function getClient(): VerityFluxClient {
  if (!defaultClient) {
    throw new VerityFluxError('Client not initialized. Call init() first.');
  }
  return defaultClient;
}

export async function checkAction(request: ActionCheckRequest): Promise<ActionCheckResult> {
  return getClient().checkAction(request);
}

export async function reportEvent(event: SecurityEvent): Promise<{ id: string }> {
  return getClient().reportEvent(event);
}

// =============================================================================
// DEFAULT EXPORT
// =============================================================================

export default VerityFluxClient;
