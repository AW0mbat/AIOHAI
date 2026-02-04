/**
 * Types for AIOHAI action parsing and approval system.
 */

export type ActionType = 
  | 'COMMAND'
  | 'READ'
  | 'WRITE'
  | 'LIST'
  | 'DELETE'
  | 'API_QUERY';

export type ActionStatus = 
  | 'pending'
  | 'approved'
  | 'rejected'
  | 'expired';

export interface ParsedAction {
  /** Unique ID for this action instance */
  id: string;
  
  /** Action type (COMMAND, READ, WRITE, etc.) */
  type: ActionType;
  
  /** Target path, command, or URL */
  target: string;
  
  /** Approval tier (1=standard, 2=elevated, 3=critical, 4=admin) */
  tier: number;
  
  /** Optional body content (e.g., file content for WRITE, command for COMMAND) */
  body: string;
  
  /** Current approval status */
  status: ActionStatus;
  
  /** Timestamp when action was parsed */
  timestamp?: string;
  
  /** Error message if execution failed */
  error?: string;
  
  /** Result of execution (if approved and completed) */
  result?: string;
}

export interface ApprovalRequest {
  /** Request ID from the proxy */
  requestId: string;
  
  /** The parsed action */
  action: ParsedAction;
  
  /** HMAC token for approval verification */
  token: string;
  
  /** Expiration timestamp */
  expiresAt: string;
  
  /** Whether FIDO2 is required */
  requiresFido2: boolean;
}

export interface ApprovalResponse {
  /** Request ID being responded to */
  requestId: string;
  
  /** Approval decision */
  decision: 'approve' | 'reject';
  
  /** HMAC token for verification */
  token: string;
  
  /** FIDO2 assertion (if required) */
  fido2Assertion?: string;
}
