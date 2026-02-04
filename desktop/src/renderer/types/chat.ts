/**
 * Types for Open WebUI chat integration.
 */

import type { ParsedAction } from './actions';

export interface ChatSession {
  id: string;
  title: string;
  createdAt: string;
  updatedAt: string;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string;
  model?: string;
  
  /** Parsed actions from assistant responses */
  actions?: ParsedAction[];
}

export interface Model {
  id: string;
  name: string;
  size?: number;
  modifiedAt?: string;
}

export interface ApprovalCard {
  requestId: string;
  operation: string;
  target: string;
  tier: number;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
}
