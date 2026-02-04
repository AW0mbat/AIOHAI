/**
 * ActionCard — Approval request card for AIOHAI actions.
 * 
 * Displays parsed action requests from the LLM with
 * CONFIRM/REJECT/EXPLAIN buttons. Visual styling indicates
 * the approval tier (standard, elevated, critical).
 */

import React, { useState } from 'react';
import type { ParsedAction } from '../../types/actions';

interface ActionCardProps {
  action: ParsedAction;
  onRespond: (actionId: string, response: 'approve' | 'reject' | 'explain') => void;
}

/**
 * Get tier display info
 */
const getTierInfo = (tier: number): { label: string; className: string; icon: string } => {
  switch (tier) {
    case 1:
      return { label: 'Standard', className: 'tier-standard', icon: '✓' };
    case 2:
      return { label: 'Elevated', className: 'tier-elevated', icon: '⚠️' };
    case 3:
      return { label: 'Critical', className: 'tier-critical', icon: '🔐' };
    case 4:
      return { label: 'Admin', className: 'tier-admin', icon: '👑' };
    default:
      return { label: 'Unknown', className: 'tier-unknown', icon: '?' };
  }
};

/**
 * Get action type display info
 */
const getActionTypeInfo = (type: string): { label: string; icon: string } => {
  const types: Record<string, { label: string; icon: string }> = {
    'COMMAND': { label: 'Execute Command', icon: '⚡' },
    'READ': { label: 'Read File', icon: '📖' },
    'WRITE': { label: 'Write File', icon: '✏️' },
    'LIST': { label: 'List Directory', icon: '📁' },
    'DELETE': { label: 'Delete File', icon: '🗑️' },
    'API_QUERY': { label: 'API Query', icon: '🌐' },
  };
  return types[type] || { label: type, icon: '❓' };
};

export const ActionCard: React.FC<ActionCardProps> = ({ action, onRespond }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  
  const tierInfo = getTierInfo(action.tier);
  const actionInfo = getActionTypeInfo(action.type);
  const isResolved = action.status !== 'pending';
  
  const handleRespond = async (response: 'approve' | 'reject' | 'explain') => {
    if (response === 'explain') {
      setIsExpanded(!isExpanded);
      return;
    }
    
    setIsProcessing(true);
    try {
      await onRespond(action.id, response);
    } finally {
      setIsProcessing(false);
    }
  };
  
  return (
    <div className={`action-card ${tierInfo.className} ${action.status}`}>
      {/* Header */}
      <div className="action-card-header">
        <div className="action-card-type">
          <span className="action-icon">{actionInfo.icon}</span>
          <span className="action-label">{actionInfo.label}</span>
        </div>
        <div className="action-card-tier">
          <span className="tier-icon">{tierInfo.icon}</span>
          <span className="tier-label">Tier {action.tier}: {tierInfo.label}</span>
        </div>
      </div>
      
      {/* Target */}
      <div className="action-card-target">
        <code>{action.target}</code>
      </div>
      
      {/* Body (if has content and expanded or always for some types) */}
      {action.body && (isExpanded || action.type === 'COMMAND') && (
        <div className="action-card-body">
          <pre><code>{action.body}</code></pre>
        </div>
      )}
      
      {/* Status badge for resolved actions */}
      {isResolved && (
        <div className={`action-card-status status-${action.status}`}>
          {action.status === 'approved' && '✓ Approved'}
          {action.status === 'rejected' && '✗ Rejected'}
          {action.status === 'expired' && '⏱ Expired'}
        </div>
      )}
      
      {/* Action buttons (only for pending) */}
      {!isResolved && (
        <div className="action-card-actions">
          {action.body && (
            <button
              className="action-btn action-btn-explain"
              onClick={() => handleRespond('explain')}
              disabled={isProcessing}
            >
              {isExpanded ? 'Hide Details' : 'Show Details'}
            </button>
          )}
          <button
            className="action-btn action-btn-reject"
            onClick={() => handleRespond('reject')}
            disabled={isProcessing}
          >
            {isProcessing ? '...' : 'Reject'}
          </button>
          <button
            className="action-btn action-btn-approve"
            onClick={() => handleRespond('approve')}
            disabled={isProcessing}
          >
            {isProcessing ? '...' : action.tier >= 3 ? '🔐 Approve with Key' : 'Confirm'}
          </button>
        </div>
      )}
      
      {/* FIDO2 hint for tier 3+ */}
      {!isResolved && action.tier >= 3 && (
        <div className="action-card-fido-hint">
          <span className="fido-icon">🔑</span>
          This action requires hardware key approval (FIDO2/Windows Hello)
        </div>
      )}
    </div>
  );
};

export default ActionCard;
