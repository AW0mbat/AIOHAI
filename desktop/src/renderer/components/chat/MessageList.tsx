/**
 * MessageList — Scrollable container for chat messages.
 * 
 * Renders the message history with streaming support for
 * the current assistant response.
 */

import React from 'react';
import { Message } from './Message';
import { ActionCard } from './ActionCard';
import type { ChatMessage } from '../../types/chat';
import type { ParsedAction } from '../../types/actions';

interface MessageListProps {
  messages: ChatMessage[];
  streamingContent: string;
  isStreaming: boolean;
  onActionResponse: (actionId: string, response: 'approve' | 'reject' | 'explain') => void;
}

export const MessageList: React.FC<MessageListProps> = ({
  messages,
  streamingContent,
  isStreaming,
  onActionResponse,
}) => {
  // Empty state
  if (messages.length === 0 && !isStreaming) {
    return (
      <div className="message-list">
        <div className="chat-empty-state">
          <div className="chat-empty-icon">💬</div>
          <h2>Start a Conversation</h2>
          <p>
            Ask me anything. I can help with files, run commands, 
            query your smart home, and more.
          </p>
          <div className="chat-suggestions">
            <button className="chat-suggestion">What can you help me with?</button>
            <button className="chat-suggestion">List files in my Documents folder</button>
            <button className="chat-suggestion">What's the status of my smart home?</button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="message-list">
      {messages.map((message) => (
        <React.Fragment key={message.id}>
          <Message message={message} />
          
          {/* Render action cards for assistant messages with actions */}
          {message.role === 'assistant' && message.actions && message.actions.length > 0 && (
            <div className="action-cards-container">
              {message.actions.map((action) => (
                <ActionCard
                  key={action.id}
                  action={action}
                  onRespond={onActionResponse}
                />
              ))}
            </div>
          )}
        </React.Fragment>
      ))}

      {/* Streaming message */}
      {isStreaming && streamingContent && (
        <Message
          message={{
            id: 'streaming',
            role: 'assistant',
            content: streamingContent,
            timestamp: new Date().toISOString(),
          }}
          isStreaming
        />
      )}

      {/* Typing indicator when streaming but no content yet */}
      {isStreaming && !streamingContent && (
        <div className="message assistant">
          <div className="message-avatar">🤖</div>
          <div className="message-content">
            <div className="typing-indicator">
              <span></span>
              <span></span>
              <span></span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default MessageList;
