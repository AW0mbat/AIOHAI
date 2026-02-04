/**
 * ChatPanel — Main chat interface with SSE streaming.
 * 
 * Manages conversation state, streams responses from Open WebUI,
 * parses action tags, and coordinates with the approval system.
 */

import React, { useState, useCallback, useRef, useEffect } from 'react';
import { MessageList } from './MessageList';
import { InputBar } from './InputBar';
import { OpenWebUIClient } from '../../services/OpenWebUIClient';
import type { ChatMessage, Model } from '../../types/chat';
import type { ParsedAction } from '../../types/actions';
import './chat.css';

interface ChatPanelProps {
  client: OpenWebUIClient | null;
}

interface ConversationState {
  messages: ChatMessage[];
  isStreaming: boolean;
  streamingContent: string;
  error: string | null;
}

export const ChatPanel: React.FC<ChatPanelProps> = ({ client }) => {
  const [models, setModels] = useState<Model[]>([]);
  const [selectedModel, setSelectedModel] = useState<string>('');
  const [conversation, setConversation] = useState<ConversationState>({
    messages: [],
    isStreaming: false,
    streamingContent: '',
    error: null,
  });

  const abortControllerRef = useRef<AbortController | null>(null);
  const messageEndRef = useRef<HTMLDivElement>(null);

  // Load available models on mount
  useEffect(() => {
    if (!client) return;

    client.listModels()
      .then((modelList) => {
        setModels(modelList);
        if (modelList.length > 0 && !selectedModel) {
          setSelectedModel(modelList[0].id);
        }
      })
      .catch((err) => {
        console.error('Failed to load models:', err);
        setConversation(prev => ({
          ...prev,
          error: 'Failed to load models. Check your connection.',
        }));
      });
  }, [client]);

  // Auto-scroll to bottom when new content arrives
  useEffect(() => {
    messageEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [conversation.messages, conversation.streamingContent]);

  /**
   * Parse <action> tags from assistant response.
   */
  const parseActions = (content: string): ParsedAction[] => {
    const actions: ParsedAction[] = [];
    const actionRegex = /<action\s+type="([^"]+)"\s+target="([^"]+)"(?:\s+tier="(\d+)")?>([\s\S]*?)<\/action>/gi;
    
    let match;
    while ((match = actionRegex.exec(content)) !== null) {
      actions.push({
        id: crypto.randomUUID(),
        type: match[1] as ParsedAction['type'],
        target: match[2],
        tier: match[3] ? parseInt(match[3], 10) : 2,
        body: match[4].trim(),
        status: 'pending',
      });
    }
    
    return actions;
  };

  /**
   * Send a message and stream the response.
   */
  const handleSendMessage = useCallback(async (content: string, attachments?: File[]) => {
    if (!client || !selectedModel || !content.trim()) return;

    // Add user message to conversation
    const userMessage: ChatMessage = {
      id: crypto.randomUUID(),
      role: 'user',
      content: content.trim(),
      timestamp: new Date().toISOString(),
    };

    setConversation(prev => ({
      ...prev,
      messages: [...prev.messages, userMessage],
      isStreaming: true,
      streamingContent: '',
      error: null,
    }));

    // Build message history for API
    const messageHistory = [
      ...conversation.messages.map(m => ({ role: m.role, content: m.content })),
      { role: 'user', content: content.trim() },
    ];

    try {
      // Create abort controller for this request
      abortControllerRef.current = new AbortController();

      const stream = await client.chatCompletion(messageHistory, selectedModel);
      const reader = stream.getReader();
      let fullContent = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        fullContent += value;
        setConversation(prev => ({
          ...prev,
          streamingContent: fullContent,
        }));
      }

      // Parse any actions from the response
      const actions = parseActions(fullContent);

      // Finalize assistant message
      const assistantMessage: ChatMessage = {
        id: crypto.randomUUID(),
        role: 'assistant',
        content: fullContent,
        timestamp: new Date().toISOString(),
        model: selectedModel,
        actions: actions.length > 0 ? actions : undefined,
      };

      setConversation(prev => ({
        ...prev,
        messages: [...prev.messages, assistantMessage],
        isStreaming: false,
        streamingContent: '',
      }));

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Stream failed';
      
      // Don't show error if we aborted intentionally
      if (errorMessage.includes('abort')) {
        setConversation(prev => ({
          ...prev,
          isStreaming: false,
          streamingContent: '',
        }));
        return;
      }

      setConversation(prev => ({
        ...prev,
        isStreaming: false,
        streamingContent: '',
        error: errorMessage,
      }));
    }
  }, [client, selectedModel, conversation.messages]);

  /**
   * Stop the current stream.
   */
  const handleStopStream = useCallback(() => {
    abortControllerRef.current?.abort();
    setConversation(prev => ({
      ...prev,
      isStreaming: false,
    }));
  }, []);

  /**
   * Handle action approval/rejection.
   */
  const handleActionResponse = useCallback(async (
    actionId: string,
    response: 'approve' | 'reject' | 'explain'
  ) => {
    // Update action status in the message
    setConversation(prev => ({
      ...prev,
      messages: prev.messages.map(msg => {
        if (!msg.actions) return msg;
        return {
          ...msg,
          actions: msg.actions.map(action => 
            action.id === actionId
              ? { ...action, status: response === 'approve' ? 'approved' : 'rejected' }
              : action
          ),
        };
      }),
    }));

    // TODO: Send approval/rejection to AIOHAI proxy
    // This will be implemented when we integrate with the proxy's approval endpoint
    console.log(`Action ${actionId}: ${response}`);
  }, []);

  /**
   * Clear conversation.
   */
  const handleClearChat = useCallback(() => {
    setConversation({
      messages: [],
      isStreaming: false,
      streamingContent: '',
      error: null,
    });
  }, []);

  // Not connected state
  if (!client) {
    return (
      <div className="chat-panel">
        <div className="chat-empty-state">
          <div className="chat-empty-icon">🔌</div>
          <h2>Not Connected</h2>
          <p>Configure your Open WebUI connection in Settings to start chatting.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="chat-panel">
      {/* Header with model selector */}
      <div className="chat-header">
        <div className="chat-header-left">
          <h1 className="chat-title">Chat</h1>
          {conversation.messages.length > 0 && (
            <button 
              className="chat-clear-btn"
              onClick={handleClearChat}
              title="Clear conversation"
            >
              Clear
            </button>
          )}
        </div>
        <div className="chat-header-right">
          <label className="model-selector">
            <span className="model-selector-label">Model:</span>
            <select
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              disabled={conversation.isStreaming}
            >
              {models.map(model => (
                <option key={model.id} value={model.id}>
                  {model.name}
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>

      {/* Error banner */}
      {conversation.error && (
        <div className="chat-error-banner">
          <span className="chat-error-icon">⚠️</span>
          <span>{conversation.error}</span>
          <button 
            className="chat-error-dismiss"
            onClick={() => setConversation(prev => ({ ...prev, error: null }))}
          >
            ✕
          </button>
        </div>
      )}

      {/* Message list */}
      <MessageList
        messages={conversation.messages}
        streamingContent={conversation.streamingContent}
        isStreaming={conversation.isStreaming}
        onActionResponse={handleActionResponse}
      />
      <div ref={messageEndRef} />

      {/* Input bar */}
      <InputBar
        onSend={handleSendMessage}
        onStop={handleStopStream}
        isStreaming={conversation.isStreaming}
        disabled={!selectedModel}
      />
    </div>
  );
};

export default ChatPanel;
