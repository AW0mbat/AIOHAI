/**
 * Message — Individual chat message bubble.
 * 
 * Renders user and assistant messages with markdown support,
 * code blocks, and visual differentiation.
 */

import React, { useMemo } from 'react';
import type { ChatMessage } from '../../types/chat';

interface MessageProps {
  message: ChatMessage;
  isStreaming?: boolean;
}

/**
 * Simple markdown renderer for chat messages.
 * Handles: code blocks, inline code, bold, italic, links, lists
 */
const renderMarkdown = (content: string): React.ReactNode => {
  // Split by code blocks first
  const parts = content.split(/(```[\s\S]*?```)/g);
  
  return parts.map((part, index) => {
    // Code block
    if (part.startsWith('```')) {
      const match = part.match(/```(\w+)?\n?([\s\S]*?)```/);
      if (match) {
        const language = match[1] || 'text';
        const code = match[2].trim();
        return (
          <pre key={index} className="code-block" data-language={language}>
            <div className="code-block-header">
              <span className="code-language">{language}</span>
              <button 
                className="code-copy-btn"
                onClick={() => navigator.clipboard.writeText(code)}
                title="Copy code"
              >
                📋
              </button>
            </div>
            <code>{code}</code>
          </pre>
        );
      }
    }
    
    // Regular text with inline formatting
    return <span key={index}>{renderInlineMarkdown(part)}</span>;
  });
};

/**
 * Render inline markdown (bold, italic, code, links).
 */
const renderInlineMarkdown = (text: string): React.ReactNode => {
  // Process line by line for lists
  const lines = text.split('\n');
  
  return lines.map((line, lineIndex) => {
    // Bullet list
    if (line.match(/^[\s]*[-*]\s/)) {
      return (
        <div key={lineIndex} className="md-list-item">
          {processInlineFormatting(line.replace(/^[\s]*[-*]\s/, '• '))}
        </div>
      );
    }
    
    // Numbered list
    if (line.match(/^[\s]*\d+\.\s/)) {
      return (
        <div key={lineIndex} className="md-list-item">
          {processInlineFormatting(line)}
        </div>
      );
    }
    
    // Headers
    if (line.startsWith('### ')) {
      return <h4 key={lineIndex} className="md-h4">{line.slice(4)}</h4>;
    }
    if (line.startsWith('## ')) {
      return <h3 key={lineIndex} className="md-h3">{line.slice(3)}</h3>;
    }
    if (line.startsWith('# ')) {
      return <h2 key={lineIndex} className="md-h2">{line.slice(2)}</h2>;
    }
    
    // Regular paragraph
    if (line.trim()) {
      return (
        <p key={lineIndex} className="md-paragraph">
          {processInlineFormatting(line)}
        </p>
      );
    }
    
    // Empty line = spacing
    return <br key={lineIndex} />;
  });
};

/**
 * Process inline formatting: bold, italic, code, links
 */
const processInlineFormatting = (text: string): React.ReactNode => {
  // Match patterns in order of precedence
  const patterns = [
    { regex: /`([^`]+)`/g, render: (m: string) => <code className="inline-code" key={m}>{m}</code> },
    { regex: /\*\*([^*]+)\*\*/g, render: (m: string) => <strong key={m}>{m}</strong> },
    { regex: /\*([^*]+)\*/g, render: (m: string) => <em key={m}>{m}</em> },
    { regex: /\[([^\]]+)\]\(([^)]+)\)/g, render: (m: string, url: string) => (
      <a key={m} href={url} target="_blank" rel="noopener noreferrer" className="md-link">{m}</a>
    )},
  ];
  
  // Simple approach: just return the text for now
  // A full implementation would recursively process all patterns
  // For MVP, we handle the most common case: inline code
  const codePattern = /`([^`]+)`/g;
  const parts: React.ReactNode[] = [];
  let lastIndex = 0;
  let match;
  
  while ((match = codePattern.exec(text)) !== null) {
    // Add text before match
    if (match.index > lastIndex) {
      parts.push(text.slice(lastIndex, match.index));
    }
    // Add code
    parts.push(
      <code key={match.index} className="inline-code">{match[1]}</code>
    );
    lastIndex = match.index + match[0].length;
  }
  
  // Add remaining text
  if (lastIndex < text.length) {
    parts.push(text.slice(lastIndex));
  }
  
  return parts.length > 0 ? parts : text;
};

/**
 * Strip action tags from display content.
 */
const stripActionTags = (content: string): string => {
  return content.replace(/<action[\s\S]*?<\/action>/gi, '').trim();
};

export const Message: React.FC<MessageProps> = ({ message, isStreaming }) => {
  const isUser = message.role === 'user';
  const isSystem = message.role === 'system';
  
  // Strip action tags from displayed content
  const displayContent = useMemo(() => {
    return stripActionTags(message.content);
  }, [message.content]);
  
  // Don't render empty messages (can happen after stripping actions)
  if (!displayContent.trim() && !isStreaming) {
    return null;
  }
  
  return (
    <div className={`message ${message.role} ${isStreaming ? 'streaming' : ''}`}>
      <div className="message-avatar">
        {isUser ? '👤' : isSystem ? '⚙️' : '🤖'}
      </div>
      <div className="message-bubble">
        <div className="message-content">
          {renderMarkdown(displayContent)}
          {isStreaming && <span className="cursor-blink">▊</span>}
        </div>
        <div className="message-meta">
          <span className="message-time">
            {new Date(message.timestamp).toLocaleTimeString([], { 
              hour: '2-digit', 
              minute: '2-digit' 
            })}
          </span>
          {message.model && (
            <span className="message-model">{message.model}</span>
          )}
        </div>
      </div>
    </div>
  );
};

export default Message;
