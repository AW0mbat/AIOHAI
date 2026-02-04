/**
 * InputBar — Message input with file attachment and send button.
 * 
 * Supports:
 * - Multi-line input (Shift+Enter for newline, Enter to send)
 * - File attachment button
 * - Stop button during streaming
 * - Character limit indicator
 */

import React, { useState, useRef, useCallback, KeyboardEvent } from 'react';

interface InputBarProps {
  onSend: (content: string, attachments?: File[]) => void;
  onStop: () => void;
  isStreaming: boolean;
  disabled?: boolean;
}

const MAX_CHARS = 10000;

export const InputBar: React.FC<InputBarProps> = ({
  onSend,
  onStop,
  isStreaming,
  disabled,
}) => {
  const [message, setMessage] = useState('');
  const [attachments, setAttachments] = useState<File[]>([]);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const charCount = message.length;
  const isOverLimit = charCount > MAX_CHARS;
  const canSend = message.trim().length > 0 && !isOverLimit && !disabled && !isStreaming;

  /**
   * Auto-resize textarea to fit content
   */
  const adjustTextareaHeight = useCallback(() => {
    const textarea = textareaRef.current;
    if (textarea) {
      textarea.style.height = 'auto';
      textarea.style.height = `${Math.min(textarea.scrollHeight, 200)}px`;
    }
  }, []);

  /**
   * Handle input change
   */
  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setMessage(e.target.value);
    adjustTextareaHeight();
  };

  /**
   * Handle key press
   */
  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    // Enter sends, Shift+Enter adds newline
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (canSend) {
        handleSend();
      }
    }
  };

  /**
   * Send the message
   */
  const handleSend = () => {
    if (!canSend) return;
    
    onSend(message, attachments.length > 0 ? attachments : undefined);
    setMessage('');
    setAttachments([]);
    
    // Reset textarea height
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
    }
  };

  /**
   * Handle file selection
   */
  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []);
    setAttachments(prev => [...prev, ...files]);
    
    // Reset input so same file can be selected again
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  /**
   * Remove an attachment
   */
  const removeAttachment = (index: number) => {
    setAttachments(prev => prev.filter((_, i) => i !== index));
  };

  /**
   * Open file picker
   */
  const handleAttachClick = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className="input-bar-container">
      {/* Attachments preview */}
      {attachments.length > 0 && (
        <div className="attachments-preview">
          {attachments.map((file, index) => (
            <div key={index} className="attachment-chip">
              <span className="attachment-icon">📎</span>
              <span className="attachment-name">{file.name}</span>
              <button
                className="attachment-remove"
                onClick={() => removeAttachment(index)}
                title="Remove attachment"
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      )}

      <div className="input-bar">
        {/* Attach button */}
        <button
          className="input-bar-btn attach-btn"
          onClick={handleAttachClick}
          disabled={disabled || isStreaming}
          title="Attach file"
        >
          📎
        </button>
        
        <input
          ref={fileInputRef}
          type="file"
          multiple
          onChange={handleFileSelect}
          style={{ display: 'none' }}
        />

        {/* Text input */}
        <textarea
          ref={textareaRef}
          value={message}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          placeholder={isStreaming ? 'Waiting for response...' : 'Type a message... (Enter to send, Shift+Enter for newline)'}
          disabled={disabled || isStreaming}
          rows={1}
          className="input-textarea"
        />

        {/* Character count (shows near limit) */}
        {charCount > MAX_CHARS * 0.8 && (
          <div className={`char-count ${isOverLimit ? 'over-limit' : ''}`}>
            {charCount.toLocaleString()} / {MAX_CHARS.toLocaleString()}
          </div>
        )}

        {/* Send or Stop button */}
        {isStreaming ? (
          <button
            className="input-bar-btn stop-btn"
            onClick={onStop}
            title="Stop generation"
          >
            ⬛
          </button>
        ) : (
          <button
            className="input-bar-btn send-btn"
            onClick={handleSend}
            disabled={!canSend}
            title="Send message"
          >
            ➤
          </button>
        )}
      </div>
    </div>
  );
};

export default InputBar;
