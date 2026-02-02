/**
 * OpenWebUIClient — All communication with the Open WebUI API.
 * 
 * Runs in the renderer process. Makes direct fetch() calls to the
 * Open WebUI instance on localhost. Uses Bearer token auth with the
 * API key configured during first-run setup.
 * 
 * Key methods:
 *   - listModels()           → available Ollama models
 *   - listChats()            → conversation history
 *   - chatCompletion()       → send message, get SSE stream back
 *   - createChat()           → start a new conversation
 *   - getChatMessages()      → messages for a specific conversation
 */

import type { ChatSession, ChatMessage, Model } from '../types/chat';

export interface OpenWebUIConfig {
  baseUrl: string;    // e.g. "http://localhost:8090"
  apiKey: string;     // Bearer token from Open WebUI Settings → Account → API Keys
}

export interface ConnectionTestResult {
  success: boolean;
  version?: string;
  user?: string;
  models?: number;
  error?: string;
  latencyMs: number;
}

export class OpenWebUIClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(config: OpenWebUIConfig) {
    // Strip trailing slash if present
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.apiKey = config.apiKey;
  }

  /**
   * Update the connection config (e.g. after first-run setup).
   */
  configure(config: OpenWebUIConfig): void {
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.apiKey = config.apiKey;
  }

  // ─── Connection Test ──────────────────────────────────────

  /**
   * Test the connection to Open WebUI. Verifies the URL is reachable,
   * the API key is valid, and returns basic info.
   */
  async testConnection(): Promise<ConnectionTestResult> {
    const start = Date.now();

    try {
      // Test 1: Can we reach the server?
      const configResponse = await this.fetch('/api/config');
      if (!configResponse.ok) {
        return {
          success: false,
          error: `Server returned HTTP ${configResponse.status}`,
          latencyMs: Date.now() - start,
        };
      }

      // Test 2: Is the API key valid? (requires auth)
      const userResponse = await this.fetch('/api/v1/auths/', { auth: true });
      if (!userResponse.ok) {
        return {
          success: false,
          error: userResponse.status === 401
            ? 'API key is invalid or expired'
            : `Auth check returned HTTP ${userResponse.status}`,
          latencyMs: Date.now() - start,
        };
      }
      const userData = await userResponse.json();

      // Test 3: Can we list models?
      const modelsResponse = await this.fetch('/api/models', { auth: true });
      let modelCount = 0;
      if (modelsResponse.ok) {
        const modelsData = await modelsResponse.json();
        modelCount = modelsData?.data?.length ?? modelsData?.models?.length ?? 0;
      }

      return {
        success: true,
        version: userData?.version || 'unknown',
        user: userData?.name || userData?.email || 'unknown',
        models: modelCount,
        latencyMs: Date.now() - start,
      };
    } catch (err) {
      return {
        success: false,
        error: err instanceof Error ? err.message : 'Connection failed',
        latencyMs: Date.now() - start,
      };
    }
  }

  // ─── Models ───────────────────────────────────────────────

  /**
   * List available models from Ollama (via Open WebUI).
   */
  async listModels(): Promise<Model[]> {
    const response = await this.fetch('/api/models', { auth: true });
    if (!response.ok) throw new Error(`Failed to list models: HTTP ${response.status}`);

    const data = await response.json();
    const models = data?.data ?? data?.models ?? [];

    return models.map((m: any) => ({
      id: m.id ?? m.name ?? m.model,
      name: m.name ?? m.id ?? m.model,
      size: m.size,
      modifiedAt: m.modified_at,
    }));
  }

  // ─── Conversations ────────────────────────────────────────

  /**
   * List all chat conversations.
   */
  async listChats(): Promise<ChatSession[]> {
    const response = await this.fetch('/api/v1/chats/', { auth: true });
    if (!response.ok) throw new Error(`Failed to list chats: HTTP ${response.status}`);

    const data = await response.json();
    return (data ?? []).map((c: any) => ({
      id: c.id,
      title: c.title || 'Untitled',
      createdAt: c.created_at,
      updatedAt: c.updated_at,
    }));
  }

  /**
   * Create a new chat conversation.
   */
  async createChat(title?: string): Promise<ChatSession> {
    const response = await this.fetch('/api/v1/chats/new', {
      auth: true,
      method: 'POST',
      body: JSON.stringify({
        chat: {
          title: title || 'New Chat',
          messages: [],
        },
      }),
    });

    if (!response.ok) throw new Error(`Failed to create chat: HTTP ${response.status}`);

    const data = await response.json();
    return {
      id: data.id,
      title: data.title || 'New Chat',
      createdAt: data.created_at,
      updatedAt: data.updated_at,
    };
  }

  /**
   * Get messages for a specific chat conversation.
   */
  async getChatMessages(chatId: string): Promise<ChatMessage[]> {
    const response = await this.fetch(`/api/v1/chats/${chatId}`, { auth: true });
    if (!response.ok) throw new Error(`Failed to get chat: HTTP ${response.status}`);

    const data = await response.json();
    const messages = data?.chat?.messages ?? [];

    return messages.map((m: any) => ({
      id: m.id || crypto.randomUUID(),
      role: m.role,
      content: m.content,
      timestamp: m.timestamp || data.updated_at,
      model: m.model,
    }));
  }

  /**
   * Delete a chat conversation.
   */
  async deleteChat(chatId: string): Promise<void> {
    const response = await this.fetch(`/api/v1/chats/${chatId}`, {
      auth: true,
      method: 'DELETE',
    });
    if (!response.ok) throw new Error(`Failed to delete chat: HTTP ${response.status}`);
  }

  // ─── Chat Completion (SSE Streaming) ──────────────────────

  /**
   * Send a chat completion request and return a ReadableStream of SSE events.
   * 
   * Usage:
   *   const stream = await client.chatCompletion(messages, modelId);
   *   for await (const chunk of stream) {
   *     // chunk is a string token
   *     appendToUI(chunk);
   *   }
   */
  async chatCompletion(
    messages: { role: string; content: string }[],
    model: string,
  ): Promise<ReadableStream<string>> {
    const response = await this.fetch('/api/chat/completions', {
      auth: true,
      method: 'POST',
      body: JSON.stringify({
        model,
        messages,
        stream: true,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      throw new Error(`Chat completion failed: HTTP ${response.status} — ${errorText}`);
    }

    if (!response.body) {
      throw new Error('Response body is null — streaming not supported');
    }

    // Transform the SSE byte stream into a stream of text tokens
    return response.body
      .pipeThrough(new TextDecoderStream())
      .pipeThrough(new TransformStream<string, string>({
        buffer: '',
        transform(chunk: string, controller: TransformStreamDefaultController<string>) {
          // SSE format: "data: {...}\n\n"
          // Chunks may split across SSE boundaries, so we buffer
          (this as any).buffer += chunk;
          const lines = (this as any).buffer.split('\n');
          (this as any).buffer = lines.pop() || ''; // Keep incomplete line in buffer

          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || !trimmed.startsWith('data: ')) continue;

            const data = trimmed.slice(6); // Remove "data: " prefix
            if (data === '[DONE]') return;

            try {
              const parsed = JSON.parse(data);
              const token = parsed?.choices?.[0]?.delta?.content;
              if (token) {
                controller.enqueue(token);
              }
            } catch {
              // Skip malformed JSON lines
            }
          }
        },
      } as any));
  }

  // ─── Internal Fetch Wrapper ───────────────────────────────

  private async fetch(
    path: string,
    options: {
      auth?: boolean;
      method?: string;
      body?: string;
    } = {},
  ): Promise<Response> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (options.auth) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    try {
      return await fetch(`${this.baseUrl}${path}`, {
        method: options.method || 'GET',
        headers,
        body: options.body,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }
  }
}
