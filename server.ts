#!/usr/bin/env deno run --allow-net --allow-read --allow-env

/**
 * ===============================
 * Deno Server Configuration (Smart Stream Handling)
 * ===============================
 * Environment variables:
 * - PORT: (Optional) Server port, defaults to 8000
 * - LOG_LEVEL: (Optional) Logging level: error, warn, info, debug (defaults to error)
 *
 * API Key Usage:
 * - API keys are passed in the Authorization header of each request
 * - Format: "Bearer your_aixplain_api_key"
 * - The server will use the provided key directly for upstream requests
 *
 * Features:
 * - Smart streaming: Only converts non-streaming upstream APIs to streaming when client requests streaming
 * - Model mapping: Maps user-friendly model names to actual IDs using embedded dictionary
 * - /v1/models endpoint: Returns available models in OpenAI format
 * - Configurable logging system (default: error only)
 * - CORS support
 */

import { serve } from "https://deno.land/std@0.208.0/http/server.ts";

// Model mappings embedded as dictionary
const MODEL_MAPPINGS: Record<string, string> = {
  "gpt-5": "6895d692d50c89537c1cf236",
  "gpt-5-mini": "6895d6d1d50c89537c1cf237",
  "gpt-5-nano": "6895d70ed50c89537c1cf238",
  "gpt-4.1-mini": "67fd9ddfef0365783d06e2ef",
  "gpt-4.1": "67fd9d6aef0365783d06e2ee",
  "gpt-4o-mini": "669a63646eb56306647e1091",
  "gpt-4o": "6646261c6eb563165658bbb1",
  "claude-sonnet-4.5": "68db1d77ce180d2fdb4deaf5",
  "claude-opus-4.1": "689cc60d3ce71f58d73cc984",
  "claude-3.7-sonnet": "67be216bd8f6a65d6f74d5e9",
  "claude-3.5-sonnet": "671be4886eb56397e51f7541",
  "gemini-2.5-pro": "68d43005ce180d2fdb4deac7",
  // "kimi-k2-instruct": "687e706a98bec9224596d301",
  "deepseek-v3.1": "68d40ca9c8568c61c1c4f403",
  "deepseek-v3.1-terminus": "68d40bacc8568c61c1c4f402",
  // "deepseek-v3-0324": "67e2f3f243d4fa5705dfa71e"
};

// Logging System
enum LogLevel {
  ERROR = 0,
  WARN = 1,
  INFO = 2,
  DEBUG = 3,
}

class Logger {
  private level: LogLevel;

  constructor(level: string = "error") {
    switch (level.toLowerCase()) {
      case "debug":
        this.level = LogLevel.DEBUG;
        break;
      case "info":
        this.level = LogLevel.INFO;
        break;
      case "warn":
        this.level = LogLevel.WARN;
        break;
      case "error":
      default:
        this.level = LogLevel.ERROR;
        break;
    }
  }

  private log(level: LogLevel, levelName: string, ...args: any[]) {
    if (level <= this.level) {
      const timestamp = new Date().toISOString();
      console.log(`[${timestamp}] [${levelName}]`, ...args);
    }
  }

  error(...args: any[]) {
    this.log(LogLevel.ERROR, "ERROR", ...args);
  }

  warn(...args: any[]) {
    this.log(LogLevel.WARN, "WARN", ...args);
  }

  info(...args: any[]) {
    this.log(LogLevel.INFO, "INFO", ...args);
  }

  debug(...args: any[]) {
    this.log(LogLevel.DEBUG, "DEBUG", ...args);
  }
}

// Initialize logger
const logger = new Logger(Deno.env.get("LOG_LEVEL") || "warn");

// Types
interface ModelMapping {
  model: string;
  id: string;
}

interface ChatCompletionRequest {
  model: string;
  messages: Array<{
    role: string;
    content: string;
  }>;
  stream?: boolean;
  [key: string]: any;
}

interface RequestWithAuth {
  request: Request;
  apiKey: string;
}

interface OpenAIModel {
  id: string;
  object: string;
  created: number;
  owned_by: string;
}

// Convert embedded mappings to ModelMapping array format for compatibility
function getModelMappings(): ModelMapping[] {
  return Object.entries(MODEL_MAPPINGS).map(([model, id]) => ({ model, id }));
}

const modelMappings: ModelMapping[] = getModelMappings();

// Helper functions
function generateChatcmplId(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "chatcmpl-";
  for (let i = 0; i < 29; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function createSSEChunk(content: string | null, model: string, finishReason: string | null = null): string {
  const chunk = {
    id: generateChatcmplId(),
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model: model,
    choices: [
      {
        index: 0,
        delta: content !== null ? { content: content } : {},
        logprobs: null,
        finish_reason: finishReason,
      },
    ],
  };
  return `data: ${JSON.stringify(chunk)}\n\n`;
}

function handleOPTIONS(request: Request): Response {
  const origin = request.headers.get("Origin") || "*";
  const requestHeaders = request.headers.get("Access-Control-Request-Headers") || "Authorization, Content-Type";

  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": requestHeaders,
      "Access-Control-Max-Age": "86400",
    },
  });
}

function getNestedProperty(obj: any, path: string): any {
  if (!path || typeof path !== 'string') return undefined;
  const keys = path.replace(/\[['"]?(\w+)['"]?\]/g, '.$1').replace(/^\./, '').split('.');
  let result = obj;
  for (const key of keys) {
    if (result === null || result === undefined) {
      return undefined;
    }
    result = result[key];
  }
  return result;
}


// Map model name to actual ID
function mapModelName(modelName: string): string {
  return MODEL_MAPPINGS[modelName] || modelName;
}

// Get user-friendly model name from ID
function getModelDisplayName(modelId: string): string {
  for (const [model, id] of Object.entries(MODEL_MAPPINGS)) {
    if (id === modelId) return model;
  }
  return modelId;
}

// Handle /v1/models endpoint
function handleModelsEndpoint(): Response {
  const openaiModels: OpenAIModel[] = modelMappings.map(mapping => ({
    id: mapping.model,
    object: "model",
    created: Math.floor(Date.now() / 1000),
    owned_by: "aixplain-proxy"
  }));

  return new Response(JSON.stringify({
    object: "list",
    data: openaiModels
  }), {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

// Main request handler
async function handleRequest(request: Request): Promise<Response> {
  if (request.method === "OPTIONS") {
    return handleOPTIONS(request);
  }

  const url = new URL(request.url);

  // Handle /v1/models endpoint
  if (url.pathname === "/v1/models" && request.method === "GET") {
    return handleModelsEndpoint();
  }

  // Only handle POST requests for chat completions
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method Not Allowed" }), {
      status: 405,
      headers: {
        'Allow': 'GET, POST, OPTIONS',
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }

  // Extract API key from Authorization header
  const authHeader = request.headers.get("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return new Response(JSON.stringify({ error: "Missing or invalid Authorization header. Expected: Bearer <your_aixplain_api_key>" }), {
      status: 401,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }

  const apiKey = authHeader.substring(7); // Remove "Bearer " prefix
  if (!apiKey.trim()) {
    return new Response(JSON.stringify({ error: "API key cannot be empty" }), {
      status: 401,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }

  logger.debug(`Using provided API key: ${apiKey.substring(0, 8)}...`);

  // Configuration
  const UPSTREAM_API_URL = "https://models.aixplain.com/api/v1/chat/completions";
  const CONTENT_FIELD = "choices[0].message.content";
  const FINISH_REASON_FIELD = "choices[0].finish_reason";

  // Parse client request
  let clientRequest: ChatCompletionRequest;
  try {
    clientRequest = await request.json();
    if (!clientRequest.model) {
      throw new Error("'model' field is missing in client request");
    }
  } catch (err) {
    logger.error("Invalid JSON body:", err);
    return new Response(JSON.stringify({ error: "Invalid JSON body or missing 'model' field" }), {
      status: 400,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }

  // Map model name to actual ID
  const originalModel = clientRequest.model;
  const mappedModelId = mapModelName(originalModel);

  // Prepare upstream request
  const upstreamPayload = {
    max_tokens: 8192,
    ...clientRequest
  };
  upstreamPayload.model = mappedModelId;

  // Key fix: Preserve client's streaming preference for upstream request
  // Only force non-streaming if upstream doesn't support streaming AND client wants streaming
  const clientWantsStreaming = clientRequest.stream === true;

  logger.debug(`Client model: ${originalModel} -> Mapped to: ${mappedModelId}`);
  logger.debug(`Client wants streaming: ${clientWantsStreaming}`);
  logger.debug(`Upstream payload:`, JSON.stringify(upstreamPayload, null, 2));

  const upstreamRequestOptions = {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "authorization": `Bearer ${apiKey}`,
    },
    body: JSON.stringify(upstreamPayload),
  };

  try {
    logger.debug("Making upstream request to:", UPSTREAM_API_URL);
    const upstreamResponse = await fetch(UPSTREAM_API_URL, upstreamRequestOptions);

    if (!upstreamResponse.ok) {
      const errorBody = await upstreamResponse.text();
      logger.error(`Upstream request failed: ${upstreamResponse.status} ${upstreamResponse.statusText}`, errorBody.substring(0, 500));
      let errorJson: any = { error: `Upstream API Error (${upstreamResponse.status})`, details: errorBody.substring(0, 500) };
      try {
        errorJson = JSON.parse(errorBody);
      } catch (e) {
        // ignore parsing error
      }
      return new Response(JSON.stringify(errorJson), {
        status: upstreamResponse.status,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    // Check if upstream returned streaming response
    const contentType = upstreamResponse.headers.get('content-type');
    const isUpstreamStreaming = contentType?.includes('text/event-stream');

    logger.debug(`Upstream response content-type: ${contentType}`);
    logger.debug(`Is upstream streaming: ${isUpstreamStreaming}`);
    logger.debug(`Route decision: ${isUpstreamStreaming && clientWantsStreaming ? 'pass-through streaming' : 'handle non-streaming'}`);

    if (isUpstreamStreaming && clientWantsStreaming) {
      // Check if the streaming response contains a Stream Error
      const reader = upstreamResponse.body?.getReader();
      if (reader) {
        const decoder = new TextDecoder();
        let buffer = '';
        let hasStreamError = false;
        let allChunks: Uint8Array[] = [];

        try {
          // Read the first chunk to check for stream error
          const { value, done } = await reader.read();
          if (value) {
            buffer = decoder.decode(value, { stream: true });
            logger.debug("First streaming chunk:", buffer.substring(0, 200));
            allChunks.push(value);

            // Check if it's a stream error
            if (buffer.includes('"error":"Stream Error"')) {
              hasStreamError = true;
              logger.debug("Detected Stream Error in upstream response, falling back to non-streaming");
            }
          }

          if (hasStreamError) {
            // Release the reader since we're falling back to non-streaming
            reader.releaseLock();

            // Fallback: Make a non-streaming request and convert to streaming
            logger.debug("Making fallback non-streaming request");
            const fallbackPayload = { ...upstreamPayload };
            fallbackPayload.stream = false;

            const fallbackResponse = await fetch(UPSTREAM_API_URL, {
              method: "POST",
              headers: {
                "content-type": "application/json",
                "authorization": `Bearer ${apiKey}`,
              },
              body: JSON.stringify(fallbackPayload),
            });

            if (!fallbackResponse.ok) {
              const errorBody = await fallbackResponse.text();
              logger.error(`Fallback request failed: ${fallbackResponse.status}`);
              return new Response(JSON.stringify({ error: `Fallback API Error (${fallbackResponse.status})`, details: errorBody.substring(0, 500) }), {
                status: fallbackResponse.status,
                headers: {
                  'Content-Type': 'application/json',
                  'Access-Control-Allow-Origin': '*'
                }
              });
            }

            const fallbackJson = await fallbackResponse.json();

            // Check for upstream API errors in fallback response
            if (fallbackJson.status === "FAILED" || fallbackJson.error) {
              const errorMessage = fallbackJson.supplierError || fallbackJson.error || "Unknown upstream error";
              logger.warn("Fallback API returned error:", errorMessage);

              // Determine appropriate status code based on error type
              let statusCode = 500; // default server error
              if (errorMessage.includes("Too many requests") || fallbackJson.error === "err.supplier_error") {
                statusCode = 429;
              }

              return new Response(JSON.stringify({
                error: errorMessage,
                type: fallbackJson.error || "upstream_error"
              }), {
                status: statusCode,
                headers: {
                  'Content-Type': 'application/json',
                  'Access-Control-Allow-Origin': '*'
                }
              });
            }

            const fullContent = getNestedProperty(fallbackJson, CONTENT_FIELD);
            const finishReason = getNestedProperty(fallbackJson, FINISH_REASON_FIELD);

            if (fullContent === undefined || fullContent === null) {
              logger.error("Could not extract content from fallback response");
              logger.info("Full fallback response JSON:", JSON.stringify(fallbackJson, null, 2));
              return new Response(JSON.stringify({ error: "Failed to extract content from fallback response" }), {
                status: 502,
                headers: {
                  'Content-Type': 'application/json',
                  'Access-Control-Allow-Origin': '*'
                }
              });
            }

            const finalContent = String(fullContent);
            const finalFinishReason = finishReason !== undefined && finishReason !== null ? String(finishReason) : "stop";

            // Convert to streaming format (output all at once as streaming)
            const stream = new ReadableStream({
              start(controller) {
                const encoder = new TextEncoder();

                // Send the entire content as one streaming chunk
                controller.enqueue(encoder.encode(createSSEChunk(finalContent, originalModel, finalFinishReason)));
                controller.enqueue(encoder.encode("data: [DONE]\n\n"));
                controller.close();

                logger.debug("Fallback streaming response completed");
              }
            });

            return new Response(stream, {
              headers: {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Access-Control-Allow-Origin': '*',
              }
            });
          } else {
            // No error detected, create a new ReadableStream that includes the already-read chunk
            const newStream = new ReadableStream({
              async start(controller) {
                try {
                  // First, enqueue the already-read chunk
                  controller.enqueue(allChunks[0]);

                  // Then read and enqueue the rest of the stream
                  let chunk;
                  while (true) {
                    const { value, done } = await reader.read();
                    if (done) break;
                    controller.enqueue(value);
                  }
                  controller.close();
                } catch (error) {
                  controller.error(error);
                } finally {
                  try {
                    reader.releaseLock();
                  } catch (e) {
                    // Ignore release error
                  }
                }
              }
            });

            logger.debug("Passing through upstream streaming response with error check");
            return new Response(newStream, {
              status: upstreamResponse.status,
              headers: {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Access-Control-Allow-Origin': '*',
              }
            });
          }
        } catch (error) {
          logger.error("Error checking streaming response:", error);
          // Continue with normal streaming pass-through as fallback
          try {
            reader.releaseLock();
          } catch (e) {
            // Ignore release error
          }
        }
      }

      // Normal streaming pass-through (if no reader or error in checking)
      logger.debug("Passing through upstream streaming response");
      return new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          'Access-Control-Allow-Origin': '*',
        }
      });
    } else {
      // Handle non-streaming upstream response
      const upstreamJson = await upstreamResponse.json();
      logger.debug("Received upstream JSON response");

      // Check for upstream API errors first
      if (upstreamJson.status === "FAILED" || upstreamJson.error) {
        const errorMessage = upstreamJson.supplierError || upstreamJson.error || "Unknown upstream error";
        logger.warn("Upstream API returned error:", errorMessage);

        // Determine appropriate status code based on error type
        let statusCode = 500; // default server error
        if (errorMessage.includes("Too many requests") || upstreamJson.error === "err.supplier_error") {
          statusCode = 429;
        }

        return new Response(JSON.stringify({
          error: errorMessage,
          type: upstreamJson.error || "upstream_error"
        }), {
          status: statusCode,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      // Extract content and finish reason
      const fullContent = getNestedProperty(upstreamJson, CONTENT_FIELD);
      const finishReason = getNestedProperty(upstreamJson, FINISH_REASON_FIELD);

      if (fullContent === undefined || fullContent === null) {
        logger.error(`Could not extract content from upstream response using path: ${CONTENT_FIELD}`);
        // logger.error("Upstream JSON structure might have changed or path is incorrect.");
        // logger.error("Full upstream response JSON:", JSON.stringify(upstreamJson, null, 2));
        return new Response(JSON.stringify({ error: "Failed to extract content from upstream response. Check server logs and hardcoded paths." }), {
          status: 502,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      const finalContent = String(fullContent);
      const finalFinishReason = finishReason !== undefined && finishReason !== null ? String(finishReason) : "stop";

      // Return appropriate response format based on client's request
      if (clientWantsStreaming) {
        // Convert non-streaming response to single-chunk streaming
        const stream = new ReadableStream({
          start(controller) {
            const encoder = new TextEncoder();

            // Send entire content as one chunk
            controller.enqueue(encoder.encode(createSSEChunk(finalContent, originalModel, finalFinishReason)));
            controller.enqueue(encoder.encode("data: [DONE]\n\n"));
            controller.close();

            logger.debug("Single-chunk streaming response sent");
          }
        });

        return new Response(stream, {
          headers: {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*',
          }
        });
      } else {
        // Return non-streaming response as requested by client
        const nonStreamingResponse = {
          id: generateChatcmplId(),
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: originalModel,
          choices: [
            {
              index: 0,
              message: {
                role: "assistant",
                content: finalContent,
              },
              logprobs: null,
              finish_reason: finalFinishReason,
            },
          ],
          usage: upstreamJson.usage || {
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
          },
        };

        logger.debug("Returning non-streaming response as requested by client");
        return new Response(JSON.stringify(nonStreamingResponse), {
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          }
        });
      }
    }

  } catch (error) {
    logger.error("Error fetching or parsing upstream response:", error);
    return new Response(JSON.stringify({ error: "Failed to fetch or parse upstream response", details: error.message }), {
      status: 502,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
}

// Initialize and start server
function main() {
  const port = parseInt(Deno.env.get("PORT") || "8000");

  logger.info(`Aixplain Proxy Server starting on port ${port}`);
  logger.info(`Loaded ${modelMappings.length} model mappings`);

  Deno.serve({ port }, handleRequest);
}

if (import.meta.main) {
  main();
}
