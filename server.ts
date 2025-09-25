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
 * - Model mapping: Maps user-friendly model names to actual IDs using models.json
 * - /v1/models endpoint: Returns available models in OpenAI format
 * - Configurable logging system (default: error only)
 * - CORS support
 */

import { serve } from "https://deno.land/std@0.208.0/http/server.ts";

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
const logger = new Logger(Deno.env.get("LOG_LEVEL") || "error");

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

// Global state
let modelMappings: ModelMapping[] = [];

// Load model mappings from models.json
async function loadModelMappings(): Promise<void> {
  try {
    const modelsFile = await Deno.readTextFile("./models.json");
    modelMappings = JSON.parse(modelsFile);
    logger.info(`Loaded ${modelMappings.length} model mappings`);
  } catch (error) {
    logger.error("Failed to load models.json:", error);
    logger.warn("Continuing without model mappings");
    modelMappings = [];
  }
}

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

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Map model name to actual ID
function mapModelName(modelName: string): string {
  const mapping = modelMappings.find(m => m.model === modelName);
  return mapping ? mapping.id : modelName;
}

// Get user-friendly model name from ID
function getModelDisplayName(modelId: string): string {
  const mapping = modelMappings.find(m => m.id === modelId);
  return mapping ? mapping.model : modelId;
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
  const CHUNK_SIZE = 5;
  const DELAY_MS = 50;

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
  const upstreamPayload = { ...clientRequest };
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

        try {
          // Read the first chunk to check for stream error
          const { value, done } = await reader.read();
          if (value) {
            buffer = decoder.decode(value, { stream: true });
            logger.debug("First streaming chunk:", buffer.substring(0, 200));

            // Check if it's a stream error
            if (buffer.includes('"error":"Stream Error"')) {
              hasStreamError = true;
              logger.debug("Detected Stream Error in upstream response, falling back to non-streaming");
            }
          }

          // Release the reader
          reader.releaseLock();

          if (hasStreamError) {
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
            const fullContent = getNestedProperty(fallbackJson, CONTENT_FIELD);
            const finishReason = getNestedProperty(fallbackJson, FINISH_REASON_FIELD);

            if (fullContent === undefined || fullContent === null) {
              logger.error("Could not extract content from fallback response");
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
          }
        } catch (error) {
          logger.error("Error checking streaming response:", error);
          // Continue with normal streaming pass-through as fallback
        }
      }

      // Normal streaming pass-through (if no Stream Error detected)
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

      // Extract content and finish reason
      const fullContent = getNestedProperty(upstreamJson, CONTENT_FIELD);
      const finishReason = getNestedProperty(upstreamJson, FINISH_REASON_FIELD);

      if (fullContent === undefined || fullContent === null) {
        logger.error(`Could not extract content from upstream response using path: ${CONTENT_FIELD}`);
        logger.error("Upstream JSON structure might have changed or path is incorrect.");
        logger.error("Received JSON sample:", JSON.stringify(upstreamJson).substring(0, 1000));
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
        // Simulate streaming for client
        const stream = new ReadableStream({
          async start(controller) {
            const encoder = new TextEncoder();
            let isClosed = false;

            // Check if controller is still usable
            const isControllerUsable = () => {
              try {
                // Try to access the controller's desiredSize property
                // If it throws, the controller is no longer usable
                return controller.desiredSize !== null && !isClosed;
              } catch {
                isClosed = true;
                return false;
              }
            };

            const safeEnqueue = (data: Uint8Array) => {
              if (isControllerUsable()) {
                try {
                  controller.enqueue(data);
                  return true;
                } catch (error) {
                  isClosed = true;
                  logger.debug("Stream controller became unusable during enqueue, client likely disconnected");
                  return false;
                }
              }
              return false;
            };

            const safeClose = () => {
              if (isControllerUsable()) {
                try {
                  isClosed = true;
                  controller.close();
                } catch (error) {
                  logger.debug("Stream controller error during close, likely already closed");
                }
              }
            };

            try {
              for (let i = 0; i < finalContent.length; i += CHUNK_SIZE) {
                if (!isControllerUsable()) {
                  logger.debug("Stream controller no longer usable, stopping simulation");
                  break;
                }

                const chunk = finalContent.slice(i, i + CHUNK_SIZE);
                if (!safeEnqueue(encoder.encode(createSSEChunk(chunk, originalModel, null)))) {
                  break;
                }

                if (DELAY_MS > 0 && isControllerUsable()) {
                  await sleep(DELAY_MS);
                }
              }

              if (isControllerUsable()) {
                safeEnqueue(encoder.encode(createSSEChunk(null, originalModel, finalFinishReason)));
                safeEnqueue(encoder.encode("data: [DONE]\n\n"));
                safeClose();
                logger.debug("Simulated stream finished successfully");
              }
            } catch (error) {
              logger.debug("Stream simulation interrupted:", error.message);
              // Don't try to call controller.error() as it might also fail
            }
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
async function main() {
  await loadModelMappings();

  const port = parseInt(Deno.env.get("PORT") || "8000");

  logger.info(`Aixplain Proxy Server starting on port ${port}`);
  logger.info(`Loaded ${modelMappings.length} model mappings`);

  await serve(handleRequest, { port });
}

if (import.meta.main) {
  main();
}