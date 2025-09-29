# Aixplain Proxy Server

Deno server for Aixplain API with model mapping and smart streaming.

## Quick Start

```bash
# Run server
deno run --allow-net --allow-read --allow-env server.ts

# Run server with custom settings

# Linux/macOS:
PORT=3000 LOG_LEVEL=debug deno run --allow-net --allow-read --allow-env server.ts

# Windows Command Prompt:
set PORT=3000&& set LOG_LEVEL="debug"&& deno run --allow-net --allow-read --allow-env server.ts

# Windows PowerShell:
$env:PORT=3000; $env:LOG_LEVEL="debug"; deno run --allow-net --allow-read --allow-env server.ts
```

## API Usage

```bash
# Chat completion
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_AIXPLAIN_API_KEY" \
  -d '{"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]}'

# List models
curl http://localhost:8000/v1/models
```

## Environment Variables

- `PORT` - Server port (default: 8000)
- `LOG_LEVEL` - Logging level: error, warn, info, debug (default: error)
