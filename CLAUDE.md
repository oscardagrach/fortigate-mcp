# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

MCP (Model Context Protocol) server for managing FortiGate firewalls via the FortiOS REST API. Provides 377 tools for system management, firewall policies, routing, VPN, security profiles, DNS, monitoring, and more. Runs as a stdio-based MCP server.

## Commands

```bash
npm run build          # Compile TypeScript (tsc) to dist/
npm run dev            # Run in development mode with tsx (auto-reloads)
npm start              # Run compiled output (dist/index.js)
```

No test framework is configured. No linter is configured.

## Required Environment Variables

- `FORTIGATE_HOST` — FortiGate hostname or IP
- `FORTIGATE_API_TOKEN` — REST API token
- `FORTIGATE_PORT` — HTTPS port (default: 443)
- `FORTIGATE_VERIFY_SSL` — Set to `false` for self-signed certs (default: true)

## Architecture

Two source files in `src/`:

- **`index.ts`** — MCP server entry point. Registers all 377 tools using `McpServer.tool()` from `@modelcontextprotocol/sdk`. Each tool defines its name, description, Zod input schema, and an async handler that calls the client and returns JSON. Uses `result()` / `errorResult()` helpers to format responses.

- **`fortigate-client.ts`** — `FortigateClient` class wrapping the FortiOS REST API (v2). All HTTP calls go through a central `request()` method handling auth (`Bearer` token), JSON serialization, and error handling. Uses Node's native `fetch`.

### Adding a New Tool

1. Add the API method to `FortigateClient` in `fortigate-client.ts`
2. Register the tool in `index.ts` with `server.tool(name, description, zodSchema, handler)`
3. Use the existing patterns: most tools accept an optional `vdom` parameter, use `encodeURIComponent` for path params, and follow the `try/catch` → `result()`/`errorResult()` pattern

### FortiOS API Patterns

- Config endpoints: `/api/v2/cmdb/{path}` — CRUD operations on firewall configuration
- Monitor endpoints: `/api/v2/monitor/{path}` — Read-only operational/status data
- VDOM support: passed as `?vdom=` query parameter
- The API uses `name` as the key for most objects (addresses, VIPs, interfaces) but `id` (integer) for policies and static routes
