# 🐼 Panda System

A Discord server management system designed for Cloudflare Workers + D1.

## Current foundation

- Cloudflare Worker endpoint for Discord Interactions
- Ed25519 request signature verification
- Health endpoint at `/api/health`
- Initial dashboard shell
- D1 schema with per-guild settings, ticket types, tickets, level profiles and audit logs
- `/panda` and `/setup` interaction commands

## Cloudflare-only runtime limits

Workers are request-driven and do not keep a permanent Discord Gateway WebSocket process alive. This means the traditional Discord.js Gateway features that require continuously receiving events are not included in this Cloudflare-only foundation:
- XP for every ordinary message
- Immediate member-join welcome events
- Continuous voice-state or presence tracking

The design uses Discord Interactions and HTTP-triggered events where supported. These limits must remain clear; do not claim unsupported Gateway features are active.

## Setup

1. Create a Cloudflare D1 database named `panda-system-db`.
2. Put its database ID in `wrangler.jsonc`.
3. Add Worker secrets:
   - `DISCORD_PUBLIC_KEY`: Discord Application Public Key
4. Apply the schema:
   ```bash
   npm install
   npx wrangler d1 execute panda-system-db --remote --file=./schema.sql
   ```
5. Deploy:
   ```bash
   npx wrangler deploy
   ```
6. Register slash commands once from a trusted local terminal after setting `DISCORD_APPLICATION_ID` and `DISCORD_BOT_TOKEN` as environment variables (never commit them):\n   `npm run register:commands`\n7. In the Discord Developer Portal, set the Interactions Endpoint URL to:
   `https://YOUR-WORKER.YOUR-SUBDOMAIN.workers.dev/interactions`

## Important

- Never put bot tokens, client secrets, or private keys in source files.
- The dashboard currently is a starter UI, not an authenticated production dashboard.
- Discord OAuth2 login, guild permission checks, dashboard settings APIs, ticket creation/closing, and slash-command registration are planned next.
