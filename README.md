# Panda System

Discord dashboard and bot foundation using Cloudflare Workers, Durable Objects, and D1.

## Architecture

- **Cloudflare Worker:** Dashboard, Discord OAuth2, API routes, and Discord Interactions endpoint.
- **Cloudflare Durable Object (PandaGateway):** Discord Gateway WebSocket connection, heartbeat/ACK handling, reconnect scheduling, welcome events, and message XP events.
- **Cloudflare D1:** Per-server settings, ticket configuration, level profiles, sessions, and audit records.
- **Static dashboard:** Served from `public/`.

The Gateway implementation lives in `src/index.js`. It uses the existing `PANDA_GATEWAY` Durable Object binding and the existing `v1` SQLite class migration. Do not remove or rename that binding/class from an already deployed project; rebuilds should keep the same class identity so the deployed Durable Object namespace remains compatible.

## Cloudflare setup

1. Apply `schema.sql` to the remote D1 database. For an existing database, applying it is safe because the tables use `CREATE TABLE IF NOT EXISTS`.
2. Set these Worker secrets in Cloudflare:
   - `DISCORD_BOT_TOKEN`
   - `DISCORD_CLIENT_SECRET`
   - `DISCORD_PUBLIC_KEY`
3. Keep `DISCORD_CLIENT_ID` and `DISCORD_APPLICATION_ID` configured in `wrangler.jsonc`.
4. In Discord Developer Portal, set the OAuth2 redirect URL to the deployed Worker URL plus `/auth/discord/callback`.
5. Enable **Server Members Intent** and **Message Content Intent** under Bot > Privileged Gateway Intents. The bot must also be invited to the server with the permissions required for its features.
6. Deploy with `npm install` then `npx wrangler deploy`.
7. Open the dashboard and sign in with Discord.

## Gateway behavior

- The Worker status endpoint starts or checks the Durable Object connection without intentionally replacing a healthy socket.
- The Durable Object sends IDENTIFY after Discord HELLO, sends heartbeats, checks heartbeat ACKs, and schedules reconnects after disconnects.
- Invalid token and rejected-intent close codes are shown as actionable errors instead of rapid retry loops.
- Logs use the `[PandaGateway]` prefix. A successful connection is confirmed by a `READY` event and status `online`.

## Important Cloudflare runtime note

This is a Cloudflare-native Gateway implementation; it does not require a separate Node host. Durable Objects can maintain outbound WebSockets, but Cloudflare may evict an inactive Durable Object instance. The project uses alarms and a five-minute scheduled check to recover the connection, so this should be treated as reconnecting bot infrastructure rather than a guarantee of uninterrupted 24/7 Gateway uptime.

## Current feature status

- Discord OAuth2 dashboard and per-server settings are implemented.
- Welcome and message XP handlers are connected to Gateway events.
- Ticket type and ticket panel settings can be saved in the dashboard.
- Actual ticket panel publishing, ticket channel creation/closure, full moderation commands, and complete applications workflow still need implementation.
- Slash-command registration is handled by `scripts/register-commands.js`.
