# Panda System
Cloudflare Workers + D1 Discord dashboard.

Included:
- Discord OAuth2 login with identify and guilds scopes.
- One-time OAuth state validation.
- HttpOnly, Secure session cookie; D1 stores only a SHA-256 hash of the session token.
- Server listing filtered by owner, Manage Server, or Administrator permissions.
- Per-server settings read/update API and audit logging.
- Arabic RTL dashboard starter.

Setup:
1. Apply the complete schema.sql to the remote D1 database. Existing installations must apply the new oauth_states and dashboard_sessions tables too.
2. The OAuth callback is generated from the host serving the dashboard, so use the final deployed Worker URL consistently.
3. Add Worker secrets in Cloudflare: DISCORD_CLIENT_SECRET and DISCORD_PUBLIC_KEY. Never commit secrets.
4. Discord Developer Portal > OAuth2 > Redirects: add PUBLIC_BASE_URL followed by /auth/discord/callback exactly.
5. Deploy using npx wrangler deploy.
6. Visit the Worker URL and use Login with Discord.
7. Register slash commands from a trusted local terminal using DISCORD_APPLICATION_ID and DISCORD_BOT_TOKEN environment variables.

The OAuth flow requests identify and guilds. Bot installation uses a separate OAuth invite with bot and applications.commands.

Limits: Workers do not keep a permanent Discord Gateway connection. XP per ordinary message and immediate member-join events require a separate Gateway-capable runtime. Ticket channel creation and full live bot features are not complete in this foundation.

## Separate Discord Gateway bot process

Cloudflare Workers remains the dashboard/API host. Run the Gateway bot as a separate persistent Node.js service from this repository:

- Runtime: Node.js 20 or newer.
- Build/install command: `npm install`
- Start command: `npm run start:bot`
- Required environment variable: `DISCORD_BOT_TOKEN` (set it as a private secret in the host dashboard; never commit it).
- The process uses discord.js with the Guilds intent and sets the bot presence to Online.
- Configure the host to restart the process automatically after a crash.

Important: a free Render Web Service sleeps after 15 minutes without inbound traffic, and Render does not offer free Background Workers. It is not suitable for reliable 24/7 Gateway uptime on the free plan. A continuously running process requires a host plan that supports an always-on worker. The Cloudflare Worker secret does not automatically transfer to the separate host; add the same bot token there privately.

This first runtime commit only establishes the persistent Gateway connection and Online presence. It does not yet implement the welcome, ticket, XP, applications, or moderation event handlers.
