import { Client, GatewayIntentBits, ActivityType } from "discord.js";

const token = process.env.DISCORD_BOT_TOKEN;
if (!token) {
  console.error("Missing DISCORD_BOT_TOKEN environment variable.");
  process.exit(1);
}

const client = new Client({
  intents: [GatewayIntentBits.Guilds],
});

client.once("ready", () => {
  console.log(`Panda System connected as ${client.user.tag}`);
  client.user.setPresence({
    status: "online",
    activities: [{ name: "Panda System 🐼", type: ActivityType.Watching }],
  });
  console.log(`Connected to ${client.guilds.cache.size} server(s).`);
});

client.on("guildCreate", guild => {
  console.log(`Added to server: ${guild.name} (${guild.id})`);
});

client.on("guildDelete", guild => {
  console.log(`Removed from server: ${guild.name} (${guild.id})`);
});

client.on("error", error => console.error("Discord client error:", error));
process.on("unhandledRejection", error => console.error("Unhandled rejection:", error));
process.on("uncaughtException", error => {
  console.error("Uncaught exception:", error);
  process.exit(1);
});

async function shutdown(signal) {
  console.log(`Received ${signal}; closing Discord connection.`);
  client.destroy();
  process.exit(0);
}
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

client.login(token).catch(error => {
  console.error("Discord login failed. Check the token and bot settings.", error);
  process.exit(1);
});
