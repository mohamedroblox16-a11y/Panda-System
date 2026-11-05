const applicationId = process.env.DISCORD_APPLICATION_ID;
const botToken = process.env.DISCORD_BOT_TOKEN;

if (!applicationId || !botToken) {
  console.error("Set DISCORD_APPLICATION_ID and DISCORD_BOT_TOKEN in your local environment.");
  process.exit(1);
}

const commands = [
  { name: "panda", description: "عرض حالة Panda System" },
  { name: "setup", description: "إنشاء إعدادات Panda System لهذا السيرفر", default_member_permissions: "32" }
];

const response = await fetch(`https://discord.com/api/v10/applications/${applicationId}/commands`, {
  method: "PUT",
  headers: {
    Authorization: `Bot ${botToken}`,
    "Content-Type": "application/json"
  },
  body: JSON.stringify(commands)
});

const body = await response.json().catch(() => ({}));
if (!response.ok) {
  console.error("Discord command registration failed:", response.status, body);
  process.exit(1);
}
console.log("Registered commands:", body.map(command => "/" + command.name).join(", "));
