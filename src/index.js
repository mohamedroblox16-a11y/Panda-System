const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers }
  });

function hexToBytes(hex) {
  if (!/^[0-9a-f]{128}$/i.test(hex || "")) return null;
  const out = new Uint8Array(64);
  for (let i = 0; i < 64; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function verifyDiscordRequest(request, publicKey) {
  const signature = request.headers.get("x-signature-ed25519");
  const timestamp = request.headers.get("x-signature-timestamp");
  if (!signature || !timestamp || !publicKey) return false;

  const sig = hexToBytes(signature);
  const key = hexToBytes(publicKey + publicKey); // public keys are 32 bytes; normalized below
  if (!sig || !/^[0-9a-f]{64}$/i.test(publicKey)) return false;

  try {
    const rawKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) rawKey[i] = parseInt(publicKey.slice(i * 2, i * 2 + 2), 16);
    const imported = await crypto.subtle.importKey("raw", rawKey, { name: "Ed25519" }, false, ["verify"]);
    const body = await request.clone().text();
    const message = new TextEncoder().encode(timestamp + body);
    return await crypto.subtle.verify({ name: "Ed25519" }, imported, sig, message);
  } catch {
    return false;
  }
}

async function ensureGuild(db, guildId) {
  await db.prepare(
    "INSERT OR IGNORE INTO guild_settings (guild_id) VALUES (?)"
  ).bind(guildId).run();
}

async function handleInteraction(interaction, env) {
  if (interaction.type === 1) return json({ type: 1 });

  if (interaction.type === 2) {
    const command = interaction.data?.name;
    if (command === "panda") {
      return json({
        type: 4,
        data: {
          embeds: [{
            title: "🐼 Panda System",
            description: "النظام الأساسي للبوت شغال. لوحة التحكم والأنظمة الإضافية قيد التجهيز.",
            color: 0x5865f2,
            footer: { text: "Panda System • Cloudflare" }
          }],
          flags: 64
        }
      });
    }

    if (command === "setup") {
      const guildId = interaction.guild_id;
      if (!guildId) {
        return json({ type: 4, data: { content: "الأمر ده لازم يتنفذ داخل سيرفر.", flags: 64 } });
      }
      await ensureGuild(env.DB, guildId);
      return json({
        type: 4,
        data: {
          content: "🐼 تم إنشاء إعدادات Panda System الأساسية لهذا السيرفر. أكمل ضبط الأنظمة من لوحة التحكم بعد ربطها.",
          flags: 64
        }
      });
    }
  }

  if (interaction.type === 3) {
    const customId = interaction.data?.custom_id || "";
    if (customId.startsWith("panda:")) {
      return json({
        type: 4,
        data: { content: "تم استلام التفاعل. إعداد هذا القسم من لوحة التحكم سيُضاف في المرحلة التالية.", flags: 64 }
      });
    }
  }

  return json({ type: 4, data: { content: "التفاعل ده لسه مش متاح.", flags: 64 } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health" && request.method === "GET") {
      return json({
        ok: true,
        service: "Panda System",
        runtime: "Cloudflare Workers",
        databaseConfigured: Boolean(env.DB)
      });
    }

    if (url.pathname === "/interactions" && request.method === "POST") {
      const valid = await verifyDiscordRequest(request, env.DISCORD_PUBLIC_KEY);
      if (!valid) return new Response("Invalid request signature", { status: 401 });
      let interaction;
      try {
        interaction = await request.json();
      } catch {
        return new Response("Invalid JSON", { status: 400 });
      }
      try {
        return await handleInteraction(interaction, env);
      } catch (error) {
        console.error("Interaction error:", error);
        return json({ type: 4, data: { content: "حصل خطأ مؤقت. جرّب تاني بعد شوية.", flags: 64 } });
      }
    }

    if (url.pathname.startsWith("/api/")) {
      return json({ error: "Not found" }, 404);
    }

    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response("Panda System", { headers: { "content-type": "text/plain; charset=utf-8" } });
  }
};
