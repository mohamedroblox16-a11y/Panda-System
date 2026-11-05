const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store",...headers}});
const COOKIE="panda_session",TTL=604800,MANAGE=32n,ADMIN=8n;
function randomToken(){return Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,"0")).join("");}
async function hash(v){const d=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(v));return Array.from(new Uint8Array(d),b=>b.toString(16).padStart(2,"0")).join("");}
function readCookie(req,name){const x=(req.headers.get("Cookie")||"").split(";").map(v=>v.trim()).find(v=>v.startsWith(name+"="));return x?decodeURIComponent(x.slice(name.length+1)):null;}
function getCookie(req){return readCookie(req,COOKIE);}
function setCookie(v,age=TTL){return COOKIE+"="+encodeURIComponent(v)+"; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age="+age;}
function redirect(url,headers={}){return new Response(null,{status:302,headers:{Location:url,...headers}});}
function callbackUri(req,env){return (env.PUBLIC_BASE_URL||new URL(req.url).origin).replace(/\/$/,"")+"/auth/discord/callback";}
function canManage(g){try{const p=BigInt(g.permissions||"0");return Boolean(g.owner)||(p&(MANAGE|ADMIN))!==0n;}catch{return Boolean(g.owner);}}
async function session(req,env){const t=getCookie(req);if(!t)return null;const row=await env.DB.prepare("SELECT user_id,username,global_name,avatar,guilds_json FROM dashboard_sessions WHERE token_hash=? AND expires_at>?").bind(await hash(t),Math.floor(Date.now()/1000)).first();if(!row)return null;let guilds=[];try{guilds=JSON.parse(row.guilds_json||"[]");}catch{}return {id:row.user_id,username:row.username,global_name:row.global_name,avatar:row.avatar,guilds};}
function hexBytes(h){if(!/^[0-9a-f]{128}$/i.test(h||""))return null;return Uint8Array.from(h.match(/.{2}/g),x=>parseInt(x,16));}
async function verify(req,key){const sig=req.headers.get("x-signature-ed25519"),ts=req.headers.get("x-signature-timestamp"),bytes=hexBytes(sig);if(!bytes||!/^[0-9a-f]{64}$/i.test(key||"")||!ts)return false;try{const pub=Uint8Array.from(key.match(/.{2}/g),x=>parseInt(x,16));const k=await crypto.subtle.importKey("raw",pub,{name:"Ed25519"},false,["verify"]);return crypto.subtle.verify({name:"Ed25519"},k,bytes,new TextEncoder().encode(ts+await req.clone().text()));}catch{return false;}}
async function oauthStart(req,env){if(!env.DISCORD_CLIENT_ID||!env.DISCORD_CLIENT_SECRET||!env.DB)return new Response("OAuth config missing. Set DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET secrets.",{status:503});const state=randomToken(),h=await hash(state),now=Math.floor(Date.now()/1000);await env.DB.prepare("DELETE FROM oauth_states WHERE expires_at<?").bind(now).run();await env.DB.prepare("INSERT INTO oauth_states(state_hash,expires_at) VALUES(?,?)").bind(h,now+600).run();const q=new URLSearchParams({client_id:env.DISCORD_CLIENT_ID,response_type:"code",redirect_uri:callbackUri(req,env),scope:"identify guilds",state});return redirect("https://discord.com/oauth2/authorize?"+q.toString(),{"Set-Cookie":"panda_oauth_state="+encodeURIComponent(state)+"; Path=/auth/discord/callback; HttpOnly; Secure; SameSite=Lax; Max-Age=600"});}
async function oauthCallback(req,env){const u=new URL(req.url),code=u.searchParams.get("code"),state=u.searchParams.get("state"),now=Math.floor(Date.now()/1000);if(u.searchParams.has("error"))return redirect("/?login=cancelled");if(!code||!state||readCookie(req,"panda_oauth_state")!==state)return new Response("OAuth state does not match this browser. Start login again.",{status:400});const sh=await hash(state),valid=await env.DB.prepare("SELECT state_hash FROM oauth_states WHERE state_hash=? AND expires_at>?").bind(sh,now).first();if(!valid)return new Response("OAuth state invalid or expired. Please login again.",{status:400});await env.DB.prepare("DELETE FROM oauth_states WHERE state_hash=?").bind(sh).run();const tr=await fetch("https://discord.com/api/v10/oauth2/token",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body:new URLSearchParams({client_id:env.DISCORD_CLIENT_ID,client_secret:env.DISCORD_CLIENT_SECRET,grant_type:"authorization_code",code,redirect_uri:callbackUri(req,env)})});const td=await tr.json();if(!tr.ok||!td.access_token){console.error("OAuth token exchange failed",td.error||tr.status);return new Response("Discord OAuth failed. Verify Client Secret and Redirect URI.",{status:502});}const h={"Authorization":"Bearer "+td.access_token};const pair=await Promise.all([fetch("https://discord.com/api/v10/users/@me",{headers:h}),fetch("https://discord.com/api/v10/users/@me/guilds",{headers:h})]);if(!pair[0].ok||!pair[1].ok)return new Response("Could not read Discord user or server list.",{status:502});const user=await pair[0].json(),raw=await pair[1].json(),guilds=raw.map(g=>({id:g.id,name:g.name,icon:g.icon,owner:Boolean(g.owner),canManage:canManage(g)}));const token=randomToken(),expires=now+TTL;await env.DB.prepare("INSERT INTO dashboard_sessions(token_hash,user_id,username,global_name,avatar,guilds_json,expires_at) VALUES(?,?,?,?,?,?,?)").bind(await hash(token),user.id,user.username,user.global_name||null,user.avatar||null,JSON.stringify(guilds),expires).run();return redirect("/",{"Set-Cookie":setCookie(token)});}
async function api(req,env,u){if(u.pathname==="/api/me"&&req.method==="GET"){const s=await session(req,env);return s?json({authenticated:true,user:{id:s.id,username:s.username,global_name:s.global_name,avatar:s.avatar}}):json({authenticated:false},401);}if(u.pathname==="/api/guilds"&&req.method==="GET"){const s=await session(req,env);return s?json({guilds:s.guilds.filter(g=>g.canManage)}):json({error:"unauthorized"},401);}const cm=u.pathname.match(/^\/api\/guilds\/([0-9]+)\/channels$/);if(cm&&req.method==="GET"){const s=await session(req,env);if(!s)return json({error:"unauthorized"},401);const g=s.guilds.find(x=>x.id===cm[1]&&x.canManage);if(!g)return json({error:"forbidden"},403);if(!env.DISCORD_BOT_TOKEN)return json({error:"أضف DISCORD_BOT_TOKEN كـ Secret في Cloudflare لتحميل القنوات."},503);const cr=await fetch("https://discord.com/api/v10/guilds/"+g.id+"/channels",{headers:{Authorization:"Bot "+env.DISCORD_BOT_TOKEN}});if(!cr.ok)return json({error:cr.status===403?"البوت مش موجود في السيرفر أو لا يملك صلاحية عرض القنوات.":"تعذر جلب قنوات Discord."},cr.status===403?403:502);const channels=await cr.json();return json({channels:channels.filter(x=>[0,4,5].includes(x.type)).map(x=>({id:x.id,name:x.name,type:x.type}))});}const tm=u.pathname.match(/^\/api\/guilds\/([0-9]+)\/ticket-types(?:\/([0-9]+))?$/);
if(tm&&["GET","POST","PATCH","DELETE"].includes(req.method)){
 const s=await session(req,env);if(!s)return json({error:"unauthorized"},401);
 const g=s.guilds.find(x=>x.id===tm[1]&&x.canManage);if(!g)return json({error:"forbidden"},403);
 if(req.method==="GET"){const rows=await env.DB.prepare("SELECT id,label,description,emoji,category_id,enabled,sort_order FROM ticket_types WHERE guild_id=? ORDER BY sort_order,id").bind(g.id).all();return json({ticketTypes:rows.results||[]});}
 if(req.method==="DELETE"){if(!tm[2])return json({error:"missing_id"},400);await env.DB.prepare("DELETE FROM ticket_types WHERE guild_id=? AND id=?").bind(g.id,Number(tm[2])).run();return json({ok:true});}
 let b;try{b=await req.json()}catch{return json({error:"invalid_json"},400)}
 const label=String(b.label||"").trim(),description=String(b.description||"").trim(),emoji=String(b.emoji||"🎫").trim(),category_id=String(b.category_id||"").trim(),enabled=b.enabled===false?0:1;
 if(!label||label.length>60||description.length>240||emoji.length>16)return json({error:"راجع الاسم والوصف والرمز (الاسم مطلوب)."},400);
 if(req.method==="POST"){const r=await env.DB.prepare("INSERT INTO ticket_types(guild_id,label,description,emoji,category_id,enabled,sort_order) VALUES(?,?,?,?,?,?,COALESCE((SELECT MAX(sort_order)+1 FROM ticket_types WHERE guild_id=?),0))").bind(g.id,label,description,emoji,category_id||null,enabled,g.id).run();return json({ok:true,id:r.meta?.last_row_id});}
 if(!tm[2])return json({error:"missing_id"},400);
 await env.DB.prepare("UPDATE ticket_types SET label=?,description=?,emoji=?,category_id=?,enabled=? WHERE guild_id=? AND id=?").bind(label,description,emoji,category_id||null,enabled,g.id,Number(tm[2])).run();return json({ok:true});
}

const publishMatch=u.pathname.match(/^\/api\/guilds\/([0-9]+)\/ticket-panel\/publish$/);
if(publishMatch&&req.method==="POST"){
 const s=await session(req,env);if(!s)return json({error:"سجّل الدخول أولاً."},401);
 const g=s.guilds.find(x=>x.id===publishMatch[1]&&x.canManage);if(!g)return json({error:"ليس لديك صلاحية إدارة السيرفر."},403);
 if(!env.DISCORD_BOT_TOKEN)return json({error:"Bot Token غير موجود في Cloudflare."},503);
 let b;try{b=await req.json()}catch{return json({error:"بيانات غير صالحة."},400)}
 const channelId=String(b.channel_id||"").trim();if(!/^\d{17,20}$/.test(channelId))return json({error:"اختار قناة صحيحة."},400);
 const rows=await env.DB.prepare("SELECT id,label,emoji FROM ticket_types WHERE guild_id=? AND enabled=1 ORDER BY sort_order,id LIMIT 25").bind(g.id).all();
 if(!rows.results?.length)return json({error:"أضف نوع تذكرة واحدًا على الأقل قبل النشر."},400);
 await env.DB.prepare("CREATE TABLE IF NOT EXISTS ticket_panel_posts (guild_id TEXT PRIMARY KEY,channel_id TEXT NOT NULL,message_id TEXT NOT NULL,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
 let previous=await env.DB.prepare("SELECT channel_id,message_id FROM ticket_panel_posts WHERE guild_id=?").bind(g.id).first();
 // Adopt an older Panda ticket panel on first update so it is edited instead of duplicated.
 if(!previous){
   const botIdentity=await fetch("https://discord.com/api/v10/users/@me",{headers:{Authorization:"Bot "+env.DISCORD_BOT_TOKEN}});
   if(botIdentity.ok){
     const bot=await botIdentity.json();
     const recent=await fetch("https://discord.com/api/v10/channels/"+channelId+"/messages?limit=100",{headers:{Authorization:"Bot "+env.DISCORD_BOT_TOKEN}});
     if(recent.ok){
       const messages=await recent.json();
       const oldPanel=messages.find(m=>m.author?.id===bot.id&&(m.components||[]).some(row=>(row.components||[]).some(c=>String(c.custom_id||"").startsWith("panda:ticket:create:"))));
       if(oldPanel)previous={channel_id:channelId,message_id:oldPanel.id};
     }
   }
 }
 const types=rows.results,components=[];
 for(let i=0;i<types.length;i+=5)components.push({type:1,components:types.slice(i,i+5).map(t=>({type:2,style:1,label:String(t.label).slice(0,80),emoji:t.emoji?{name:t.emoji}:undefined,custom_id:"panda:ticket:create:"+t.id}))});
 const body={content:String(b.message||"اختار نوع التذكرة المناسب من الأزرار بالأسفل.").slice(0,1800),components,allowed_mentions:{parse:[]}};
 let response,data={},updated=false;
 if(previous&&previous.channel_id===channelId){
   response=await fetch("https://discord.com/api/v10/channels/"+channelId+"/messages/"+previous.message_id,{method:"PATCH",headers:{Authorization:"Bot "+env.DISCORD_BOT_TOKEN,"content-type":"application/json"},body:JSON.stringify(body)});
   if(response.status===404){response=null;}
   else if(response.ok){data=await response.json().catch(()=>({}));updated=true;}
   else {const error=await response.json().catch(()=>({}));console.error("[Tickets] panel update failed",response.status,error);return json({error:response.status===403?"البوت لا يملك صلاحية تعديل رسالة اللوحة.":"Discord رفض تحديث لوحة التذاكر (HTTP "+response.status+")."},502);}
 }
 if(!response){
   response=await fetch("https://discord.com/api/v10/channels/"+channelId+"/messages",{method:"POST",headers:{Authorization:"Bot "+env.DISCORD_BOT_TOKEN,"content-type":"application/json"},body:JSON.stringify(body)});
   data=await response.json().catch(()=>({}));
   if(!response.ok){console.error("[Tickets] panel publish failed",response.status,data);return json({error:response.status===403?"البوت لا يملك صلاحية إرسال الرسائل واستخدام الأزرار في القناة.":response.status===404?"القناة غير موجودة أو البوت ليس داخل السيرفر.":"Discord رفض نشر اللوحة (HTTP "+response.status+")."},502);}
 }
 if(previous&&previous.channel_id!==channelId){
   const oldDelete=await fetch("https://discord.com/api/v10/channels/"+previous.channel_id+"/messages/"+previous.message_id,{method:"DELETE",headers:{Authorization:"Bot "+env.DISCORD_BOT_TOKEN}});
   if(!oldDelete.ok&&oldDelete.status!==404)console.warn("[Tickets] old panel could not be removed",oldDelete.status);
 }
 const messageId=updated?previous.message_id:data.id;
 await env.DB.prepare("INSERT INTO ticket_panel_posts(guild_id,channel_id,message_id) VALUES(?,?,?) ON CONFLICT(guild_id) DO UPDATE SET channel_id=excluded.channel_id,message_id=excluded.message_id,updated_at=CURRENT_TIMESTAMP").bind(g.id,channelId,messageId).run();
 await env.DB.prepare("INSERT INTO ticket_panels(guild_id,channel_id,message,button_label,button_emoji) VALUES(?,?,?,?,?) ON CONFLICT(guild_id) DO UPDATE SET channel_id=excluded.channel_id,message=excluded.message,button_label=excluded.button_label,button_emoji=excluded.button_emoji,updated_at=CURRENT_TIMESTAMP").bind(g.id,channelId,body.content,String(b.button_label||"فتح تذكرة").slice(0,50),String(b.button_emoji||"🎫").slice(0,16)).run();
 await env.DB.prepare("INSERT OR IGNORE INTO guild_settings(guild_id,guild_name) VALUES(?,?)").bind(g.id,g.name).run();
 await env.DB.prepare("UPDATE guild_settings SET tickets_enabled=1 WHERE guild_id=?").bind(g.id).run();
 return json({ok:true,updated,message_id:messageId,channel_id:channelId,message:updated?"تم تحديث لوحة التذاكر الحالية.":"تم إنشاء لوحة التذاكر."});
}

const pm=u.pathname.match(/^\/api\/guilds\/([0-9]+)\/ticket-panel$/);
if(pm&&(req.method==="GET"||req.method==="PATCH")){
 const s=await session(req,env);if(!s)return json({error:"unauthorized"},401);
 const g=s.guilds.find(x=>x.id===pm[1]&&x.canManage);if(!g)return json({error:"forbidden"},403);
 if(req.method==="GET"){const panel=await env.DB.prepare("SELECT * FROM ticket_panels WHERE guild_id=?").bind(g.id).first();return json({panel:panel||{channel_id:"",message:"اختار نوع التذكرة المناسب من الأزرار بالأسفل.",button_label:"فتح تذكرة",button_emoji:"🎫"}});}
 let b;try{b=await req.json()}catch{return json({error:"invalid_json"},400)}
 const vals=[String(b.channel_id||"").trim()||null,String(b.message||"").trim().slice(0,1800),String(b.button_label||"فتح تذكرة").trim().slice(0,50),String(b.button_emoji||"🎫").trim().slice(0,16),g.id];
 await env.DB.prepare("INSERT INTO ticket_panels(guild_id,channel_id,message,button_label,button_emoji) VALUES(?,?,?,?,?) ON CONFLICT(guild_id) DO UPDATE SET channel_id=excluded.channel_id,message=excluded.message,button_label=excluded.button_label,button_emoji=excluded.button_emoji,updated_at=CURRENT_TIMESTAMP").bind(...vals).run();return json({ok:true});
}
const m=u.pathname.match(/^\/api\/guilds\/([0-9]+)\/settings$/);if(m&&(req.method==="GET"||req.method==="PATCH")){const s=await session(req,env);if(!s)return json({error:"unauthorized"},401);const g=s.guilds.find(x=>x.id===m[1]&&x.canManage);if(!g)return json({error:"forbidden"},403);await env.DB.prepare("INSERT OR IGNORE INTO guild_settings(guild_id,guild_name) VALUES(?,?)").bind(g.id,g.name).run();if(req.method==="GET")return json({settings:await env.DB.prepare("SELECT * FROM guild_settings WHERE guild_id=?").bind(g.id).first()});let b;try{b=await req.json();}catch{return json({error:"invalid_json"},400);}const allowed=["language","prefix","welcome_enabled","welcome_channel_id","welcome_message","welcome_image_url","tickets_enabled","ticket_category_id","ticket_log_channel_id","levels_enabled","xp_multiplier","level_up_channel_id","applications_enabled","logs_channel_id"],entries=Object.entries(b).filter(([k])=>allowed.includes(k));if(!entries.length)return json({error:"no_valid_fields"},400);const numeric=["welcome_enabled","tickets_enabled","levels_enabled","applications_enabled"];for(const [k,v] of entries){if(numeric.includes(k)&&![0,1,true,false].includes(v))return json({error:"invalid_value",field:k},400);if(k==="xp_multiplier"&&(!Number.isFinite(Number(v))||Number(v)<0.1||Number(v)>100))return json({error:"invalid_multiplier"},400);if(typeof v==="string"&&v.length>2000)return json({error:"too_long",field:k},400);}const sets=entries.map(([k])=>k+"=?").join(","),vals=entries.map(([k,v])=>numeric.includes(k)?(v===true?1:v===false?0:v):v);await env.DB.prepare("UPDATE guild_settings SET "+sets+",updated_at=CURRENT_TIMESTAMP WHERE guild_id=?").bind(...vals,g.id).run();await env.DB.prepare("INSERT INTO audit_logs(guild_id,actor_id,action,details) VALUES(?,?,?,?)").bind(g.id,s.id,"dashboard_settings_updated",JSON.stringify(entries.map(([k])=>k))).run();return json({settings:await env.DB.prepare("SELECT * FROM guild_settings WHERE guild_id=?").bind(g.id).first()});}return json({error:"not_found"},404);}
async function editInteractionReply(i, body) {
  if (!i.application_id || !i.token) {
    console.error("[Tickets] missing interaction webhook credentials");
    return;
  }
  const response = await fetch(
    "https://discord.com/api/v10/webhooks/" + i.application_id + "/" + i.token + "/messages/@original",
    {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...body, allowed_mentions: { parse: [] } })
    }
  );
  if (!response.ok) {
    console.error("[Tickets] could not update deferred interaction", response.status, (await response.text().catch(() => "")).slice(0, 500));
  }
}

async function createTicketForInteraction(i, env) {
  const guild = i.guild_id;
  const member = i.member || {};
  const user = member.user || i.user || {};
  let reply = "حصل خطأ أثناء إنشاء التذكرة. حاول مرة أخرى.";

  try {
    if (!guild || !user.id) {
      reply = "تعذر تحديد السيرفر أو العضو.";
      return reply;
    }

    const customId = String(i.data?.custom_id || "");
    const match = customId.match(/^panda:ticket:create:(\d+)$/);
    if (!match) {
      reply = "زر التذكرة غير صالح.";
      return reply;
    }

    if (!env.DISCORD_BOT_TOKEN) {
      reply = "إعدادات البوت ناقصة على Cloudflare.";
      return reply;
    }

    const type = await env.DB.prepare(
      "SELECT id,label,category_id FROM ticket_types WHERE id=? AND guild_id=? AND enabled=1"
    ).bind(Number(match[1]), guild).first();

    if (!type) {
      reply = "نوع التذكرة غير متاح. حدّث لوحة التذاكر من الداشبورد.";
      return reply;
    }

    const old = await env.DB.prepare(
      "SELECT channel_id FROM tickets WHERE guild_id=? AND user_id=? AND status='open' LIMIT 1"
    ).bind(guild, user.id).first();

    if (old?.channel_id) {
      reply = "عندك تذكرة مفتوحة بالفعل: <#" + old.channel_id + ">";
      return reply;
    }

    const settings = await env.DB.prepare(
      "SELECT ticket_category_id,tickets_enabled FROM guild_settings WHERE guild_id=?"
    ).bind(guild).first();

    if (settings?.tickets_enabled === 0) {
      reply = "نظام التذاكر متوقف من لوحة التحكم.";
      return reply;
    }

    const botRes = await fetch("https://discord.com/api/v10/users/@me", {
      headers: { Authorization: "Bot " + env.DISCORD_BOT_TOKEN }
    });

    if (!botRes.ok) {
      console.error("[Tickets] bot identity request failed", botRes.status, await botRes.text().catch(() => ""));
      reply = "البوت غير قادر على التحقق من حسابه. راجع Bot Token في Cloudflare.";
      return reply;
    }

    const bot = await botRes.json();
    const category = type.category_id || settings?.ticket_category_id;

    // Allocate a separate increasing ticket number for each ticket button/type.
    await env.DB.prepare(
      "CREATE TABLE IF NOT EXISTS ticket_type_counters (guild_id TEXT NOT NULL,type_id INTEGER NOT NULL,next_number INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(guild_id,type_id))"
    ).run();
    const counter = await env.DB.prepare(
      "INSERT INTO ticket_type_counters(guild_id,type_id,next_number) VALUES(?,?,1) " +
      "ON CONFLICT(guild_id,type_id) DO UPDATE SET next_number=next_number+1 RETURNING next_number"
    ).bind(guild, type.id).first();
    const ticketNumber = Number(counter?.next_number || 1);
    const buttonSlug = String(type.label || "ticket")
      .normalize("NFKC")
      .toLowerCase()
      .replace(/[^\p{L}\p{N}_-]+/gu, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 85) || "ticket";
    const channelBody = {
      name: buttonSlug + "_" + ticketNumber,
      type: 0,
      permission_overwrites: [
        { id: guild, type: 0, deny: "1024" },
        { id: user.id, type: 1, allow: "68608" },
        { id: bot.id, type: 1, allow: "68608" }
      ]
    };
    if (category) channelBody.parent_id = category;

    const channelResponse = await fetch("https://discord.com/api/v10/guilds/" + guild + "/channels", {
      method: "POST",
      headers: {
        Authorization: "Bot " + env.DISCORD_BOT_TOKEN,
        "content-type": "application/json"
      },
      body: JSON.stringify(channelBody)
    });
    const channel = await channelResponse.json().catch(() => ({}));

    if (!channelResponse.ok) {
      console.error("[Tickets] create channel failed", channelResponse.status, channel);
      if (channelResponse.status === 403) {
        reply = "مش قادر أعمل الروم. اديني صلاحية Manage Channels وتأكد إن رتبة البوت مسموح لها بإدارة القنوات.";
      } else if (channel.code === 50013) {
        reply = "البوت ناقصه صلاحيات إنشاء القنوات أو الوصول للفئة المختارة.";
      } else if (channel.code === 50035) {
        reply = "إعداد الفئة غير صحيح. اختار Category صحيحة أو امسح الفئة من إعدادات نوع التذكرة.";
      } else {
        reply = "Discord رفض إنشاء الروم (HTTP " + channelResponse.status + "). راجع صلاحيات البوت والفئة المختارة.";
      }
      return reply;
    }

    try {
      const inserted = await env.DB.prepare(
        "INSERT INTO tickets(guild_id,channel_id,user_id,ticket_type_id,status) VALUES(?,?,?,?,'open')"
      ).bind(guild, channel.id, user.id, type.id).run();
      const ticketId = inserted.meta?.last_row_id;
      if (ticketId) {
        const message = {
          content: "🎫 **" + type.label + "**\nأهلاً <@" + user.id + ">، اكتب تفاصيل طلبك هنا.",
          components: [{
            type: 1,
            components: [{
              type: 2,
              style: 4,
              label: "إغلاق التذكرة",
              emoji: { name: "🔒" },
              custom_id: "panda:ticket:close:" + ticketId
            }]
          }],
          allowed_mentions: { users: [user.id] }
        };
        const messageResponse = await fetch("https://discord.com/api/v10/channels/" + channel.id + "/messages", {
          method: "POST",
          headers: {
            Authorization: "Bot " + env.DISCORD_BOT_TOKEN,
            "content-type": "application/json"
          },
          body: JSON.stringify(message)
        });
        if (!messageResponse.ok) {
          console.error("[Tickets] welcome message failed", messageResponse.status, await messageResponse.text().catch(() => ""));
        }
      } else {
        console.error("[Tickets] ticket row inserted without last_row_id");
      }
    } catch (dbError) {
      console.error("[Tickets] database insert/message error", dbError?.message || dbError);
      reply = "الروم اتعمل، لكن حصل خطأ في تسجيل التذكرة بقاعدة البيانات. تواصل مع إدارة السيرفر.";
      return reply;
    }

    reply = "تم إنشاء تذكرتك بنجاح: <#" + channel.id + ">";
    return reply;
  } catch (error) {
    console.error("[Tickets] create flow failed", error?.stack || error);
    return reply;
  }
}

async function closeTicketForInteraction(i, env) {
  const guild = i.guild_id;
  const member = i.member || {};
  const user = member.user || i.user || {};
  if (!guild || !user.id) return "تعذر تحديد السيرفر أو العضو.";
  if (!env.DISCORD_BOT_TOKEN) return "إعدادات البوت ناقصة على Cloudflare.";

  const close = String(i.data?.custom_id || "").match(/^panda:ticket:close:(\d+)$/);
  if (!close) return "زر إغلاق التذكرة غير صالح.";

  const ticket = await env.DB.prepare(
    "SELECT id,user_id,channel_id,status FROM tickets WHERE id=? AND guild_id=?"
  ).bind(Number(close[1]), guild).first();

  if (!ticket || ticket.status !== "open") return "التذكرة مغلقة بالفعل أو غير موجودة.";

  const permissions = BigInt(member.permissions || "0");
  const staff = (permissions & 8n) !== 0n || (permissions & 32n) !== 0n;
  if (ticket.user_id !== user.id && !staff) return "صاحب التذكرة أو الإدارة فقط يمكنهم إغلاقها.";

  // Delete the ticket channel when the close button is pressed.
  const deleted = await fetch(
    "https://discord.com/api/v10/channels/" + ticket.channel_id,
    { method: "DELETE", headers: { Authorization: "Bot " + env.DISCORD_BOT_TOKEN } }
  );

  if (!deleted.ok) {
    const detail = await deleted.text().catch(() => "");
    console.error("[Tickets] could not delete ticket channel", deleted.status, detail.slice(0, 500));
    if (deleted.status === 403) return "مش قادر أحذف الروم: ادّي البوت صلاحية Manage Channels.";
    if (deleted.status !== 404) return "Discord رفض حذف الروم (HTTP " + deleted.status + "). راجع صلاحيات البوت.";
  }

  await env.DB.prepare(
    "UPDATE tickets SET status='closed',closed_at=CURRENT_TIMESTAMP WHERE id=?"
  ).bind(ticket.id).run();

  return "🗑️ تم حذف روم التذكرة بواسطة <@" + user.id + ">.";
}

async function handleInteraction(i, env, ctx) {
  if (i.type === 1) return json({ type: 1 });

  if (i.type === 2) {
    const name = i.data?.name;
    if (name === "panda") return json({ type: 4, data: { content: "🐼 Panda System متصل.", flags: 64 } });
    if (name === "setup") {
      if (!i.guild_id) return json({ type: 4, data: { content: "استخدم الأمر داخل سيرفر.", flags: 64 } });
      await env.DB.prepare("INSERT OR IGNORE INTO guild_settings(guild_id) VALUES(?)").bind(i.guild_id).run();
      return json({ type: 4, data: { content: "تم إنشاء إعدادات Panda System الأساسية لهذا السيرفر.", flags: 64 } });
    }
  }

  if (i.type === 3) {
    const customId = String(i.data?.custom_id || "");
    const guild = i.guild_id;
    const member = i.member || {};
    const user = member.user || i.user || {};

    if (!guild || !user.id) {
      return json({ type: 4, data: { content: "تعذر تحديد السيرفر أو العضو.", flags: 64 } });
    }

    if (/^panda:ticket:create:\d+$/.test(customId)) {
      if (!ctx?.waitUntil) {
        console.error("[Tickets] execution context waitUntil is unavailable");
        return json({ type: 4, data: { content: "تعذر تشغيل إنشاء التذكرة حاليًا. حاول مرة أخرى.", flags: 64 } });
      }

      // Acknowledge immediately so Discord's 3-second interaction deadline is met.
      ctx.waitUntil((async () => {
        const content = await createTicketForInteraction(i, env);
        await editInteractionReply(i, { content });
      })().catch(async error => {
        console.error("[Tickets] background task failed", error?.stack || error);
        await editInteractionReply(i, { content: "حصل خطأ غير متوقع أثناء إنشاء التذكرة. راجع سجلات Cloudflare." });
      }));

      return json({ type: 5, data: { flags: 64 } });
    }

    const close = customId.match(/^panda:ticket:close:\d+$/);
    if (close) {
      if (!ctx?.waitUntil) {
        return json({ type: 4, data: { content: "تعذر تشغيل إغلاق التذكرة حاليًا. حاول مرة أخرى.", flags: 64 } });
      }

      // Defer the component update immediately, then lock the channel in the background.
      ctx.waitUntil((async () => {
        const content = await closeTicketForInteraction(i, env);
        // Remove the close button only after Discord confirms the channel lock succeeded.
        await editInteractionReply(i, content.startsWith("🗑️")
          ? { content, components: [] }
          : { content });
      })().catch(async error => {
        console.error("[Tickets] close background task failed", error?.stack || error);
        // Keep the button available so the user can retry after the issue is fixed.
        await editInteractionReply(i, {
          content: "حصل خطأ أثناء إغلاق التذكرة. راجع سجلات Cloudflare."
        });
      }));

      return json({ type: 6 });
    }
  }

  return json({ type: 4, data: { content: "التفاعل ده لسه مش متاح.", flags: 64 } });
}

export class PandaGateway {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
    this.ws = null;
    this.heartbeatTimer = null;
    this.heartbeatTimeout = null;
    this.sequence = null;
    this.awaitingHeartbeatAck = false;
    this.retryCount = 0;
    this.cooldowns = new Map();
    this.intentionalClose = false;
  }

  async status() {
    return (await this.ctx.storage.get("gateway_status")) || {
      state: "offline",
      detail: "لم يبدأ الاتصال بعد",
      updated_at: new Date().toISOString()
    };
  }

  async setStatus(state, detail = "") {
    const value = { state, detail, updated_at: new Date().toISOString() };
    await this.ctx.storage.put("gateway_status", value);
    console.log("[PandaGateway] status", value);
    return value;
  }

  clearHeartbeat() {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    if (this.heartbeatTimeout) clearTimeout(this.heartbeatTimeout);
    this.heartbeatTimer = null;
    this.heartbeatTimeout = null;
    this.awaitingHeartbeatAck = false;
  }

  async fetch(req) {
    const path = new URL(req.url).pathname;
    if (path === "/status") return json(await this.status());
    if (path === "/start") {
      await this.connect();
      return json({ ok: true, status: await this.status() });
    }
    return json({ error: "not_found" }, 404);
  }

  async connect() {
    if (!this.env.DISCORD_BOT_TOKEN) {
      await this.setStatus("error", "Cloudflare Secret DISCORD_BOT_TOKEN غير موجود.");
      return;
    }

    if (this.ws && (this.ws.readyState === WebSocket.CONNECTING || this.ws.readyState === WebSocket.OPEN)) {
      await this.ctx.storage.setAlarm(Date.now() + 10 * 60 * 1000);
      return;
    }

    this.clearHeartbeat();
    await this.setStatus("connecting", "جاري فتح اتصال Discord Gateway...");

    try {
      const ws = new WebSocket("wss://gateway.discord.gg/?v=10&encoding=json");
      this.ws = ws;
      this.intentionalClose = false;

      ws.addEventListener("open", () => {
        if (this.ws !== ws) return;
        console.log("[PandaGateway] WebSocket opened; waiting for HELLO.");
        this.setStatus("connecting", "تم فتح النقل؛ في انتظار HELLO من Discord.");
      });

      ws.addEventListener("message", event => {
        this.onMessage(event.data, ws).catch(error => {
          console.error("[PandaGateway] message handler failed", error?.message || String(error));
          this.setStatus("error", "حدث خطأ أثناء معالجة رسالة Gateway.");
        });
      });

      ws.addEventListener("error", event => {
        console.error("[PandaGateway] WebSocket transport error", event?.message || "no message");
      });

      ws.addEventListener("close", event => {
        console.error("[PandaGateway] WebSocket closed", {
          code: event.code,
          reason: event.reason,
          wasClean: event.wasClean
        });
        this.onClose(event, ws).catch(error => console.error("[PandaGateway] close handler failed", error));
      });

      // Keep a recovery alarm. It must never forcibly replace a healthy socket.
      await this.ctx.storage.setAlarm(Date.now() + 10 * 60 * 1000);
    } catch (error) {
      console.error("[PandaGateway] connection creation failed", error?.message || String(error));
      this.ws = null;
      await this.setStatus("reconnecting", "تعذر فتح الاتصال؛ ستتم إعادة المحاولة.");
      await this.scheduleReconnect();
    }
  }

  send(payload) {
    if (this.ws?.readyState !== WebSocket.OPEN) return false;
    this.ws.send(JSON.stringify(payload));
    return true;
  }

  async onMessage(raw, ws) {
    if (ws !== this.ws) return;
    let packet;
    try {
      packet = JSON.parse(raw);
    } catch {
      console.error("[PandaGateway] ignored non-JSON Gateway frame");
      return;
    }

    if (packet.s !== null && packet.s !== undefined) this.sequence = packet.s;
    console.log("[PandaGateway] Gateway packet", {
      op: packet.op,
      event: packet.t || null,
      sequence: packet.s ?? null
    });

    // Discord HELLO: begin heartbeats, then IDENTIFY exactly once per fresh session.
    if (packet.op === 10) {
      const interval = Number(packet.d?.heartbeat_interval);
      if (!Number.isFinite(interval) || interval < 1000) {
        await this.setStatus("error", "Discord أرسل heartbeat_interval غير صالح.");
        ws.close(4000, "Invalid heartbeat interval");
        return;
      }

      this.clearHeartbeat();
      const jitter = Math.floor(Math.random() * interval);
      this.heartbeatTimeout = setTimeout(() => this.sendHeartbeat(ws), jitter);
      this.heartbeatTimer = setInterval(() => this.sendHeartbeat(ws), interval);

      const intents = 1 | 2 | 512 | 32768; // GUILDS, GUILD_MEMBERS, GUILD_MESSAGES, MESSAGE_CONTENT
      console.log("[PandaGateway] HELLO received; sending IDENTIFY", { interval, intents });
      this.send({
        op: 2,
        d: {
          token: this.env.DISCORD_BOT_TOKEN,
          intents,
          properties: {
            "$os": "cloudflare",
            "$browser": "panda-system",
            "$device": "panda-system"
          }
        }
      });
      return;
    }

    if (packet.op === 11) {
      this.awaitingHeartbeatAck = false;
      return;
    }

    if (packet.op === 1) {
      this.send({ op: 1, d: this.sequence });
      return;
    }

    if (packet.op === 7) {
      console.warn("[PandaGateway] Discord requested reconnect.");
      this.intentionalClose = true;
      await this.setStatus("reconnecting", "Discord طلب إعادة الاتصال.");
      try { ws.close(4000, "Discord requested reconnect"); } catch {}
      await this.scheduleReconnect(1500);
      return;
    }

    if (packet.op === 9) {
      console.warn("[PandaGateway] Discord invalidated the session; a fresh Identify will be used.");
      this.sequence = null;
      this.intentionalClose = true;
      try { ws.close(4000, "Invalid session"); } catch {}
      await this.scheduleReconnect(3000 + Math.floor(Math.random() * 2000));
      return;
    }

    if (packet.op !== 0) return;

    if (packet.t === "READY") {
      this.retryCount = 0;
      console.log("[PandaGateway] READY received; Discord Gateway is connected.");
      await this.setStatus("online", "اتصال Discord Gateway نشط.");
      return;
    }

    if (packet.t === "RESUMED") {
      this.retryCount = 0;
      console.log("[PandaGateway] RESUMED received.");
      await this.setStatus("online", "تم استئناف اتصال Discord Gateway.");
      return;
    }

    if (packet.t === "GUILD_MEMBER_ADD") await this.welcome(packet.d);
    if (packet.t === "MESSAGE_CREATE") await this.addXp(packet.d);
  }

  sendHeartbeat(ws) {
    if (this.ws !== ws || ws.readyState !== WebSocket.OPEN) return;
    if (this.awaitingHeartbeatAck) {
      console.error("[PandaGateway] heartbeat ACK timed out; reconnecting.");
      this.intentionalClose = false;
      try { ws.close(4000, "Heartbeat ACK timeout"); } catch {}
      return;
    }
    this.awaitingHeartbeatAck = true;
    ws.send(JSON.stringify({ op: 1, d: this.sequence }));
  }

  async onClose(event, ws) {
    if (this.ws !== ws) return;
    this.clearHeartbeat();
    this.ws = null;

    if (event.code === 4004 || event.code === 4013 || event.code === 4014) {
      const detail = event.code === 4004
        ? "Discord رفض Bot Token؛ راجع التوكن داخل Cloudflare Secrets."
        : event.code === 4014
          ? "Discord رفض Privileged Intents؛ فعّل Server Members وMessage Content من Developer Portal."
          : "Discord رفض Intents المرسلة؛ راجع إعدادات Gateway Intents.";
      await this.setStatus("error", detail);
      // These errors need a settings change, not a rapid reconnect loop.
      await this.ctx.storage.deleteAlarm();
      return;
    }

    const detail = this.intentionalClose
      ? "إعادة اتصال مطلوبة؛ جاري المحاولة."
      : "انقطع اتصال Gateway (code " + event.code + (event.reason ? ", reason: " + event.reason : "") + ").";
    await this.setStatus("reconnecting", detail);
    await this.scheduleReconnect();
  }

  async scheduleReconnect(delay) {
    this.retryCount = Math.min(this.retryCount + 1, 6);
    const wait = delay ?? Math.min(60000, 5000 * this.retryCount);
    await this.ctx.storage.setAlarm(Date.now() + wait);
  }

  async alarm() {
    // A scheduled alarm is a health check, not a command to kill a live socket.
    if (this.ws && (this.ws.readyState === WebSocket.CONNECTING || this.ws.readyState === WebSocket.OPEN)) {
      await this.ctx.storage.setAlarm(Date.now() + 10 * 60 * 1000);
      return;
    }
    await this.connect();
  }

  async discord(path, body) {
    if (!this.env.DISCORD_BOT_TOKEN) return;
    const response = await fetch("https://discord.com/api/v10" + path, {
      method: "POST",
      headers: {
        Authorization: "Bot " + this.env.DISCORD_BOT_TOKEN,
        "content-type": "application/json"
      },
      body: JSON.stringify(body)
    });
    if (!response.ok) {
      const detail = await response.text().catch(() => "");
      console.error("[PandaGateway] Discord REST error", response.status, detail.slice(0, 300));
    }
  }

  async welcome(member) {
    const guildId = member.guild_id || member.guild?.id;
    if (!guildId) return;
    const settings = await this.env.DB.prepare(
      "SELECT welcome_enabled,welcome_channel_id,welcome_message,welcome_image_url FROM guild_settings WHERE guild_id=?"
    ).bind(guildId).first();
    if (!settings?.welcome_enabled || !settings.welcome_channel_id) return;

    const user = member.user || member;
    const content = String(settings.welcome_message || "أهلاً {user} نورت السيرفر! 🐼")
      .replaceAll("{user}", "<@" + user.id + ">")
      .replaceAll("{username}", user.username || "عضو")
      .replaceAll("{server}", "السيرفر");

    const body = { content, allowed_mentions: { parse: ["users"] } };
    if (settings.welcome_image_url) body.embeds = [{ image: { url: settings.welcome_image_url } }];
    await this.discord("/channels/" + settings.welcome_channel_id + "/messages", body);
  }

  async addXp(message) {
    if (!message.guild_id || !message.author || message.author.bot || !message.content?.trim()) return;

    const key = message.guild_id + ":" + message.author.id;
    const now = Date.now();
    const last = this.cooldowns.get(key) || 0;
    if (now - last < 60000) return;
    this.cooldowns.set(key, now);

    const settings = await this.env.DB.prepare(
      "SELECT levels_enabled,xp_multiplier,level_up_channel_id FROM guild_settings WHERE guild_id=?"
    ).bind(message.guild_id).first();
    if (!settings?.levels_enabled) return;

    const multiplier = Number(settings.xp_multiplier) || 1;
    const amount = Math.max(1, Math.round((15 + Math.floor(Math.random() * 11)) * multiplier));

    await this.env.DB.prepare(
      "INSERT INTO level_profiles(guild_id,user_id,xp,level,messages_count) VALUES(?,?,?,0,1) " +
      "ON CONFLICT(guild_id,user_id) DO UPDATE SET xp=xp+excluded.xp,messages_count=messages_count+1,updated_at=CURRENT_TIMESTAMP"
    ).bind(message.guild_id, message.author.id, amount).run();

    const profile = await this.env.DB.prepare(
      "SELECT xp,level FROM level_profiles WHERE guild_id=? AND user_id=?"
    ).bind(message.guild_id, message.author.id).first();

    let level = 0;
    while (level < 1000 && profile.xp >= 5 * level * level + 50 * level + 100) level++;
    if (level > Number(profile.level || 0)) {
      await this.env.DB.prepare(
        "UPDATE level_profiles SET level=?,updated_at=CURRENT_TIMESTAMP WHERE guild_id=? AND user_id=?"
      ).bind(level, message.guild_id, message.author.id).run();

      if (settings.level_up_channel_id) {
        const notice = await fetch(
          "https://discord.com/api/v10/channels/" + settings.level_up_channel_id + "/messages",
          {
            method: "POST",
            headers: {
              Authorization: "Bot " + this.env.DISCORD_BOT_TOKEN,
              "content-type": "application/json"
            },
            body: JSON.stringify({
              content: "🎉 مبروك <@" + message.author.id + ">! وصلت للمستوى **" + level + "** 🏆",
              allowed_mentions: { users: [message.author.id] }
            })
          }
        );
        if (!notice.ok) console.error("[PandaGateway] level-up announcement failed", notice.status, (await notice.text().catch(() => "")).slice(0, 300));
      }
    }
  }
}

export default {async scheduled(controller,env,ctx){const id=env.PANDA_GATEWAY.idFromName("main");ctx.waitUntil(env.PANDA_GATEWAY.get(id).fetch("https://gateway.internal/start",{method:"POST"}));},async fetch(req,env,ctx){const u=new URL(req.url);if(u.pathname==="/auth/discord"&&req.method==="GET")return oauthStart(req,env);if(u.pathname==="/auth/discord/callback"&&req.method==="GET"){try{return await oauthCallback(req,env);}catch(e){console.error("OAuth callback error",e);return new Response("OAuth login failed. Check Worker logs and settings.",{status:500});}}if(u.pathname==="/auth/logout"&&req.method==="POST"){const t=getCookie(req);if(t)await env.DB.prepare("DELETE FROM dashboard_sessions WHERE token_hash=?").bind(await hash(t)).run();return redirect("/",{"Set-Cookie":COOKIE+"=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"});}if(u.pathname==="/api/bot/status"&&req.method==="GET"){const id=env.PANDA_GATEWAY.idFromName("main");return env.PANDA_GATEWAY.get(id).fetch("https://gateway.internal/start",{method:"POST"});}if(u.pathname.startsWith("/api/")){if(u.pathname==="/api/health")return json({ok:true,service:"Panda System",databaseConfigured:Boolean(env.DB),oauthConfigured:Boolean(env.DISCORD_CLIENT_ID&&env.DISCORD_CLIENT_SECRET)});return api(req,env,u);}if(u.pathname==="/interactions"&&req.method==="POST"){console.log("[Interactions] request received");if(!await verify(req,env.DISCORD_PUBLIC_KEY)){console.error("[Interactions] signature verification failed; check DISCORD_PUBLIC_KEY and the Discord endpoint URL.");return new Response("Invalid request signature",{status:401});}let i;try{i=await req.json();}catch{return new Response("Invalid JSON",{status:400});}console.log("[Interactions] verified", {type:i.type,custom_id:i.data?.custom_id||null,guild_id:i.guild_id||null});try{return await handleInteraction(i,env,ctx);}catch(e){console.error("[Interactions] handler failed",e?.stack||e);return json({type:4,data:{content:"حصل خطأ مؤقت. راجع سجلات Cloudflare.",flags:64}});}}if(env.ASSETS)return env.ASSETS.fetch(req);return new Response("Panda System");}};
