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
const pm=u.pathname.match(/^\/api\/guilds\/([0-9]+)\/ticket-panel$/);
if(pm&&(req.method==="GET"||req.method==="PATCH")){
 const s=await session(req,env);if(!s)return json({error:"unauthorized"},401);
 const g=s.guilds.find(x=>x.id===pm[1]&&x.canManage);if(!g)return json({error:"forbidden"},403);
 if(req.method==="GET"){const panel=await env.DB.prepare("SELECT * FROM ticket_panels WHERE guild_id=?").bind(g.id).first();return json({panel:panel||{channel_id:"",message:"اختار نوع التذكرة المناسب من الأزرار بالأسفل.",button_label:"فتح تذكرة",button_emoji:"🎫"}});}
 let b;try{b=await req.json()}catch{return json({error:"invalid_json"},400)}
 const vals=[String(b.channel_id||"").trim()||null,String(b.message||"").trim().slice(0,1800),String(b.button_label||"فتح تذكرة").trim().slice(0,50),String(b.button_emoji||"🎫").trim().slice(0,16),g.id];
 await env.DB.prepare("INSERT INTO ticket_panels(guild_id,channel_id,message,button_label,button_emoji) VALUES(?,?,?,?,?) ON CONFLICT(guild_id) DO UPDATE SET channel_id=excluded.channel_id,message=excluded.message,button_label=excluded.button_label,button_emoji=excluded.button_emoji,updated_at=CURRENT_TIMESTAMP").bind(...vals).run();return json({ok:true});
}
const m=u.pathname.match(/^\/api\/guilds\/([0-9]+)\/settings$/);if(m&&(req.method==="GET"||req.method==="PATCH")){const s=await session(req,env);if(!s)return json({error:"unauthorized"},401);const g=s.guilds.find(x=>x.id===m[1]&&x.canManage);if(!g)return json({error:"forbidden"},403);await env.DB.prepare("INSERT OR IGNORE INTO guild_settings(guild_id,guild_name) VALUES(?,?)").bind(g.id,g.name).run();if(req.method==="GET")return json({settings:await env.DB.prepare("SELECT * FROM guild_settings WHERE guild_id=?").bind(g.id).first()});let b;try{b=await req.json();}catch{return json({error:"invalid_json"},400);}const allowed=["language","prefix","welcome_enabled","welcome_channel_id","welcome_message","welcome_image_url","tickets_enabled","ticket_category_id","ticket_log_channel_id","levels_enabled","xp_multiplier","applications_enabled","logs_channel_id"],entries=Object.entries(b).filter(([k])=>allowed.includes(k));if(!entries.length)return json({error:"no_valid_fields"},400);const numeric=["welcome_enabled","tickets_enabled","levels_enabled","applications_enabled"];for(const [k,v] of entries){if(numeric.includes(k)&&![0,1,true,false].includes(v))return json({error:"invalid_value",field:k},400);if(k==="xp_multiplier"&&(!Number.isFinite(Number(v))||Number(v)<0.1||Number(v)>100))return json({error:"invalid_multiplier"},400);if(typeof v==="string"&&v.length>2000)return json({error:"too_long",field:k},400);}const sets=entries.map(([k])=>k+"=?").join(","),vals=entries.map(([k,v])=>numeric.includes(k)?(v===true?1:v===false?0:v):v);await env.DB.prepare("UPDATE guild_settings SET "+sets+",updated_at=CURRENT_TIMESTAMP WHERE guild_id=?").bind(...vals,g.id).run();await env.DB.prepare("INSERT INTO audit_logs(guild_id,actor_id,action,details) VALUES(?,?,?,?)").bind(g.id,s.id,"dashboard_settings_updated",JSON.stringify(entries.map(([k])=>k))).run();return json({settings:await env.DB.prepare("SELECT * FROM guild_settings WHERE guild_id=?").bind(g.id).first()});}return json({error:"not_found"},404);}
async function handleInteraction(i,env){if(i.type===1)return json({type:1});if(i.type===2){const n=i.data?.name;if(n==="panda")return json({type:4,data:{content:"🐼 Panda System متصل.",flags:64}});if(n==="setup"){if(!i.guild_id)return json({type:4,data:{content:"استخدم الأمر داخل سيرفر.",flags:64}});await env.DB.prepare("INSERT OR IGNORE INTO guild_settings(guild_id) VALUES(?)").bind(i.guild_id).run();return json({type:4,data:{content:"تم إنشاء إعدادات Panda System الأساسية لهذا السيرفر.",flags:64}});}}return json({type:4,data:{content:"التفاعل ده لسه مش متاح.",flags:64}});}

export class PandaGateway {
  constructor(ctx, env) {
    this.ctx=ctx; this.env=env; this.ws=null; this.heartbeat=null; this.seq=null;
    this.retry=0; this.lastAck=Date.now(); this.cooldowns=new Map();
  }
  async status(){return await this.ctx.storage.get("gateway_status")||{state:"offline",detail:"لم يبدأ الاتصال بعد",updated_at:new Date().toISOString()};}
  async setStatus(state,detail=""){await this.ctx.storage.put("gateway_status",{state,detail,updated_at:new Date().toISOString()});}
  async fetch(req){
    const path=new URL(req.url).pathname;
    if(path==="/status")return json(await this.status());
    if(path==="/start"){await this.connect(true);return json({ok:true,status:await this.status()});}
    return json({error:"not_found"},404);
  }
  async connect(force=false){
    if(!this.env.DISCORD_BOT_TOKEN){await this.setStatus("error","Secret DISCORD_BOT_TOKEN غير موجود في Worker.");return;}
    if(this.ws&&(this.ws.readyState===0||this.ws.readyState===1)&&!force)return;
    try{if(this.ws)this.ws.close(1000,"reconnecting");}catch{}
    if(this.heartbeat){clearInterval(this.heartbeat);this.heartbeat=null;}
    await this.setStatus("connecting","جاري الاتصال بـ Discord Gateway");
    try{
      const ws=new WebSocket("wss://gateway.discord.gg/?v=10&encoding=json");
      this.ws=ws;
      ws.addEventListener("message",e=>this.onMessage(e.data,ws).catch(err=>console.error("Gateway message error",err)));
      ws.addEventListener("close",e=>this.onClose(e,ws));
      ws.addEventListener("error",()=>this.setStatus("error","حدث خطأ في اتصال Gateway."));
      await this.ctx.storage.setAlarm(Date.now()+14*60*1000);
    }catch(e){await this.setStatus("error","تعذر فتح اتصال Gateway: "+String(e).slice(0,180));await this.ctx.storage.setAlarm(Date.now()+30000);}
  }
  send(data){if(this.ws&&this.ws.readyState===1)this.ws.send(JSON.stringify(data));}
  async onMessage(raw,ws){
    if(ws!==this.ws)return;
    let p;try{p=JSON.parse(raw);}catch{return;}
    if(p.s!==null&&p.s!==undefined)this.seq=p.s;
    if(p.op===10){
      const ms=p.d.heartbeat_interval;
      if(this.heartbeat)clearInterval(this.heartbeat);
      this.heartbeat=setInterval(()=>{this.send({op:1,d:this.seq});},ms);
      this.send({op:2,d:{token:this.env.DISCORD_BOT_TOKEN,intents:1|2|512|32768,properties:{"$os":"cloudflare","$browser":"panda-system","$device":"panda-system"}}});
      return;
    }
    if(p.op===1){this.send({op:1,d:this.seq});return;}
    if(p.op===7){await this.setStatus("reconnecting","Discord طلب إعادة الاتصال.");await this.connect(true);return;}
    if(p.op===9){await this.setStatus("reconnecting","جلسة Gateway غير صالحة؛ إعادة المحاولة.");this.seq=null;await this.ctx.storage.setAlarm(Date.now()+5000);return;}
    if(p.op===11){this.lastAck=Date.now();return;}
    if(p.op===0){
      if(p.t==="READY"){await this.setStatus("online","اتصال Discord Gateway نشط.");this.retry=0;}
      if(p.t==="RESUMED")await this.setStatus("online","تم استئناف اتصال Discord Gateway.");
      if(p.t==="GUILD_MEMBER_ADD")await this.welcome(p.d);
      if(p.t==="MESSAGE_CREATE")await this.addXp(p.d);
    }
  }
  async onClose(e,ws){
    if(ws!==this.ws)return;
    if(this.heartbeat){clearInterval(this.heartbeat);this.heartbeat=null;}
    const detail=e.code===4014?"Discord رفض Intents؛ فعّل Server Members Intent وMessage Content Intent من Developer Portal.":e.code===4004?"Bot Token غير صحيح.":("انقطع الاتصال (code "+e.code+"). إعادة المحاولة.");
    await this.setStatus("reconnecting",detail);
    this.retry=Math.min(this.retry+1,6);
    await this.ctx.storage.setAlarm(Date.now()+Math.min(60000,5000*this.retry));
  }
  async alarm(){await this.connect(true);}
  async discord(path,body){
    if(!this.env.DISCORD_BOT_TOKEN)return;
    const r=await fetch("https://discord.com/api/v10"+path,{method:"POST",headers:{Authorization:"Bot "+this.env.DISCORD_BOT_TOKEN,"content-type":"application/json"},body:JSON.stringify(body)});
    if(!r.ok)console.error("Discord REST error",r.status,await r.text().catch(()=>""));
  }
  async welcome(member){
    const gid=member.guild_id||member.guild?.id;if(!gid)return;
    const s=await this.env.DB.prepare("SELECT welcome_enabled,welcome_channel_id,welcome_message,welcome_image_url FROM guild_settings WHERE guild_id=?").bind(gid).first();
    if(!s||!s.welcome_enabled||!s.welcome_channel_id)return;
    const user=member.user||member;
    let content=String(s.welcome_message||"أهلاً {user} نورت السيرفر! 🐼").replaceAll("{user}","<@"+user.id+">").replaceAll("{username}",user.username||"عضو").replaceAll("{server}","السيرفر");
    const body={content,allowed_mentions:{parse:["users"]}};
    if(s.welcome_image_url)body.embeds=[{image:{url:s.welcome_image_url}}];
    await this.discord("/channels/"+s.welcome_channel_id+"/messages",body);
  }
  async addXp(msg){
    if(!msg.guild_id||!msg.author||msg.author.bot||!msg.content?.trim())return;
    const key=msg.guild_id+":"+msg.author.id,now=Date.now(),last=this.cooldowns.get(key)||0;
    if(now-last<60000)return;this.cooldowns.set(key,now);
    const s=await this.env.DB.prepare("SELECT levels_enabled,xp_multiplier FROM guild_settings WHERE guild_id=?").bind(msg.guild_id).first();
    if(!s||!s.levels_enabled)return;
    const amount=Math.max(1,Math.round((15+Math.floor(Math.random()*11))*(Number(s.xp_multiplier)||1)));
    await this.env.DB.prepare("INSERT INTO level_profiles(guild_id,user_id,xp,level,messages_count) VALUES(?,?,?,0,1) ON CONFLICT(guild_id,user_id) DO UPDATE SET xp=xp+excluded.xp,messages_count=messages_count+1,updated_at=CURRENT_TIMESTAMP").bind(msg.guild_id,msg.author.id,amount).run();
    const row=await this.env.DB.prepare("SELECT xp,level FROM level_profiles WHERE guild_id=? AND user_id=?").bind(msg.guild_id,msg.author.id).first();
    let level=0;while(level<1000&&row.xp>=5*level*level+50*level+100)level++;
    if(level!==row.level)await this.env.DB.prepare("UPDATE level_profiles SET level=?,updated_at=CURRENT_TIMESTAMP WHERE guild_id=? AND user_id=?").bind(level,msg.guild_id,msg.author.id).run();
  }
}

export default {async scheduled(controller,env,ctx){const id=env.PANDA_GATEWAY.idFromName("main");ctx.waitUntil(env.PANDA_GATEWAY.get(id).fetch("https://gateway.internal/start",{method:"POST"}));},async fetch(req,env){const u=new URL(req.url);if(u.pathname==="/auth/discord"&&req.method==="GET")return oauthStart(req,env);if(u.pathname==="/auth/discord/callback"&&req.method==="GET"){try{return await oauthCallback(req,env);}catch(e){console.error("OAuth callback error",e);return new Response("OAuth login failed. Check Worker logs and settings.",{status:500});}}if(u.pathname==="/auth/logout"&&req.method==="POST"){const t=getCookie(req);if(t)await env.DB.prepare("DELETE FROM dashboard_sessions WHERE token_hash=?").bind(await hash(t)).run();return redirect("/",{"Set-Cookie":COOKIE+"=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"});}if(u.pathname==="/api/bot/status"&&req.method==="GET"){const id=env.PANDA_GATEWAY.idFromName("main");return env.PANDA_GATEWAY.get(id).fetch("https://gateway.internal/start",{method:"POST"});}if(u.pathname.startsWith("/api/")){if(u.pathname==="/api/health")return json({ok:true,service:"Panda System",databaseConfigured:Boolean(env.DB),oauthConfigured:Boolean(env.DISCORD_CLIENT_ID&&env.DISCORD_CLIENT_SECRET)});return api(req,env,u);}if(u.pathname==="/interactions"&&req.method==="POST"){if(!await verify(req,env.DISCORD_PUBLIC_KEY))return new Response("Invalid request signature",{status:401});let i;try{i=await req.json();}catch{return new Response("Invalid JSON",{status:400});}try{return await handleInteraction(i,env);}catch(e){console.error(e);return json({type:4,data:{content:"حصل خطأ مؤقت.",flags:64}});}}if(env.ASSETS)return env.ASSETS.fetch(req);return new Response("Panda System");}};
