import {initializeApp} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import * as A from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import * as F from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
import fbcfg from "./firebase-config.js";
export const app=initializeApp(fbcfg),auth=A.getAuth(app),db=F.getFirestore(app);export{A,F,fbcfg};
export const J=s=>{try{return JSON.parse(s||"{}")}catch{return{}}};
// ---- feedback helpers: toast messages, timeouts and a spinner for any async button ----
export const toast=(msg,kind="ok")=>{let box=document.getElementById("toasts");if(!box){box=document.createElement("div");box.id="toasts";box.setAttribute("role","status");box.setAttribute("aria-live","polite");document.body.append(box)}
 const t=document.createElement("div");t.className="toast "+kind;t.textContent=msg;box.append(t);setTimeout(()=>{t.classList.add("out");setTimeout(()=>t.remove(),300)},kind==="bad"?6000:3500)};
// Firestore queues writes forever while offline, so a save would spin silently. Fail after 15 s instead.
export const withTimeout=(p,ms=15000)=>Promise.race([p,new Promise((_,r)=>setTimeout(()=>r({code:"timeout",message:"No response from Firebase. Check the internet connection and try again."}),ms))]);
// busy(button,"Saving…",async()=>{...},"Saved"): shows a spinner while fn runs, then a green tick (okLabel) on success.
export async function busy(btn,label,fn,okLabel){if(!btn||btn.dataset.busy)return;const old=btn.innerHTML;btn.dataset.busy="1";btn.disabled=true;btn.classList.add("busy");btn.innerHTML=`<span class="spin"></span>${esc(label)}`;
 try{const r=await fn();if(okLabel){btn.classList.remove("busy");btn.classList.add("done");btn.innerHTML="✓ "+esc(okLabel);await new Promise(x=>setTimeout(x,1300))}return r}
 finally{delete btn.dataset.busy;btn.disabled=false;btn.classList.remove("busy","done");btn.innerHTML=old}}
export const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
export const online=s=>!!(s.seen&&!s.removed&&Date.now()/1000-s.seen<90);
// A child can belong to several parents (parentIds). Legacy single parentId is still understood.
export const parentsOf=d=>Array.isArray(d.parentIds)?d.parentIds:(d.parentId?[d.parentId]:[]);
const pad=n=>String(n).padStart(2,"0");
export const clock=sec=>{sec=Math.max(0,Math.floor(sec));const h=Math.floor(sec/3600),m=Math.floor(sec%3600/60),s=sec%60;return h?`${h}:${pad(m)}:${pad(s)}`:`${m}:${pad(s)}`};
const ago=t=>{const x=Math.floor(Date.now()/1000-t);return x<90?"just now":x<3600?Math.floor(x/60)+" min ago":x<86400?Math.floor(x/3600)+" h ago":Math.floor(x/86400)+" d ago"};
export const when=t=>{const d=new Date(t*1000),n=new Date(),day=Math.round((new Date(n.getFullYear(),n.getMonth(),n.getDate())-new Date(d.getFullYear(),d.getMonth(),d.getDate()))/864e5);
 return (day===0?"Today":day===1?"Yesterday":d.toLocaleDateString([],{month:"short",day:"numeric"}))+" "+d.toLocaleTimeString([],{hour:"numeric",minute:"2-digit"}).toLowerCase()};
// Same site/app seen many times (www.x.com vs x.com, Chrome.exe vs chrome.exe) is treated as ONE entry.
export const nsite=d=>String(d??"").trim().toLowerCase().replace(/^www\./,"");
const mergeApps=o=>{const r={};for(const[k,v]of Object.entries(o||{})){const n=String(k).trim().toLowerCase();if(n)r[n]=(r[n]||0)+(+v||0)}return r};
const evInfo=e=>{const am=/^(Application started|Blocked application):\s*([^\s·]+)/i.exec(e.message||"");return{app:am?am[2].toLowerCase():"",site:e.d?nsite(e.d):""}};
const hhmm=t=>new Date(t*1000).toLocaleTimeString([],{hour:"numeric",minute:"2-digit"});
const ttl=m=>{const x=/ — (.+)$/.exec(m||"");return x?x[1]:""};
// Blocked-site log. Preferred source: status.siteHits = {"domain":{n:count,last:unixSeconds}} (agent, later).
// Fallback: count "Blocked website: domain" events so the page works with the current agent.
const hits=s=>{const m={};for(const[k,v]of Object.entries(s.siteHits||{})){const key=nsite(k);m[key]=m[key]||{n:0,last:0};m[key].n+=+v.n||0;m[key].last=Math.max(m[key].last,+v.last||0)}
 if(!s.siteHits)for(const e of s.events||[]){const x=/^Blocked website:?\s*([^\s,;]+)/i.exec(e.message||"");if(x){const k=x[1].toLowerCase().replace(/^https?:\/\/|^www\.|\/.*$/g,"");m[k]=m[k]||{n:0,last:0};m[k].n++;m[k].last=Math.max(m[k].last,e.at||0)}}
 return Object.entries(m).sort((a,b)=>b[1].last-a[1].last)};
const BR=["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe"];
const FILTERS=[["adult","Adult content","Pornography and explicit sites"],["gambling","Gambling & betting","Casinos, sportsbooks, lotteries"],["social","Social media","Facebook, TikTok, Instagram and similar"],["proxy","VPNs & proxies","Stops filter bypass tools"],["safe","Safe search","Google, Bing and YouTube restricted mode"]];
const PRESETS={child:{adult:true,gambling:true,social:true,proxy:true,safeSearch:true},teen:{adult:true,gambling:true,social:false,proxy:true,safeSearch:true}};

// ---- who is signed in? 'admin' | 'parent' | 'none'. Used to keep parents out of the admin and setup pages. ----
export async function roleOf(user){
 if(!user||user.isAnonymous)return "none";
 try{if((await F.getDoc(F.doc(db,"admins",user.uid))).exists())return "admin"}catch{}
 try{if((await F.getDoc(F.doc(db,"parents",user.uid))).exists())return "parent"}catch{}
 return "none"}

// ---- daily counters: they cover 00:00 to 23:59 of today only. Nothing from earlier days is kept or shown. ----
const dayStart=()=>{const n=new Date();return Math.floor(new Date(n.getFullYear(),n.getMonth(),n.getDate()).getTime()/1000)};
export const dayStr=()=>new Date().toLocaleDateString("sv");
export const secToMidnight=()=>{const n=new Date();return Math.max(0,Math.floor((new Date(n.getFullYear(),n.getMonth(),n.getDate()+1)-n)/1000))};
const DEFAULT_GAMES=["robloxplayerbeta.exe","minecraft.exe","javaw.exe","steam.exe","epicgameslauncher.exe","fortniteclient-win64-shipping.exe","leagueclient.exe","riotclientservices.exe","valorant.exe","among us.exe"];
const GAME_RX=/(roblox|minecraft|fortnite|valorant|leagueclient|leagueoflegends|riotclient|^steam|epicgames|amongus|among us|genshin|pubg|^gta|csgo|^cs2|dota2|fifa|efootball|callofduty|warzone|r5apex|apexlegends|overwatch|rocketleague|terraria|stardew|cyberpunk|fallguys|brawlhalla|freefire|^bluestacks|^hd-player|^ldplayer|^noxplayer|javaw|solitaire|^ludo|^chess|^eadesktop|^ealauncher|^eaapp|^origin\.exe|battle\.net|^upc\.exe)/i;
const NOT_GAME=/(gamebar|gameinput|gamingservices|xboxpcapp|xboxapp)/i;
// Helpers that run in the background all day are not "apps the child used".
const BG_APP=/(webview|onedrive|widgets|searchapp|searchui|securityhealth|svchost|conhost|dllhost|sihost|taskhostw|backgroundtaskhost|smartscreen|useroobe|phoneexperience|crossdevice|nvcontainer|nvidia|rtkaud|realtek|igfx|audiodg|wmiprvse|fontdrvhost|msedgeupdate|googleupdate|crashpad|^cmd\.exe|^powershell|^pythonw?\.exe|notice|helper\.exe|service\.exe|tray\.exe)/i;
export const isGame=(n,c)=>{n=String(n||"").toLowerCase();if(!n||NOT_GAME.test(n))return false;return [...DEFAULT_GAMES,...(c.blockedGames||[]),...(c.allowedGames||[])].map(x=>String(x).toLowerCase()).includes(n)||GAME_RX.test(n)};
const niceApp=n=>String(n||"").replace(/\.exe$/i,"");
// o = {hideSite, hideApp, hideText}: anything the administrator hid from the parent is left out of the counts too.
export function dailyStats(s,c,o){
 const t0=dayStart(),tl=s.timeline||s.events||[],pg=new Map(),lau={},blk=[];
 for(const e of tl){if(!(e.at>=t0))continue;const m=e.message||"",kind=e.kind||(/^Visited /.test(m)?"web":/^Blocked/.test(m)?"block":/^Application/.test(m)?"app":"sys");
  if(kind==="web"){const k=nsite(e.d);if(k&&!o.hideSite(k))pg.set(k,(pg.get(k)||0)+1)}
  else if(kind==="block"){if(!(e.d&&o.hideSite(e.d))&&!o.hideText(m))blk.push(e)}
  else if(kind==="app"&&/^Application started/i.test(m)){const a=evInfo(e).app;if(a&&!o.hideApp(a))lau[a]=(lau[a]||0)+1}}
 // the agent also reports the last visit times of every site; use whichever is larger so a long feed never under-counts
 for(const x of s.sites||[]){if(x.g)continue;const k=nsite(x.d);if(!k||o.hideSite(k))continue;const n=(x.v||[]).filter(t=>t>=t0).length;if(n>(pg.get(k)||0))pg.set(k,n)}
 // app minutes are reset by the agent at its own midnight; a report older than today's midnight is yesterday's data
 const stale=s.day&&s.day!==dayStr()&&(+s.seen||0)<t0,am=stale?{}:mergeApps(s.apps),apps=[],games=[];
 for(const n of new Set([...Object.keys(am),...Object.keys(lau)])){if(o.hideApp(n)||BG_APP.test(n))continue;const row=[n,am[n]||0,lau[n]||0];(isGame(n,c)?games:apps).push(row)}
 const by=(x,y)=>(y[2]-x[2])||(y[1]-x[1]);apps.sort(by);games.sort(by);
 const sites=[...pg.entries()].sort((a,b)=>b[1]-a[1]);
 return {pages:sites.reduce((t,x)=>t+x[1],0),sites,apps,games,launches:Object.values(lau).reduce((t,x)=>t+x,0),blocked:blk.length}}
export const humanMin=m=>{m=Math.round(m);if(m<1)return "less than a minute";const h=Math.floor(m/60),r=m%60;return (h?h+(h===1?" hour":" hours"):"")+(h&&r?" and ":"")+(r?r+(r===1?" minute":" minutes"):"")};

// ---- read aloud with the most natural voice the device has ----
// Browsers expose the voices installed on the device. "Natural"/"Neural" (Microsoft Edge), Google, Siri and Premium/Enhanced voices
// sound like a person; old "Desktop"/eSpeak voices sound like a robot. We rank them and use the best one, or the one the viewer picked.
const VKEY="pg-voice",vstore={get(){try{return localStorage.getItem(VKEY)||""}catch{return""}},set(v){try{localStorage.setItem(VKEY,v)}catch{}}};
const vrank=v=>{const n=(v.name||"")+" "+(v.voiceURI||"");if(!/^en/i.test(v.lang||""))return -100;let s=0;
 if(/natural|neural|online/i.test(n))s+=60;if(/premium|enhanced|siri/i.test(n))s+=45;if(/google/i.test(n))s+=30;
 if(/samantha|serena|karen|moira|tessa|daniel|allison|susan|fiona|kate|oliver|ava\b/i.test(n))s+=20;
 s+=({"en-NG":9,"en-GB":6,"en-US":5,"en-ZA":4,"en-GH":4}[String(v.lang).replace("_","-")]||0);
 if(/espeak|compact|desktop|zira|david|mark\b|hazel|robot|fred|ralph|junior|albert|bad news|bells|boing|cellos|good news|organ|trinoids|whisper|wobble|zarvox|bubbles|deranged|hysterical/i.test(n))s-=60;
 if(v.localService===false)s+=5;return s};
const allVoices=()=>{try{return speechSynthesis.getVoices()}catch{return[]}};
export const voiceList=()=>allVoices().filter(v=>/^en/i.test(v.lang||"")).map(v=>[vrank(v),v]).sort((a,b)=>b[0]-a[0]);
const pickVoice=()=>{const L=voiceList(),want=vstore.get();return (want&&(L.find(x=>x[1].voiceURI===want)||[])[1])||(L[0]||[])[1]||null};
export const setVoicePref=v=>vstore.set(v||"");
export const canSpeak=()=>"speechSynthesis" in window&&"SpeechSynthesisUtterance" in window;
const vname=v=>String(v.name).replace(/^Microsoft\s+/i,"").replace(/\s*Online\s*\(Natural\)/i," Natural").replace(/\s*-\s*English.*$/i,"")+" · "+String(v.lang).replace("_","-");
// Fills a <select> with the best voices and shows a hint in `hint` when only basic voices exist.
export function fillVoiceSelect(sel,hint){if(!sel)return;const L=voiceList(),cur=vstore.get();
 sel.innerHTML='<option value="">Best voice (automatic)</option>'+L.slice(0,14).map(([,v])=>`<option value="${esc(v.voiceURI)}" ${v.voiceURI===cur?"selected":""}>${esc(vname(v))}</option>`).join("");
 if(hint){const weak=!L.length||L[0][0]<40;hint.hidden=!weak;hint.textContent=weak?"This device only has basic voices. For a much more human voice, open ParentGuard in Microsoft Edge (free Natural voices), or install a Premium / Enhanced voice in the device's speech settings.":""}}
export const onVoices=cb=>{if(!canSpeak())return;cb();try{speechSynthesis.addEventListener("voiceschanged",cb)}catch{}};
let speakToken=0;
export function stopSpeak(){speakToken++;try{speechSynthesis.cancel()}catch{}}
// Reads text sentence by sentence with short natural pauses (long single utterances stop part-way in some browsers).
export function speak(text,onEnd){
 if(!canSpeak()){toast("Reading aloud is not supported in this browser. Try Microsoft Edge or Chrome.","bad");onEnd&&onEnd();return false}
 stopSpeak();const my=speakToken,v=pickVoice(),parts=String(text).replace(/\s+/g," ").trim().match(/[^.!?]+[.!?]*/g)||[],chunks=[];
 for(const p of parts){const l=chunks.length-1;if(l>=0&&chunks[l].length+p.length<160&&!/[.!?]\s*$/.test(chunks[l]))chunks[l]+=p;else chunks.push(p.trim())}
 let i=0;const next=()=>{if(my!==speakToken)return;if(i>=chunks.length){onEnd&&onEnd();return}
  const u=new SpeechSynthesisUtterance(chunks[i++]);if(v){u.voice=v;u.lang=v.lang}else u.lang="en-US";u.rate=.94;u.pitch=1;u.volume=1;
  u.onend=()=>setTimeout(next,i<chunks.length?220:0);u.onerror=e=>{if(my!==speakToken||e.error==="interrupted"||e.error==="canceled")return;onEnd&&onEnd()};
  try{speechSynthesis.speak(u)}catch{onEnd&&onEnd()}};
 setTimeout(next,80);return true}

// One child's dashboard. role 'admin' may lock sections from the parent. save(cfg, adminCfg|undefined).
// Returned element has .refresh(newDoc) which updates live data without losing unsaved edits.
export function panel(id,d,role,save){
 const adm=role==="admin",a=J(d.adminCfg);let c=J(d.cfg);
 if(adm)for(const k of ["paused","bonus","unlockedUntil","overrideMode","apps","allowedApps","blockedGames","allowedGames","blockGames","sites","allowedSites","safeSearch","locationEnabled"])if(k in a)c[k]=a[k];
 const HTAB=()=>a.hide||[],isH=k=>!adm&&HTAB().includes(k),
  hidS=()=>a.hiddenSites||[],hidA=()=>a.hiddenApps||[],
  isHidSite=n=>{n=String(n||"").toLowerCase();return hidS().some(h=>n===h||n.endsWith("."+h))},isHidApp=n=>hidA().includes(String(n||"").toLowerCase()),
  hideSite=n=>!adm&&isHidSite(n),hideApp=n=>!adm&&isHidApp(n),
  hideText=m=>{if(adm)return false;m=String(m||"").toLowerCase();return hidS().some(h=>m.includes(h))||hidA().some(h=>m.includes(h))};
 const L=a.locked||[],susp=()=>!adm&&!!d.suspended,dis=k=>(!adm&&L.includes(k))||susp()?"disabled":"";
 const lkt=k=>adm?`<label class=lkt><input type=checkbox data-l=${k} ${L.includes(k)?"checked":""}> Lock from parent</label>`:L.includes(k)?`<span class=lkt>🔒 Locked by administrator</span>`:"";
 const w={};for(const k of ["apps","allowedApps","blockedGames","allowedGames","sites","allowedSites"])w[k]=[...(c[k]||[])];
 let pending=null,tab="over",tlf="all",vsf="all",vq="",showBg=false,reqs=[],unsubR=null;const open=new Set();
 const el=document.createElement("div");el.className="c dev";
 const chipEd=k=>{const off=dis(k==="sites"||k==="allowedSites"?"sites":k.includes("ame")?"games":"apps");return `<div class=chips data-k=${k}>${w[k].map(x=>`<span class=chip>${esc(x)}${off?"":`<button type=button data-rm="${esc(x)}" aria-label="Remove ${esc(x)}">×</button>`}</span>`).join("")}${off?"":`<input data-add placeholder="Type and press Enter">`}</div>`};
 const tg=(f,t,s,on,k)=>`<label class=tg><input type=checkbox data-f=${f} ${on?"checked":""} ${dis(k)}><span class=sl></span><span class=tt><b>${t}</b><small>${s}</small></span></label>`;
 const flt=f=>f==="safe"?c.safeSearch!==false:!!c[f];
 const lockedNow=()=>{
  if(d.suspended)return true;
  const now=Date.now()/1000,until=Number(c.unlockedUntil||0),mode=String(c.overrideMode||"");
  if(mode==="unlock"&&(!until||until>now))return false;
  if(mode==="lock")return true;
  if(until>now)return false; // legacy timed unlock
  const status=J(d.status);
  return !!c.paused||!!status.msg||!!status.lock;
 };
 const calc=()=>{const s=J(d.status),on=online(s),wk=[0,6].includes(new Date().getDay()),base=wk?(c.limitWk??c.limit):c.limit,bonus=c.bonus&&c.bonus.day===s.day?+c.bonus.min:0,
  lim=base==null||isNaN(+base)?null:+base+bonus,us=s.usedSec!=null?+s.usedSec:(+s.used||0)*60,run=on&&!!s.active&&!lockedNow();
  return {s,on,lim,used:Math.floor(us/60),run,rem:lim==null?null:Math.max(0,lim*60-us-(run?Math.min(Math.max(Date.now()/1000-s.seen,0),30):0))}};
 const stateLine=(s,on,run,lk,rem)=>{
  if(!on)return "⏸ Paused: the device is offline.";
  const lc=s.lock;if(lk||rem===0||(lc&&s.msg)){
   if(!lc)return "Waiting for the device to apply the lock…";
   return (lc.ok?"✓ ":"⚠ ")+esc(lc.note||"")+" · "+when(lc.at)+(lc.checked?" · re-checked "+ago(lc.checked):"")}
  if(run)return "▶ Counting down: the child is using the PC.";
  if(s.childState==="locked")return "⏸ Paused: the PC user session is locked.";
  if(s.childState==="no-user-session")return "⏸ Waiting: no Windows user is currently signed in.";
  return "⏸ Waiting: no active desktop session is detected.";};
 const head=()=>{const {s,on,lim,used,rem,run}=calc(),pct=lim?Math.min(100,(lim*60-(rem??0))/(lim*60)*100):0,lk=lockedNow(),
  until=Number(c.unlockedUntil||0),unl=(c.overrideMode==="unlock"&&(!until||until>Date.now()/1000))||until>Date.now()/1000,
  ack=pending&&(Number(s.policyAppliedAt||0)>=pending-2)?(pending=null,"✓ Device confirmed the change"):pending?"Sent. Waiting for the device to confirm…":"";
  const al=[];if(s.removed)al.push("ParentGuard was removed from this device by the administrator.");else if(s.protection==="off")al.push("Parental control is stopped on this device by the administrator. Nothing is restricted or monitored until it is resumed.");if(!s.seen)al.push("The agent has never reported. Finish installing it on the child's PC.");else if(!on)al.push("Device offline for "+ago(s.seen).replace(" ago","")+". Locks and changes apply when it reconnects.");
  const pr=reqs.filter(r=>r.status==="pending").length;if(pr)al.unshift(pr+" pending request"+(pr>1?"s":"")+" from "+(d.name||"the child")+". Open the Requests tab to answer.");
  if(on&&s.msg)al.push("Restriction active: "+s.msg);if(on&&s.policySyncError)al.push("The agent could not fetch the latest website command: "+s.policySyncError);if(lim&&rem!=null&&rem>0&&rem<lim*6)al.push("Screen time almost used up.");
  return `${d.suspended?`<div class=banner style="margin:0 0 14px">⛔ This child is suspended by the administrator. The device stays locked.</div>`:""}
  <div class=timer><div class="tbox ${lk?"lk":""}"><small>${lk?"Device is locked":unl?"Temporarily unlocked":"Screen time left today"}</small>
   <div class=big data-timer>${lk?"Locked":rem==null?"No limit":clock(rem)}</div>
   <div class="pbar ${pct>90?"d":pct>70?"w":""}"><i data-bar style="width:${pct}%"></i></div>
   <small>${used} min used${lim!=null?` of ${lim} min`:""}${unl?(until?` · unlock ends ${when(until)}`:" · website override active"):""}</small>
   <div class=tstat>${stateLine(s,on,run,lk,rem)}</div></div>
  ${isH("control")?"":`<div class=lockbox><button class="lockbtn ${lk?"ok":"dg"}" data-q=${lk?"unlock":"lock"} ${dis("control")}>${lk?"🔓 Unlock device now":"🔒 Lock device now"}</button>
   ${lk?`<select data-q=unlock-min ${dis("control")} aria-label="Unlock length"><option value=30>Unlock for 30 minutes</option><option value=60>Unlock for 1 hour</option><option value=120>Unlock for 2 hours</option><option value=0>Unlock until I lock again (ignore schedules)</option></select>`:`<div class=row><select data-q=extend-min ${dis("control")} aria-label="Extra time"><option value=15>+15 min</option><option value=30 selected>+30 min</option><option value=60>+1 hour</option><option value=120>+2 hours</option></select><button class=gr data-q=extend ${dis("control")}>Add screen time</button></div>`}
   <button class=gr data-q=resume ${dis("control")}>Resume normal schedule</button><span class=q role=status>${ack}</span>${lkt("control")}</div>`}</div>
  ${al.length?`<div class=alerts><b>Needs attention</b><ul>${al.map(x=>`<li>${esc(x)}</li>`).join("")}</ul></div>`:""}`};
 const over=()=>{const {s,on,lim}=calc(),h=s.hist||{},ks=Object.keys(h).sort().slice(-7),mx=Math.max(lim||0,...ks.map(k=>h[k]),1),ap=Object.entries(mergeApps(s.apps)).filter(([n])=>!hideApp(n)).sort((x,y)=>y[1]-x[1]).slice(0,6),am=ap.length?ap[0][1]||1:1,dv=s.device||{},loc=s.location;
  return `<div class=tiles><div class=t><small>Connection</small><b class="${on?"on":"off"}">${on?"● Online":"○ Offline"}</b></div><div class=t><small>Last seen</small><b>${s.seen?ago(s.seen):"never"}</b></div><div class=t><small>Now</small><b>${on?(s.active?"User active":"No active desktop"):"—"}</b></div><div class=t><small>Computer</small><b>${esc(dv.computerName||"—")}</b></div></div>
  <div class=t style="margin-top:8px"><b>Windows users on this PC</b><div>${(s.activeUsers||[]).length?(s.activeUsers.map(esc).join(", ")+` <small>· active now</small>`):((s.accounts||[]).length?s.accounts.map(esc).join(", "):"No signed-in Windows user detected")}</div><small>Monitoring and device controls apply to every user account on this PC.</small></div>
  ${isH("usage")?"":`<div class=sec><b>Screen time, last days</b></div><div class=chart>${ks.map(k=>`<div class=col title="${k}: ${h[k]} min"><i style="height:${Math.round(h[k]/mx*100)}%"></i><small>${k.slice(5)}</small></div>`).join("")||"<small>No data yet</small>"}</div>
  <div class=sec><b>Top apps today</b></div>${ap.map(([n,m])=>`<div class=ar><span>${esc(n)}</span><span class=bar><i style="width:${Math.max(4,m/am*100)}%"></i></span><small>${Math.round(m)}m</small></div>`).join("")||"<small>None yet</small>"}`}
  ${isH("location")?"":`<div class=sec><b>Location</b></div><div class=t>${s.locationEnabled?(loc?`<a target=_blank rel=noopener href="https://maps.google.com/?q=${Number(loc.latitude)},${Number(loc.longitude)}">Open latest location in Maps</a><small>Accuracy ${Math.round(Number(loc.accuracy)||0)} m · ${esc(loc.capturedAt||"")}</small>`:"<span class=off>Precise location not available</span>"):"Location sharing is off"}${s.locationEnabled&&s.ipLocation?`<small>Approximate: ${esc([s.ipLocation.city,s.ipLocation.region,s.ipLocation.country].filter(Boolean).join(", ")||"unknown")}</small>`:""}</div>`}`};
 // ---- "Today so far": pages, apps, games. Starts at 0 every midnight and never shows earlier days. ----
 const dly=()=>dailyStats(J(d.status),c,{hideSite:hideSite,hideApp:hideApp,hideText:hideText});
 const mn=m=>m<1?"under 1 min":Math.round(m)+" min",plural=(n,w)=>n+" "+w+(n===1?"":"s");
 const leftTxt=()=>{const x=secToMidnight(),h=Math.floor(x/3600),m=Math.floor(x%3600/60);return h?h+" h "+m+" min":m+" min"};
 const todayStats=()=>{const D=dly(),tiles=[],cols=[],more=(a,n)=>a.length>n?`<small class=foot>and ${a.length-n} more</small>`:"",none="<small>Nothing yet today</small>";
  const stat=(cls,n,t,sub)=>`<div class="stat ${cls}"><b>${n}</b><span>${t}</span><small>${sub}</small></div>`;
  if(!isH("visits")){tiles.push(stat("s-pages",D.pages,D.pages===1?"Page visited":"Pages visited",plural(D.sites.length,"different site")));
   cols.push(`<div class=tdcol><h5>🌐 Sites today</h5>${D.sites.slice(0,6).map(([n,k])=>`<div class=tdrow><span>${esc(n)}</span><small>${plural(k,"visit")}</small></div>`).join("")||none}${more(D.sites,6)}</div>`)}
  if(!isH("apps")){tiles.push(stat("s-apps",D.apps.length,D.apps.length===1?"App used":"Apps used",(L=>L?L+(L===1?" launch":" launches")+" today":"programs running today")(D.apps.reduce((t,a)=>t+a[2],0))),stat("s-games",D.games.length,D.games.length===1?"Game played":"Games played",D.games.length?"see list below":"none today"));
   const line=([n,m,k])=>`<div class=tdrow><span>${esc(niceApp(n))}</span><small>${m?mn(m):"opened"}${k>1?" · "+k+"×":""}</small></div>`;
   cols.push(`<div class=tdcol><h5>🧩 Apps today</h5>${D.apps.slice(0,6).map(line).join("")||none}${more(D.apps,6)}</div>`,`<div class=tdcol><h5>🎮 Games today</h5>${D.games.slice(0,6).map(line).join("")||none}${more(D.games,6)}</div>`)}
  if(!isH("web"))tiles.push(stat("s-block",D.blocked,D.blocked===1?"Blocked attempt":"Blocked attempts",D.blocked?"stopped by the filter":"all clear"));
  return tiles.length?`<div class=stats>${tiles.join("")}</div><div class=tdgrid>${cols.join("")}</div>`:`<div class=empty>The administrator has hidden these counters.</div>`};
 const todayCard=()=>`<div class=today><div class=todayhead><div><h4>Today so far</h4><small data-tmeta></small></div><div class=speakbar>${canSpeak()?`<button type=button class=speakbtn data-speak>🔊 Read aloud</button><select data-voice aria-label="Reading voice"></select>`:""}</div></div><div data-tstats></div><div class=voicehint data-vhint hidden></div><small class=foot>Counted from 12:00 am to 11:59 pm. Pages come from the browser history the agent reads (the same site opened again within 2 minutes counts once). Apps are programs running on the PC; background helpers are left out.</small></div>`;
 const summaryText=()=>{const {s,on,lim,used}=calc(),D=dly(),nm=d.name||"your child",p=[`Here is ${nm}'s day so far.`];
  if(!isH("visits"))p.push(D.pages?`${nm} has visited ${plural(D.pages,"page")} on ${plural(D.sites.length,"site")} today.`:`${nm} has not visited any websites today.`);
  if(!isH("apps")){p.push(D.apps.length?`${plural(D.apps.length,"app")} used today${D.apps.length>1?", most of all "+niceApp(D.apps[0][0]):", which is "+niceApp(D.apps[0][0])}.`:"No apps used so far.");
   p.push(D.games.length?`${plural(D.games.length,"game")} played today: ${D.games.slice(0,3).map(g=>niceApp(g[0])).join(", ")}.`:"No games played so far.")}
  if(!isH("web")&&D.blocked)p.push(`${plural(D.blocked,"blocked attempt")} were stopped by the filter.`.replace("1 blocked attempt were","1 blocked attempt was"));
  if(!isH("usage"))p.push(`Screen time used is ${humanMin(used)}${lim!=null?" out of "+humanMin(lim):""}.`);
  p.push(lockedNow()?"The device is locked right now.":on?"The device is online.":"The device is offline.");
  const pr=reqs.filter(r=>r.status==="pending").length;if(pr)p.push(`${plural(pr,"request")} from ${nm} ${pr===1?"is":"are"} waiting for your answer.`);
  return p.join(" ").replace(/\.exe\b/gi,"").replace(/([a-z0-9-]+)\.(com|net|org|ng|io|tv|co)\b/gi,"$1 dot $2")};
 const ICON={web:"🌐",block:"⛔",app:"🧩",screen:"⏱️",user:"👤",sys:"⚙️"};
 const dayName=t=>{const d=new Date(t*1000),n=new Date(),k=Math.round((new Date(n.getFullYear(),n.getMonth(),n.getDate())-new Date(d.getFullYear(),d.getMonth(),d.getDate()))/864e5);return k===0?"Today":k===1?"Yesterday":d.toLocaleDateString([],{weekday:"long",month:"short",day:"numeric"})};
 // One row per site/app: name on the left, Block / Allow / Hide actions on the SAME row.
 const hasL=(k,n)=>(w[k]||[]).includes(n);
 const acts=(kind,n)=>{const bk=kind==="site"?"sites":"apps",ak=kind==="site"?"allowedSites":"allowedApps",isB=hasL(bk,n),isA=hasL(ak,n),hid=kind==="site"?isHidSite(n):isHidApp(n),x=`data-kind=${kind} data-n="${esc(n)}"`;
  return `<span class=acts>${isB?`<button class=gr ${x} data-act=unblock ${dis(bk)}>Unblock</button>`:`<button class=dg ${x} data-act=block ${dis(bk)}>Block</button>`}${isA?`<button class=gr ${x} data-act=unallow ${dis(bk)}>Unallow</button>`:`<button class=ok ${x} data-act=allow ${dis(bk)}>Allow</button>`}${adm?(hid?`<button class=gr ${x} data-act=unhide>Unhide</button>`:`<button class=wn ${x} data-act=hide>Hide from parent</button>`):""}</span>`};
 // Collapsible history: shows the repeated times of one site/app when its row is opened. Open state survives refreshes.
 const histBody=(items,max=40)=>items.length?`<div class=hbody>${items.slice(0,max).map(e=>`<div class=hrow><span class=ti>${esc(when(e.at))}</span><span class=hm>${esc(e.message||"")}${e.u?` <small class=sp>${esc(e.u)}</small>`:""}</span></div>`).join("")}${items.length>max?`<small>…and ${items.length-max} older entries</small>`:""}</div>`:`<div class=hbody><small>No individual entries recorded yet.</small></div>`;
 const timeline=()=>{const s=J(d.status),all=(s.timeline||s.events||[]).map(e=>({...e,kind:e.kind||(/^Blocked/.test(e.message||"")?"block":/^Application/.test(e.message||"")?"app":"sys")}));
  const list=all.filter(e=>!(e.d&&hideSite(e.d))&&!hideText(e.message)).filter(e=>tlf==="all"?e.kind!=="sys":e.kind===tlf).sort((a,b)=>b.at-a.at);
  if(!list.length)return `<div class=empty>${all.length?"Nothing in this filter yet.":"No activity reported yet. Updates appear here within seconds of the child using the PC."}</div>`;
  const days=[];
  for(const e of list){const dn=dayName(e.at);let g=days[days.length-1];if(!g||g.dn!==dn){g={dn,map:new Map()};days.push(g)}
   const i=evInfo(e),key=i.site?`s|${i.site}|${e.kind}`:i.app?`a|${i.app}|${e.kind}`:`m|${e.kind}|${e.message}`;
   let r=g.map.get(key);if(!r){r={key:dn+"|"+key,kind:e.kind,site:i.site,app:i.app,items:[]};g.map.set(key,r)}r.items.push(e)}
  let h="";
  for(const g of days){h+=`<div class=tlday>${esc(g.dn)}</div>`;
   for(const r of g.map.values()){const e0=r.items[0],n=r.items.length,blk=r.kind==="block",ic=ICON[r.kind]||"•",
     link=r.site?`<a href="http://${esc(r.site)}" target=_blank rel="noopener noreferrer">${esc(r.site)}</a>`:"",
     ac=r.site?acts("site",r.site):r.app?acts("app",r.app):"";
    if(n===1){const txt=(r.site?(blk?"Blocked website: ":"Visited ")+link:esc(e0.message))+(r.site&&!blk&&ttl(e0.message)?` <small class=sp>${esc(ttl(e0.message))}</small>`:"")+(e0.c?` <span class="tag bad">⚠ looks like ${esc(e0.c)} site</span>`:"");
     h+=`<div class="tli k-${esc(r.kind)}"><span class=ti>${hhmm(e0.at)}</span><span class=ic>${ic}</span><span class=tx>${txt}</span>${ac}</div>`;continue}
    const name=r.site?(blk?"Blocked website: ":"Visited ")+link:r.app?(blk?"Blocked application: ":"Application started: ")+`<b>${esc(r.app)}</b>`:esc(e0.message),
     span=`first ${hhmm(r.items[n-1].at)} · last ${hhmm(e0.at)}`;
    h+=`<details class="tlg k-${esc(r.kind)}" data-d="${esc(r.key)}" ${open.has(r.key)?"open":""}><summary><span class=ti>${hhmm(e0.at)}</span><span class=ic>${ic}</span><span class=tx>${name} <span class="tag gy">${n}×</span><small class=sp>${span}</small></span>${ac}<span class=chev aria-hidden=true>▾</span></summary>${histBody(r.items)}</details>`}}
  return h};
 const visits=()=>{const s=J(d.status),q=vq.trim().toLowerCase();
  if(!s.sites)return `<div class=empty>Visited sites appear here once the updated agent (v5.2+) is running on the child's PC.</div>`;
  const tl=(s.timeline||s.events||[]),m=new Map();
  for(const x of s.sites||[]){const k=nsite(x.d);if(!k||hideSite(x.d))continue;let r=m.get(k);if(!r){r={d:k,n:0,l:0,bl:0,b:0,g:true,c:"",k:0,v:new Set()};m.set(k,r)}
   if(x.c)r.c=x.c;r.k=Math.max(r.k,+x.k||0);r.n+=+x.n||0;r.b+=+x.b||0;r.l=Math.max(r.l,+x.l||0);r.bl=Math.max(r.bl,+x.bl||0);if(!x.g||x.b)r.g=false;r.v.add(String(x.d).toLowerCase())}
  const list=[...m.values()].filter(x=>(showBg||!x.g||x.b)&&(vsf==="all"||(vsf==="blocked"&&x.b>0))&&(!q||x.d.includes(q))).sort((a,b)=>Math.max(b.l,b.bl)-Math.max(a.l,a.bl));
  if(!list.length)return `<div class=empty>No websites match.</div>`;
  return list.map(x=>{const last=Math.max(x.l,x.bl),key="vs|"+x.d,hist=tl.filter(e=>e.d&&nsite(e.d)===x.d).sort((a,b)=>b.at-a.at),
    vars=[...x.v].filter(v=>v!==x.d);
   return `<details class=grp data-d="${esc(key)}" ${open.has(key)?"open":""}><summary><div class=iname><a href="http://${esc(x.d)}" target=_blank rel="noopener noreferrer">${esc(x.d)}</a>
    <small>${x.n?x.n+(x.n===1?" visit":" visits")+" · ":""}Last: ${when(last)}</small>
    <span class=tags>${x.b?`<span class="tag bad">blocked ${x.b}×</span>`:""}${x.k?`<span class="tag bad">⛔ opened although blocked</span>`:""}${x.c&&!x.b&&!hasL("sites",x.d)?`<span class="tag bad">⚠ looks like ${esc(x.c)} site · not blocked</span>`:""}${hasL("sites",x.d)?`<span class="tag bad">on block list</span>`:""}${hasL("allowedSites",x.d)?`<span class="tag ok">allowed</span>`:""}${x.g?`<span class="tag gy">background</span>`:""}${adm&&isHidSite(x.d)?`<span class="tag wn">hidden from parent</span>`:""}</span></div>${acts("site",x.d)}<span class=chev aria-hidden=true>▾</span></summary>
    ${vars.length?`<div class=hbody><small>Also seen as:</small> <span class=tags>${vars.map(v=>`<span class="tag gy">${esc(v)}</span>`).join("")}</span></div>`:""}${histBody(hist)}</details>`}).join("")};
 const webMon=()=>{const s=J(d.status),w=s.web;
  if(!w)return `<div class=t style="margin:0 0 10px"><b>Web monitoring status</b><small>Waiting for the updated agent (v5.9) to report. Run install.bat again on the child's PC.</small></div>`;
  const live=w.mode==="real-time-filter",src=w.historySources||[],er=w.historyErrors||[];
  return `<div class=t style="margin:0 0 10px"><b>Web monitoring status</b>
   <div>${live?"✅ Real-time blocking is on: every website lookup on this PC is checked before the page loads.":"⚠ Real-time blocking is NOT running"+(w.dnsError?" ("+esc(w.dnsError)+")":"")+". Only the HOSTS-file list is enforced."}</div>
   <div>${src.length?"✅ Visited sites are read from the browser history of: "+src.map(esc).join(", "):"⚠ No browser history found yet. Open Chrome, Edge, Brave or Firefox once on the child's account."}${w.historyAt?` <small>· checked ${ago(w.historyAt)}</small>`:""}</div>
   ${er.length?`<div class=off><small>${er.map(esc).join("<br>")}</small></div>`:""}
   <div>${w.privateOff?"✅ Private / Incognito browsing, guest mode and history deletion are switched off.":"⚠ Private-browsing restriction not confirmed on this PC."}</div>
   ${live?`<small>Lookups checked: ${w.dnsQueries||0} · blocked: ${w.dnsBlocked||0}</small>`:""}</div>`};
 const appsUsed=()=>{const s=J(d.status),us=mergeApps(s.apps),tl=s.timeline||s.events||[];
  const names=[...new Set([...Object.keys(us),...w.apps.map(x=>String(x).toLowerCase()),...w.allowedApps.map(x=>String(x).toLowerCase())])].filter(n=>!hideApp(n)).sort((x,y)=>(us[y]||0)-(us[x]||0));
  if(!names.length)return `<div class=empty>No apps seen yet. Apps the child opens appear here with their actions.</div>`;
  return names.map(n=>{const m=us[n],hist=tl.filter(e=>evInfo(e).app===n).sort((a,b)=>b.at-a.at),key="ap|"+n,
    info=`<div class=iname><b>${esc(n)}</b><small>${m!=null?Math.round(m)+" min today":"not seen today"}${hist.length>1?` · opened ${hist.length}×`:""}</small>
    <span class=tags>${hasL("apps",n)?`<span class="tag bad">blocked</span>`:""}${hasL("allowedApps",n)?`<span class="tag ok">allowed</span>`:""}${adm&&isHidApp(n)?`<span class="tag wn">hidden from parent</span>`:""}</span></div>${acts("app",n)}`;
   if(!hist.length)return `<div class=item>${info}</div>`;
   return `<details class=grp data-d="${esc(key)}" ${open.has(key)?"open":""}><summary>${info}<span class=chev aria-hidden=true>▾</span></summary>${histBody(hist)}</details>`}).join("")};
 const sitesLog=()=>{const h=hits(J(d.status)).filter(([dom])=>!hideSite(dom));return h.length?h.map(([dom,v])=>`<div class=hit><div><a href="http://${esc(dom)}" target=_blank rel="noopener noreferrer">http://${esc(dom)}</a><br><small>Last: ${v.last?when(v.last):"unknown"}</small></div><span class=cnt>blocked ${v.n} ${v.n===1?"time":"times"}</span></div>`).join(""):`<div class=empty>No blocked attempts yet. Blocked websites will appear here with the time of each attempt.</div>`};
 const RT={time:"⏱ More screen time",site:"🌐 Allow website",app:"🧩 Allow app",message:"💬 Message"},LOCKKEY={time:"control",site:"sites",app:"apps",message:""};
 const reqList=()=>{if(!reqs.length)return `<div class=empty>No requests yet. When ${esc(d.name||"the child")} asks for more time, or for a site or app to be allowed, from the pop-up window, it appears here and is e-mailed to the parent and the administrator.</div>`;
  return reqs.map(r=>{const p=r.status==="pending",what=r.type==="time"?(Number(r.minutes)||30)+" more minutes":r.type==="message"?"":esc(r.target||""),k=LOCKKEY[r.type]||"",
   badge=p?`<span class="tag wn">Waiting</span>`:r.status==="approved"?`<span class="tag ok">Approved</span>`:r.status==="seen"?`<span class="tag gy">Read</span>`:`<span class="tag bad">Declined</span>`,
   mail=r.emailed?"✉ E-mailed to parent and administrator":r.emailError?"✉ E-mail not sent: "+esc(r.emailError):"✉ Sending e-mail…";
   return `<div class="rq ${p?"pend":""}"><div class=rqh><b>${RT[r.type]||"Request"}</b><span class=rqw>${what}</span>${badge}<small>${r.createdAt?when(r.createdAt):""}</small></div>
   ${r.note?`<div class=rqn>“${esc(r.note)}”</div>`:""}${r.reason?`<small>${esc(r.reason)}</small>`:""}<small class=rqm>${mail}</small>
   ${p?`<div class=row style="margin-top:8px"><button class=ok data-rq=yes data-id="${esc(r.id)}" ${dis(k)}>${r.type==="message"?"Mark as read":"Approve"}</button>${r.type==="message"?"":`<button class=dg data-rq=no data-id="${esc(r.id)}" ${dis(k)}>Decline</button>`}</div>`:""}</div>`}).join("")};
 const HV=[["over","Overview tab"],["req","Requests tab"],["live","Live timeline tab"],["visits","Sites visited tab"],["web","Website rules tab"],["apps","Apps & games tab"],["time","Schedule tab"],["usage","Screen-time chart and top apps"],["location","Location"],["control","Lock / unlock / add-time buttons"]];
 const pview=()=>`<div class=pane data-p=pview ${tab!=="pview"?"hidden":""}><div class=sec><b>What the parent can see</b></div><small>Tick anything you want to <b>hide from the parent dashboard</b>. You always see everything.</small>
  <div class=grid style="margin-top:10px">${HV.map(([k,t])=>`<label class=tg><input type=checkbox data-hv="${k}" ${HTAB().includes(k)?"checked":""}><span class=sl></span><span class=tt><b>${t}</b><small>Hidden from parent</small></span></label>`).join("")}</div>
  <div class=sec><b>Hidden sites</b><small>Hide a single site from the parent on the Sites visited tab</small></div><div class=hl>${hidS().map(n=>`<span class=chip>${esc(n)}<button type=button data-act=unhide data-kind=site data-n="${esc(n)}" aria-label="Unhide">×</button></span>`).join("")||"<small>None</small>"}</div>
  <div class=sec><b>Hidden apps</b></div><div class=hl>${hidA().map(n=>`<span class=chip>${esc(n)}<button type=button data-act=unhide data-kind=app data-n="${esc(n)}" aria-label="Unhide">×</button></span>`).join("")||"<small>None</small>"}</div></div>`;
 const body=()=>`<div class=tabs role=tablist>${[["over","Overview"],["req","Requests"],["live","Live timeline"],["visits","Sites visited"],["web","Website rules"],["apps","Apps & games"],["time","Schedule"],...(adm?[["pview","Parent view"]]:[])].filter(([k])=>!isH(k)).map(([k,t])=>`<button class="${k===tab?"act":""}" data-tab=${k} role=tab>${t}${k==="req"?`<span class=bdg data-reqbadge ${reqs.some(r=>r.status==="pending")?"":"hidden"}>${reqs.filter(r=>r.status==="pending").length||""}</span>`:""}</button>`).join("")}</div>
 ${adm?pview():""}${isH("req")?"":`<div class=pane data-p=req ${tab!=="req"?"hidden":""}><div class=sec><b>Requests from the child</b><small>Newest first</small></div><div class=reqs>${reqList()}</div></div>`}
 <div class=pane data-p=over ${tab!=="over"?"hidden":""}>${todayCard()}<div class=ov>${over()}</div></div>
 <div class=pane data-p=web ${tab!=="web"?"hidden":""}>
  <div class=sec><b>Blocked attempts</b><small>Newest first</small></div><div class=hits>${sitesLog()}</div>
  <div class=sec><b>Age profile</b>${lkt("adult")}</div><div class=seg>${[["child","Child · under 13"],["teen","Teen · 13 to 17"],["custom","Custom"]].map(([k,t])=>`<button type=button data-age=${k} class="${(c.ageGroup||"custom")===k?"act":""}" ${dis("adult")}>${t}</button>`).join("")}</div>
  <div class=sec><b>Content filters</b></div><div class=grid>${FILTERS.map(([f,t,s])=>tg(f,t,s,flt(f),f==="safe"?"browsers":"adult")).join("")}</div>
  <div class=sec><b>Always block these sites</b>${lkt("sites")}</div>${chipEd("sites")}
  <div class=sec><b>Always allow these sites</b></div>${chipEd("allowedSites")}
  <div class=sec><b>Blocked browsers</b>${lkt("browsers")}</div><div class=grid>${BR.map(b=>tg("br-"+b,b.replace(".exe",""),"Block this browser",(c.browsers||[]).includes(b),"browsers")).join("")}</div></div>
 <div class=pane data-p=apps ${tab!=="apps"?"hidden":""}>
  <div class=sec><b>Apps used</b><small>Block, allow or hide each app on its row</small></div><div class=addbar><b>Block an app</b><div class=row><input data-newapp placeholder="App file name, e.g. game.exe" aria-label="App to block" ${dis("apps")}><button class=dg data-addblock=app ${dis("apps")}>⛔ Block app</button></div></div><div class=al>${appsUsed()}</div>
  <div class=sec><b>Blocked apps</b>${lkt("apps")}</div>${chipEd("apps")}<div class=sec><b>Allowed app exceptions</b></div>${chipEd("allowedApps")}
  <div class=sec><b>Games</b>${lkt("games")}</div><div class=grid>${tg("bg","Block common games","Steam, Epic, Roblox, Minecraft and others",c.blockGames,"games")}</div>
  <div class=sec><b>Extra blocked games</b></div>${chipEd("blockedGames")}<div class=sec><b>Allowed games</b></div>${chipEd("allowedGames")}</div>
 <div class=pane data-p=time ${tab!=="time"?"hidden":""}><div class=sec><b>Daily limits and hours</b>${lkt("time")}</div><div class=fields>
  <div class=t style="grid-column:1/-1"><b>Device-wide monitoring</b><small>No child Windows username is required. ParentGuard automatically detects the active Windows user and applies monitoring, screen-time rules, and lock/unlock controls to every user account on this PC.</small></div>
  <label>School days limit (min)<input data-f=li type=number min=0 value="${c.limit??120}" ${dis("time")}></label>
  <label>Weekend limit (min)<input data-f=lw type=number min=0 value="${c.limitWk??c.limit??120}" ${dis("time")}></label>
  <label>Allowed from<input data-f=st type=time value="${c.start||"07:00"}" ${dis("time")}></label><label>Allowed until<input data-f=en type=time value="${c.end||"21:00"}" ${dis("time")}></label></div>
  <div class=sec><b>Location</b>${lkt("location")}</div><div class=grid>${tg("loc","Share device location","Needs Windows Location Services",c.locationEnabled,"location")}</div></div>
 ${isH("live")?"":`<div class=pane data-p=live ${tab!=="live"?"hidden":""}><div class=seg style="margin-bottom:10px">${[["all","Everything"],["web","Websites"],["block","Blocked"],["app","Apps"],["user","Users"],["screen","Screen time"]].map(([k,t])=>`<button type=button data-tlf=${k} class="${k===tlf?"act":""}">${t}</button>`).join("")}</div><div class=tl>${timeline()}</div></div>`}
 <div class=pane data-p=visits ${tab!=="visits"?"hidden":""}><div data-wm>${webMon()}</div><div class=addbar><b>Block a website</b><div class=row><input data-newsite placeholder="Paste a link or domain, e.g. https://example.com/page" aria-label="Link to block" ${dis("sites")}><button class=dg data-addblock=site ${dis("sites")}>⛔ Block link</button></div></div><div class=row><input data-vq placeholder="Search websites" value="${esc(vq)}" aria-label="Search websites"><div class=seg style="flex:none">${[["all","All"],["blocked","Blocked only"]].map(([k,t])=>`<button type=button data-vsf=${k} class="${k===vsf?"act":""}">${t}</button>`).join("")}</div></div>
  <label class=tg style="margin:10px 0"><input type=checkbox data-bg ${showBg?"checked":""}><span class=sl></span><span class=tt><b>Show background services</b><small>Windows, Google and CDN lookups that are not sites the child chose</small></span></label><div class=vl>${visits()}</div></div>
 <div class=savebar><button data-q=save ${susp()?"disabled":""}>Save settings</button><span class=m role=status></span></div>`;
 el.innerHTML=`<div class=dhead><h3>${esc(d.name||"Child")}</h3></div><div class=pane data-h></div><div data-b></div>`;
 const $=s=>el.querySelector(s),H=$("[data-h]");
 if(!adm&&isH(tab))tab=["over","req","live","visits","web","apps","time"].find(k=>!isH(k))||"over";
 const drawHead=()=>{H.innerHTML=head()};drawHead();$("[data-b]").innerHTML=body();
 const drawLists=()=>{$(".tl").innerHTML=timeline();$(".vl").innerHTML=visits();$(".al").innerHTML=appsUsed();const h=el.querySelector("[data-p=pview]");if(h){const t=tab;h.outerHTML=pview();el.querySelector("[data-p=pview]").hidden=t!=="pview"}};
 const drawToday=()=>{const ts=$("[data-tstats]");if(ts)ts.innerHTML=todayStats();const tm=$("[data-tmeta]");if(tm)tm.textContent="Starts again at midnight, in "+leftTxt()};
 const refreshLive=()=>{drawToday();const wm=$("[data-wm]");if(wm)wm.innerHTML=webMon();drawHead();$(".ov").innerHTML=over();$(".hits").innerHTML=sitesLog();$(".tl").innerHTML=timeline();$(".vl").innerHTML=visits();$(".al").innerHTML=appsUsed()};
 let talking=false,lastDay=dayStr();drawToday();
 onVoices(()=>fillVoiceSelect($("[data-voice]"),$("[data-vhint]")));
 const tick=()=>{if(!el.isConnected){clearInterval(t);if(talking)stopSpeak();if(unsubR){unsubR();unsubR=null}return}if(lastDay!==dayStr()){lastDay=dayStr();refreshLive()}const {rem,lim}=calc(),tm=$("[data-timer]");if(tm&&!lockedNow()&&rem!=null){tm.textContent=clock(rem);const b=$("[data-bar]");if(b)b.style.width=Math.min(100,(lim*60-rem)/(lim*60)*100)+"%"}};
 const t=setInterval(tick,1000),t2=setInterval(()=>{if(el.isConnected)refreshLive();else{clearInterval(t2);if(unsubR){unsubR();unsubR=null}}},30000);
 const drawReqs=()=>{const l=el.querySelector(".reqs");if(l)l.innerHTML=reqList();const bd=el.querySelector("[data-reqbadge]"),n=reqs.filter(r=>r.status==="pending").length;if(bd){bd.textContent=n||"";bd.hidden=!n}drawHead()};
 try{unsubR=F.onSnapshot(F.query(F.collection(db,"devices",id,"requests"),F.orderBy("createdAt","desc"),F.limit(30)),sn=>{reqs=sn.docs.map(x=>({id:x.id,...x.data()}));drawReqs()},()=>{})}catch{}
 el.refresh=nd=>{if(nd){d=nd;const n=J(d.cfg);for(const k of ["paused","unlockedUntil","overrideMode","bonus"])c[k]=n[k]}refreshLive()};
 const commitNow=async nc=>{c=nc;pending=Math.floor(Date.now()/1000);await withTimeout(save(nc,adm?{...a,paused:nc.paused,bonus:nc.bonus,unlockedUntil:nc.unlockedUntil,overrideMode:nc.overrideMode,locked:L}:undefined));drawHead()};
 const commit=(nc,btn)=>busy(btn,"Sending…",async()=>{try{await commitNow(nc);toast("Sent to the device. Waiting for it to confirm…","ok")}catch(e){pending=null;drawHead();const q=$(".q");if(q)q.textContent="Failed: "+(e.code||e.message);toast("Could not send: "+(e.code||e.message),"bad")}});
 const collect=()=>{const v=s=>$(`[data-f="${s}"]`),ck=s=>v(s).checked,n={...c,...w};
  Object.assign(n,{blockGames:ck("bg"),browsers:BR.filter(b=>ck("br-"+b)),safeSearch:ck("safe"),adult:ck("adult"),gambling:ck("gambling"),social:ck("social"),proxy:ck("proxy"),locationEnabled:ck("loc"),limit:+v("li").value,limitWk:+v("lw").value,start:v("st").value,end:v("en").value});return n};
 const addChip=(k,val)=>{val=val.trim().toLowerCase().replace(/^https?:\/\/|^www\.|\/.*$/g,"");if(k.includes("pps")||k.includes("ame"))val=val.replace(/^.*[\\/]/,"");if(val&&!w[k].includes(val))w[k].push(val)};
 const redrawChips=k=>{const box=el.querySelector(`.chips[data-k=${k}]`);box.outerHTML=chipEd(k);el.querySelector(`.chips[data-k=${k}] input`)?.focus()};
 const saveAll=async()=>{const n=collect();let ac;if(adm)ac={...a,...n,locked:[...el.querySelectorAll("[data-l]:checked")].map(x=>x.dataset.l)};await withTimeout(save(n,ac));c=n};
 const doSave=()=>busy($("[data-q=save]"),"Saving…",async()=>{const m=$(".m");m.className="m work";m.innerHTML='<span class="spin"></span> Saving your settings…';
  try{await saveAll();m.className="m okm";m.textContent="✓ Saved. The device will pick this up shortly.";toast("Settings saved ✓","ok")}
  catch(err){m.className="m badm";m.textContent="✗ Not saved: "+(err.code||err.message);toast("Could not save: "+(err.code||err.message),"bad");throw err}},"Saved").catch(()=>{});
 const answer=(r,yes,btn)=>busy(btn,yes?"Approving…":"Declining…",async()=>{try{
   if(yes&&r.type==="time"){const now=Math.floor(Date.now()/1000);await commitNow({...c,paused:false,overrideMode:"unlock",unlockedUntil:Math.max(Number(c.unlockedUntil||0),now)+(Number(r.minutes)||30)*60})}
   else if(yes&&(r.type==="site"||r.type==="app")){const al=r.type==="site"?"allowedSites":"allowedApps",bl=r.type==="site"?"sites":"apps";w[al]=[...new Set([...w[al],r.target])];w[bl]=w[bl].filter(x=>x!==r.target);await saveAll()}
   await withTimeout(F.updateDoc(F.doc(db,"devices",id,"requests",r.id),{status:yes?(r.type==="message"?"seen":"approved"):"denied",decidedAt:Math.floor(Date.now()/1000),decidedBy:role}));
   toast(yes?(r.type==="message"?"Marked as read":"Approved. The device applies it within seconds."):"Request declined","ok")}
  catch(e){toast("Could not "+(yes?"approve":"decline")+": "+(e.code||e.message),"bad")}});
 el.addEventListener("click",e=>{const b=e.target.closest("button");if(!b)return;
  if(b.dataset.speak!==undefined){const idle=()=>{talking=false;b.classList.remove("playing");b.innerHTML="🔊 Read aloud"};
   if(talking){stopSpeak();idle();return}talking=true;b.classList.add("playing");b.innerHTML="⏹ Stop reading";if(!speak(summaryText(),idle))idle();return}
  if(b.dataset.tab){tab=b.dataset.tab;el.querySelectorAll("[data-tab]").forEach(x=>x.classList.toggle("act",x===b));el.querySelectorAll("[data-p]").forEach(p=>p.hidden=p.dataset.p!==tab);return}
  if(b.dataset.rm!==undefined){const k=b.closest(".chips").dataset.k;w[k]=w[k].filter(x=>x!==b.dataset.rm);redrawChips(k);return}
  if(b.dataset.age){const g=b.dataset.age;el.querySelectorAll("[data-age]").forEach(x=>x.classList.toggle("act",x===b));c.ageGroup=g;const p=PRESETS[g];if(p)for(const[f,v]of Object.entries(p)){const i=$(`[data-f="${f==="safeSearch"?"safe":f}"]`);if(i)i.checked=v}return}
  if(b.dataset.tlf){tlf=b.dataset.tlf;el.querySelectorAll("[data-tlf]").forEach(x=>x.classList.toggle("act",x===b));$(".tl").innerHTML=timeline();return}
  if(b.dataset.vsf){vsf=b.dataset.vsf;el.querySelectorAll("[data-vsf]").forEach(x=>x.classList.toggle("act",x===b));$(".vl").innerHTML=visits();return}
  if(b.dataset.addblock){const kind=b.dataset.addblock,inp=$(kind==="site"?"[data-newsite]":"[data-newapp]");let v=inp.value.trim().toLowerCase();
   if(kind==="site")v=v.replace(/^[a-z]+:\/\//,"").replace(/^www\./,"").replace(/[\/?#:].*$/,"");else v=v.replace(/^.*[\\/]/,"");
   if(!v||(kind==="site"&&!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(v))){toast(kind==="site"?"Enter a valid link or domain":"Enter an app file name","bad");return}
   const bk=kind==="site"?"sites":"apps",ak=kind==="site"?"allowedSites":"allowedApps";if(!w[bk].includes(v))w[bk].push(v);w[ak]=w[ak].filter(x=>x!==v);inp.value="";
   drawLists();redrawChips(bk);redrawChips(ak);doSave().then(drawLists);return}
  if(b.dataset.act){const kind=b.dataset.kind,n=b.dataset.n.toLowerCase(),act=b.dataset.act,bk=kind==="site"?"sites":"apps",ak=kind==="site"?"allowedSites":"allowedApps";
   const rm=(k,v)=>{w[k]=w[k].filter(x=>x!==v)},ad=(k,v)=>{if(!w[k].includes(v))w[k].push(v)};
   if(act==="hide"||act==="unhide"){const hk=kind==="site"?"hiddenSites":"hiddenApps",cur=a[hk]||[];a[hk]=act==="hide"?[...new Set([...cur,n])]:cur.filter(x=>x!==n);
    busy(b,act==="hide"?"Hiding…":"Unhiding…",async()=>{try{await withTimeout(save(c,{...a,locked:[...el.querySelectorAll("[data-l]:checked")].map(x=>x.dataset.l)}));toast(act==="hide"?"Hidden from the parent ✓":"Visible to the parent again ✓","ok")}catch(e){toast("Could not save: "+(e.code||e.message),"bad")}drawLists()});return}
   if(act==="block"){ad(bk,n);rm(ak,n)}else if(act==="unblock")rm(bk,n);else if(act==="allow"){ad(ak,n);rm(bk,n)}else if(act==="unallow")rm(ak,n);
   drawLists();redrawChips(bk);redrawChips(ak);doSave().then(drawLists);return}
  if(b.dataset.rq){const r=reqs.find(x=>x.id===b.dataset.id);if(r)answer(r,b.dataset.rq==="yes",b);return}
  const q=b.dataset.q;if(q==="lock")commit({...c,paused:true,overrideMode:"lock",unlockedUntil:0},b);
  else if(q==="unlock"){const m=Number($("[data-q=unlock-min]").value);commit({...c,paused:false,overrideMode:"unlock",unlockedUntil:m?Math.floor(Date.now()/1000)+m*60:0},b)}
  else if(q==="resume")commit({...c,paused:false,overrideMode:"schedule",unlockedUntil:0},b);
  else if(q==="extend"){const m=Number($("[data-q=extend-min]").value)||30,day=J(d.status).day||new Date().toLocaleDateString("sv"),p=c.bonus&&c.bonus.day===day?+c.bonus.min:0;commit({...c,bonus:{day,min:p+m}},b)}
  else if(q==="save")doSave()});
 el.addEventListener("input",e=>{if(e.target.dataset.vq!==undefined){vq=e.target.value;$(".vl").innerHTML=visits()}});
 el.addEventListener("change",e=>{if(e.target.dataset.voice!==undefined){setVoicePref(e.target.value);if(talking){stopSpeak();talking=false;const sb=$("[data-speak]");if(sb){sb.classList.remove("playing");sb.innerHTML="🔊 Read aloud"}}toast("Voice changed. Press Read aloud to hear it.","ok");return}
  if(e.target.dataset.hv){a.hide=[...el.querySelectorAll("[data-hv]:checked")].map(x=>x.dataset.hv);withTimeout(save(c,{...a,locked:[...el.querySelectorAll("[data-l]:checked")].map(x=>x.dataset.l)})).then(()=>toast("Parent view updated ✓","ok"),err=>toast("Could not save: "+(err.code||err.message),"bad"));return}
  if(e.target.dataset.bg!==undefined){showBg=e.target.checked;$(".vl").innerHTML=visits()}});
 el.addEventListener("toggle",e=>{const dm=e.target.dataset&&e.target.dataset.d;if(dm){e.target.open?open.add(dm):open.delete(dm)}},true);
 el.addEventListener("keydown",e=>{if(e.key==="Enter"&&(e.target.dataset.newsite!==undefined||e.target.dataset.newapp!==undefined)){e.preventDefault();e.target.closest(".addbar").querySelector("[data-addblock]").click();return}
  if(e.key==="Enter"&&e.target.dataset.add!==undefined){e.preventDefault();const k=e.target.closest(".chips").dataset.k;addChip(k,e.target.value);redrawChips(k)}});
 return el}
