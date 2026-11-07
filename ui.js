// ParentGuard UI helpers: voice greeting and password show/hide. No Firebase, no logic changes.
const ls={get:k=>{try{return localStorage.getItem(k)}catch{return null}},set:(k,v)=>{try{localStorage.setItem(k,v)}catch{}}};
// ---- voice (preference kept in this browser; default on) ----
export const voiceOn=()=>ls.get('pg:voice')!=='off';
const tsync=()=>document.querySelectorAll('[data-voice]').forEach(b=>{b.setAttribute('aria-pressed',voiceOn());b.textContent=voiceOn()?'🔊 Voice on':'🔇 Voice off'});
export function say(text){if(!voiceOn()||!('speechSynthesis' in window))return;const u=new SpeechSynthesisUtterance(text);u.lang='en';u.rate=.95;const v=speechSynthesis.getVoices().find(x=>/^en/i.test(x.lang));if(v)u.voice=v;
 // browsers block speech before the first tap/click: wait for one, then speak
 u.onerror=e=>{if(e.error==='not-allowed'){const go=()=>say(text);addEventListener('click',go,{once:true});addEventListener('keydown',go,{once:true})}};speechSynthesis.cancel();speechSynthesis.speak(u)}
addEventListener('pagehide',()=>{try{speechSynthesis.cancel()}catch{}});
export function greeting(box,name,key){const h=new Date().getHours(),part=h<12?'Good morning':h<18?'Good afternoon':'Good evening',first=String(name||'').trim().split(/\s+/)[0]||'there',sk='pg:greeted:'+key;let s={kids:0,online:0},t;
 const sum=()=>!s.kids?'No children are linked to your account yet.':`You have ${s.kids} ${s.kids>1?'children':'child'} linked, and ${s.online?s.online+(s.online>1?' are':' is')+' online right now':'none are online right now'}.`;
 const say2=()=>say(part+', '+first+'. '+sum());
 box.innerHTML='<div><small></small><h2></h2><p></p><div class="pills"><span></span><span></span></div></div><div class="gctl"><button type="button" data-voice aria-pressed="true"></button><button type="button" data-replay>▶ Read aloud</button></div>';
 const q=x=>box.querySelector(x);q('small').textContent=new Date().toLocaleDateString([],{weekday:'long',month:'long',day:'numeric'});q('h2').textContent=part+', '+first;
 q('[data-voice]').onclick=()=>{ls.set('pg:voice',voiceOn()?'off':'on');if(!voiceOn()){try{speechSynthesis.cancel()}catch{}}tsync()};q('[data-replay]').onclick=()=>{if(!voiceOn()){ls.set('pg:voice','on');tsync()}say2()};tsync();
 return{update(n){s=n;q('p').textContent=sum();const sp=box.querySelectorAll('.pills span');sp[0].textContent=s.kids+(s.kids===1?' child':' children');sp[1].textContent=s.online+' online';
  let seen=false;try{seen=sessionStorage.getItem(sk)}catch{}if(!seen){clearTimeout(t);t=setTimeout(()=>{try{sessionStorage.setItem(sk,'1')}catch{}say2()},1500)}}}}
// ---- show / hide password buttons (works for inputs created later too) ----
const eye=()=>document.querySelectorAll('input[type=password]:not([data-eye])').forEach(i=>{i.dataset.eye=1;const w=document.createElement('span');w.className='pwwrap';i.replaceWith(w);w.append(i);const b=document.createElement('button');b.type='button';b.className='eye gr';b.textContent='Show';b.setAttribute('aria-label','Show password');b.onclick=()=>{const h=i.type==='password';i.type=h?'text':'password';b.textContent=h?'Hide':'Show'};w.append(b)});
new MutationObserver(eye).observe(document.body,{childList:true,subtree:true});eye();
