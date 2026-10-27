"use strict";
const $ = id => document.getElementById(id);
let csrf = "";
async function api(path, opts={}) {
  const r=await fetch(path,{credentials:"same-origin",cache:"no-store",...opts});
  let data={};
  try{ data=await r.json(); }catch{}
  if(!r.ok) throw new Error(data.error || "Request failed");
  return data;
}
function announce(msg){$("notice").textContent=msg;}
function cell(row, value){
  const el=document.createElement("td");el.textContent=String(value);row.appendChild(el);
}
async function refresh(){
  try{
    const me=await api("/api/me");csrf=me.csrf;
    $("login").hidden=true;$("dash").hidden=false;
    $("identity").textContent=me.tenant+" / "+me.user+" · "+me.role;
    $("metrics").replaceChildren();
    try{
      const m=await api("/api/metrics");
      for(const [label,key] of [["Requests (24h)","requests_24h"],["Allowed (24h)","allowed_24h"],["Throttled (24h)","throttled_24h"]]){
        const card=document.createElement("article");card.className="card";
        const value=document.createElement("div");value.className="value";value.textContent=String(m[key]??0);
        const title=document.createElement("p");title.textContent=label;
        card.append(value,title);$("metrics").appendChild(card);
      }
    }catch{ $("metrics").textContent="Metrics unavailable for this role."; }
    $("audit").replaceChildren();
    try{
      const events=await api("/api/audit");
      for(const e of events){const row=document.createElement("tr");
        cell(row,e.actor);cell(row,e.action);cell(row,new Date(e.timestamp*1000).toISOString());
        $("audit").appendChild(row);}
    }catch{announce("Audit events unavailable for this role.");}
  }catch{ $("login").hidden=false;$("dash").hidden=true;csrf=""; }
}
$("login-form").addEventListener("submit",async e=>{
  e.preventDefault();announce("");
  try{
    await api("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({tenant:$("tenant").value,user:$("user").value,password:$("password").value})});
    $("password").value="";await refresh();
  }catch(err){announce(err.message);$("password").value="";}
});
$("logout").addEventListener("click",async()=>{
  try{await api("/api/logout",{method:"POST",headers:{"X-CSRF-Token":csrf}});
    csrf="";announce("Signed out");await refresh();
  }catch(err){announce(err.message);}
});
refresh();
