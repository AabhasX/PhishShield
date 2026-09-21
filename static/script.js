async function scanUrl(){
  const input=document.getElementById("urlInput");
  const button=document.getElementById("scanBtn");
  const errorBox=document.getElementById("errorBox");
  const section=document.getElementById("resultSection");
  const url=input.value.trim();
  errorBox.classList.add("hidden");

  if(!url){
    errorBox.textContent="Please enter a URL first.";
    errorBox.classList.remove("hidden");
    return;
  }

  button.disabled=true; button.textContent="Analyzing...";
  try{
    const response=await fetch("/analyze",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({url})
    });
    const data=await response.json();
    if(!response.ok) throw new Error(data.error||"Analysis failed.");
    renderResult(data);
    await loadDashboard();
  }catch(error){
    errorBox.textContent=error.message;
    errorBox.classList.remove("hidden");
    section.classList.add("hidden");
  }finally{
    button.disabled=false; button.textContent="Analyze URL";
  }
}

function renderResult(data){
  document.getElementById("resultSection").classList.remove("hidden");
  document.getElementById("resultStatus").textContent=data.status;
  document.getElementById("resultUrl").textContent=data.url;
  document.getElementById("hostValue").textContent=data.host;
  document.getElementById("scoreValue").textContent=data.score;

  const badge=document.getElementById("resultBadge");
  badge.style.background =
    data.status==="SAFE" ? "var(--accent)" :
    data.status==="SUSPICIOUS" ? "var(--warn)" : "var(--danger)";

  const list=document.getElementById("reasonsList");
  list.innerHTML="";
  data.reasons.forEach(reason=>{
    const item=document.createElement("div");
    item.className="reason";
    item.textContent="• "+reason;
    list.appendChild(item);
  });

  document.getElementById("resultSection").scrollIntoView({
    behavior:"smooth",block:"start"
  });
}

async function loadDashboard(){
  const [statsResponse,historyResponse]=await Promise.all([
    fetch("/stats"),fetch("/history")
  ]);
  const stats=await statsResponse.json();
  const history=await historyResponse.json();

  document.getElementById("totalStat").textContent=stats.total;
  document.getElementById("safeStat").textContent=stats.safe;
  document.getElementById("suspiciousStat").textContent=stats.suspicious;
  document.getElementById("highRiskStat").textContent=stats.high_risk;

  const body=document.getElementById("historyBody");
  if(!history.length){
    body.innerHTML='<tr><td colspan="4" class="empty">No scans yet.</td></tr>';
    return;
  }

  body.innerHTML=history.map(row=>{
    const cls=row.status==="SAFE"?"safe":
      row.status==="SUSPICIOUS"?"suspicious":"high";
    return `<tr>
      <td class="url-cell" title="${escapeHtml(row.url)}">${escapeHtml(row.url)}</td>
      <td>${row.score}/100</td>
      <td><span class="status ${cls}">${row.status}</span></td>
      <td>${row.scanned_at}</td>
    </tr>`;
  }).join("");
}

function escapeHtml(value){
  return String(value)
    .replaceAll("&","&amp;").replaceAll("<","&lt;")
    .replaceAll(">","&gt;").replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

document.getElementById("urlInput").addEventListener("keydown",e=>{
  if(e.key==="Enter") scanUrl();
});
loadDashboard();
