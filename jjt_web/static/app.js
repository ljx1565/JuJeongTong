const state = {
  view: "run", targets: new Set(), scope: "full",
  checks: new Set(["unix", "windows", "network", "pc", "dbms", "virtual", "web_application"]), confirmed: false,
  type: "", status: "", query: "", page: 1, pageSize: 500,
  resultTarget: "", resultFrom: "", resultTo: "", editingTarget: null,
  resultRun: 0, resultDevice: "",
  resultSort: "observed_at", resultOrder: "desc",
  targetMode: "saved", directTarget: { hostname:"", ip:"", port:22, username:"", password:"", role:"", platform:"", path:"" },
};
let targets = [];
const scopes = [["full", "전체 기준 점검", 7, "장비별 전체 항목"]];
const checks = [["unix", "Unix Server", "서버 계정·서비스·파일·네트워크", 55], ["windows", "Windows Server", "Windows 서버 보안 설정", 62], ["network", "Network Device", "라우터·스위치 보안 설정", 31], ["pc", "Windows PC", "사용자 PC 보안 설정", 18], ["dbms", "DBMS", "데이터베이스 보안 설정", 26], ["virtual", "Virtualization", "ESXi·XenServer 보안 설정", 25], ["web_application", "Web Application", "웹 애플리케이션 설정", 5]];
const content = document.querySelector("#content");

document.querySelectorAll("[data-view]").forEach(button => button.addEventListener("click", () => switchView(button.dataset.view)));
document.querySelector("#refresh").addEventListener("click", render);
setInterval(() => { document.querySelector("#clock").textContent = new Date().toLocaleTimeString("ko-KR", { hour12: false, timeZone: "Asia/Seoul" }) + " KST"; }, 1000);
bootstrap();

async function bootstrap() {
  await checkHealth();
  try {
    const data = await api("/api/targets");
    targets = data.targets.map(item => [String(item.id), item.hostname, item.ip, item.checks.join(" + "), item.role, item.checks, item]);
    if (targets.length) state.targets.add(targets[0][0]);
  } catch (error) { toast(error.message); }
  render();
}

function switchView(view) { state.view = view; document.querySelectorAll("[data-view]").forEach(button => button.classList.toggle("active", button.dataset.view === view)); render(); }
async function render() { content.innerHTML = `<section class="loading"><i></i>화면을 준비하고 있습니다.</section>`; if (state.view === "run") renderRun(); else if (state.view === "targets") await renderTargets(); else if (state.view === "guide") await renderGuide(); else await renderResults(); }

function renderRun() {
  const selected = targets.filter(item => state.targets.has(item[0]));
  const scope = scopes[0];
  const count = checks.filter(item => state.checks.has(item[0])).reduce((sum, item) => sum + item[3], 0);
  content.innerHTML = `<section class="page-intro"><div><h2>주정통 보안 점검</h2><p>대상 장비와 점검 항목을 선택해 보안 점검을 실행합니다.</p></div></section>
  <div class="layout"><div class="stack">
    <section class="panel"><header><div><small>STEP 01</small><h3>점검 대상</h3><p>등록 장치를 선택하거나 이번 점검 대상을 직접 입력하세요.</p></div><div class="target-mode"><button data-target-mode="saved" class="${state.targetMode === "saved" ? "active" : ""}">등록 장치</button><button data-target-mode="direct" class="${state.targetMode === "direct" ? "active" : ""}">직접 입력</button></div></header>${state.targetMode === "saved" ? `<div class="selection"><b>${selected.length}</b> / ${targets.length}대 선택<i><span style="width:${selected.length * 100 / targets.length}%"></span></i></div><div class="target-actions"><button id="all">전체 선택</button><button id="clear">선택 해제</button></div><div class="targets">${targets.map(item => targetCard(item)).join("")}</div>` : directTargetForm()}</section>
    <section class="panel"><header><div><small>STEP 02</small><h3>점검 모듈</h3><p>실제 jjt/team_works 모듈 중 실행할 유형을 선택하세요.</p></div><button id="check-all">전체 선택</button></header><div class="checks">${checks.map(item => `<label class="${state.checks.has(item[0]) ? "selected" : ""}"><input data-check="${item[0]}" type="checkbox" ${state.checks.has(item[0]) ? "checked" : ""}><i>✓</i><span><b>${item[1]}</b><small>${item[2]}</small></span><strong>${item[3]}</strong></label>`).join("")}</div></section>
  </div><aside class="summary"><small>RUN SUMMARY</small><h3>실행 전 확인</h3><dl><dt>입력 방식</dt><dd>${state.targetMode === "saved" ? "등록 장치 선택" : "직접 입력"}</dd><dt>선택 장비</dt><dd><strong>${state.targetMode === "saved" ? selected.length : 1}</strong>대</dd><dt>대상 목록</dt><dd class="chips">${state.targetMode === "saved" ? (selected.map(item => `<span>${item[1]}</span>`).join("") || "선택 없음") : (escapeHtml(state.directTarget.hostname || state.directTarget.ip) || "입력 필요")}</dd><dt>점검 수준</dt><dd>${scope[1]}</dd><dt>선택 모듈 항목</dt><dd>${count}개</dd></dl><div class="warning"><b>실행 전 확인하세요.</b><span>직접 입력 정보는 DB 장치 목록에 저장하지 않고 이번 실행에만 사용합니다.</span></div><label class="confirm"><input id="confirm" type="checkbox" ${state.confirmed ? "checked" : ""}>대상과 점검 범위를 확인했습니다.</label><button id="submit" class="submit" ${!state.confirmed || (state.targetMode === "saved" && !selected.length) || !count ? "disabled" : ""}>점검 실행 요청<small>실제 장치에 즉시 접속합니다.</small></button><button id="go-results" class="secondary">점검 결과 확인 →</button></aside></div>`;
  bindRun();
}

function targetCard(item) { const selected = state.targets.has(item[0]); const status = item[6].ssh_status || "unknown"; return `<button data-target="${item[0]}" class="target ${selected ? "selected" : ""}" aria-pressed="${selected}"><i>${item[3].slice(0, 2)}</i><span><b>${item[1]}</b><small>${item[2]} · ${item[4]}</small></span><em class="connection ${status}">${selected ? "✓ 선택됨" : statusLabel(status)}</em></button>`; }
function directTargetForm() { const item=state.directTarget; return `<div class="direct-target"><div class="form-grid"><label>호스트명<input data-direct="hostname" value="${escapeHtml(item.hostname)}" placeholder="temporary-host"></label><label>IP 주소<input data-direct="ip" value="${escapeHtml(item.ip)}" placeholder="172.16.0.10"></label><label>SSH Port<input data-direct="port" type="number" min="1" max="65535" value="${item.port}"></label><label>사용자명<input data-direct="username" value="${escapeHtml(item.username)}"></label><label>비밀번호<input data-direct="password" type="password" value="${escapeHtml(item.password)}"></label><label>장치 역할<input data-direct="role" value="${escapeHtml(item.role)}" placeholder="server, network, db"></label><label>가상화 Platform<select data-direct="platform"><option value="">선택 안 함</option><option value="esxi" ${item.platform === "esxi" ? "selected" : ""}>ESXi</option><option value="xenserver" ${item.platform === "xenserver" ? "selected" : ""}>XenServer</option></select></label><label>Web 대상 경로<input data-direct="path" value="${escapeHtml(item.path)}" placeholder="/ 또는 Application 경로"></label></div><p>입력한 접속정보는 실행 요청에만 사용하며 접속장치 DB에는 등록하지 않습니다.</p></div>`; }
function bindRun() {
  document.querySelectorAll("[data-target-mode]").forEach(button => button.onclick = () => { captureDirectTarget(); state.targetMode = button.dataset.targetMode; state.confirmed = false; renderRun(); });
  document.querySelectorAll("[data-direct]").forEach(input => input.oninput = captureDirectTarget);
  document.querySelectorAll("[data-target]").forEach(button => button.addEventListener("click", () => { state.targets.has(button.dataset.target) ? state.targets.delete(button.dataset.target) : state.targets.add(button.dataset.target); state.confirmed = false; renderRun(); }));
  if (document.querySelector("#all")) document.querySelector("#all").onclick = () => { state.targets = new Set(targets.map(item => item[0])); state.confirmed = false; renderRun(); };
  if (document.querySelector("#clear")) document.querySelector("#clear").onclick = () => { state.targets.clear(); state.confirmed = false; renderRun(); };
  document.querySelectorAll("[data-check]").forEach(input => input.addEventListener("change", () => { input.checked ? state.checks.add(input.dataset.check) : state.checks.delete(input.dataset.check); state.confirmed = false; renderRun(); }));
  document.querySelector("#check-all").onclick = () => { state.checks = new Set(checks.map(item => item[0])); state.confirmed = false; renderRun(); };
  document.querySelector("#confirm").onchange = event => { state.confirmed = event.target.checked; renderRun(); };
  document.querySelector("#submit").onclick = startRun;
  document.querySelector("#go-results").onclick = () => switchView("results");
}

async function startRun() {
  const button = document.querySelector("#submit");
  button.disabled = true;
  try {
    captureDirectTarget();
    const payload = { targets: [...state.targets], checks: [...state.checks], confirm: "RUN" };
    if (state.targetMode === "direct") { payload.targets = []; payload.direct_target = state.directTarget; }
    const data = await api("/api/jobs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    toast(`점검 작업 ${data.job.id}을 시작했습니다.`);
    showJob(data.job);
    pollJob();
  } catch (error) { toast(error.message); button.disabled = false; }
}
function captureDirectTarget() { document.querySelectorAll("[data-direct]").forEach(input => { state.directTarget[input.dataset.direct] = input.type === "number" ? Number(input.value) : input.value; }); }

async function pollJob() {
  const data = await api("/api/jobs/current");
  if (!data.job) return;
  showJob(data.job);
  if (["queued", "running"].includes(data.job.status)) setTimeout(pollJob, 2000);
}

function showJob(job) {
  const summary = document.querySelector(".summary");
  if (!summary) return;
  const percent = Math.round(job.completed * 100 / Math.max(job.total, 1));
  summary.innerHTML = `<small>LIVE EXECUTION</small><h3>${job.status === "running" ? "점검 실행 중" : job.status === "queued" ? "실행 준비 중" : "점검 완료"}</h3><dl><dt>작업 ID</dt><dd>${job.id}</dd><dt>진행</dt><dd><strong>${job.completed}</strong> / ${job.total}대</dd><dt>상태</dt><dd>${job.status}</dd></dl><div class="selection"><b>${percent}%</b><i><span style="width:${percent}%"></span></i></div>${job.results.map(item => `<div class="job-result"><b>${escapeHtml(item.hostname)}</b><span>${item.ok ? "완료" : "실패"} · ${Number(item.elapsed || 0).toFixed(1)}초</span><small>${escapeHtml((item.log || []).slice(-2).join(" · "))}</small></div>`).join("")}<button id="go-results" class="secondary">점검 결과 확인 →</button>`;
  document.querySelector("#go-results").onclick = () => switchView("results");
}

async function reloadTargets() {
  const data = await api("/api/targets");
  targets = data.targets.map(item => [String(item.id), item.hostname, item.ip, item.checks.join(" + "), item.role, item.checks, item]);
}

async function renderTargets() {
  await reloadTargets();
  const editing = state.editingTarget ? targets.find(item => item[0] === String(state.editingTarget))?.[6] : null;
  content.innerHTML = `<section class="result-head"><div><small>CONNECTION INVENTORY</small><h2>접속장치 관리</h2><p>점검 대상의 접속정보를 DB에서 생성·변경·제거하고 SSH 연결 상태를 확인합니다.</p></div><button id="new-target">새 장치 추가</button></section>
  <section class="device-layout"><div class="device-list">${targets.map(item => deviceRow(item[6])).join("") || `<div class="empty">등록된 장치가 없습니다.</div>`}</div><aside class="device-form">${targetForm(editing)}</aside></section>`;
  bindTargetManager();
}

async function renderGuide() {
  const data = await api("/api/check-catalog");
  content.innerHTML = `<section class="result-head"><div><small>CHECK REFERENCE</small><h2>주정통 검사항목 안내</h2><p>실제 점검 엔진에 등록된 코드와 항목명을 자산 유형별로 확인합니다.</p></div><span>총 ${data.types.reduce((sum, item) => sum + item.count, 0)}개 항목</span></section><section class="guide-tabs">${data.types.map((type, index) => `<button data-guide="${type.id}" class="${index === 0 ? "active" : ""}"><b>${type.label}</b><span>${type.count}개</span></button>`).join("")}</section><section id="guide-content"></section>`;
  const show = id => {
    const type = data.types.find(item => item.id === id);
    document.querySelectorAll("[data-guide]").forEach(button => button.classList.toggle("active", button.dataset.guide === id));
    document.querySelector("#guide-content").innerHTML = `<header class="guide-head"><div><small>${type.id.toUpperCase()}</small><h3>${type.label}</h3><p>항목을 누르면 실제 점검 기준과 실행 정보를 확인할 수 있습니다.</p></div><strong>${type.count}</strong></header><div class="guide-list">${type.items.map(item => `<article class="guide-item"><button class="guide-summary" aria-expanded="false"><b>${escapeHtml(item.code)}</b><span>${escapeHtml(item.title)}</span><i>＋</i></button><div class="guide-detail"><dl><dt>점검 기준</dt><dd>${escapeHtml(item.criterion)}</dd><dt>판정 방식</dt><dd>대상 장비에서 설정값을 수집해 양호·취약·검토필요·해당없음 중 하나로 판정합니다.</dd><dt>실행 함수</dt><dd><code>${escapeHtml(item.method)}</code></dd></dl></div></article>`).join("")}</div>`;
    document.querySelectorAll(".guide-summary").forEach(button => button.onclick = () => { const item = button.closest(".guide-item"); const open = item.classList.toggle("open"); button.setAttribute("aria-expanded", open); button.querySelector("i").textContent = open ? "−" : "＋"; });
  };
  document.querySelectorAll("[data-guide]").forEach(button => button.onclick = () => show(button.dataset.guide));
  if (data.types.length) show(data.types[0].id);
}

function deviceRow(item) {
  return `<article><i class="device-state ${item.ssh_status || "unknown"}"></i><div><b>${escapeHtml(item.hostname)}</b><span>${escapeHtml(item.ip)}:${item.port} · ${escapeHtml(item.role || "미분류")}</span><small>${item.checks.map(labelCheck).join(" · ")}</small></div><div class="device-health"><strong>${statusLabel(item.ssh_status)}</strong><small>${escapeHtml(item.ssh_message || "아직 연결을 확인하지 않았습니다.")}</small><time>${time(item.ssh_checked_at)}</time></div><div class="device-actions"><button data-probe="${item.id}">연결 확인</button><button data-edit="${item.id}">변경</button><button data-delete="${item.id}" class="danger-button">제거</button></div></article>`;
}

function targetForm(item) {
  const selected = new Set(item?.checks || ["unix"]);
  return `<small>${item ? "EDIT TARGET" : "NEW TARGET"}</small><h3>${item ? "접속장치 변경" : "새 접속장치"}</h3><form id="target-form"><div class="form-grid"><label>호스트명<input name="hostname" required value="${escapeHtml(item?.hostname || "")}"></label><label>IP 주소<input name="ip" required value="${escapeHtml(item?.ip || "")}"></label><label>역할<input name="role" value="${escapeHtml(item?.role || "")}" placeholder="client, db, hypervisor"></label><label>Port<input name="port" type="number" min="1" max="65535" value="${item?.port || 22}"></label><label>사용자명<input name="username" required value="${escapeHtml(item?.username || "")}"></label><label>비밀번호<input name="password" type="password" ${item ? "" : "required"} placeholder="${item ? "변경할 때만 입력" : "접속 비밀번호"}"></label></div><fieldset><legend>점검 유형</legend>${checks.map(check => `<label><input type="checkbox" name="checks" value="${check[0]}" ${selected.has(check[0]) ? "checked" : ""}>${check[1]}</label>`).join("")}</fieldset><label class="extra-field">추가 설정 JSON<textarea name="extra" rows="5">${escapeHtml(JSON.stringify(item?.extra || {}, null, 2))}</textarea></label><label class="enabled-field"><input name="enabled" type="checkbox" ${item?.enabled !== false ? "checked" : ""}>점검 대상으로 사용</label><div class="form-actions"><button type="submit" class="save-button">${item ? "변경 저장" : "장치 생성"}</button>${item ? `<button type="button" id="cancel-edit">취소</button>` : ""}</div></form>`;
}

function bindTargetManager() {
  document.querySelector("#new-target").onclick = () => { state.editingTarget = null; renderTargets(); };
  document.querySelectorAll("[data-edit]").forEach(button => button.onclick = () => { state.editingTarget = button.dataset.edit; renderTargets(); });
  document.querySelectorAll("[data-probe]").forEach(button => button.onclick = async () => { button.disabled = true; button.textContent = "확인 중"; try { const data = await api(`/api/targets/${button.dataset.probe}/probe`, { method: "POST" }); toast(data.target.ssh_message); await renderTargets(); } catch (error) { toast(error.message); button.disabled = false; } });
  document.querySelectorAll("[data-delete]").forEach(button => button.onclick = async () => { if (!confirm("이 접속장치를 제거할까요? 기존 점검 결과는 유지됩니다.")) return; await api(`/api/targets/${button.dataset.delete}`, { method: "DELETE" }); state.editingTarget = null; toast("장치를 제거했습니다."); await renderTargets(); });
  document.querySelector("#cancel-edit")?.addEventListener("click", () => { state.editingTarget = null; renderTargets(); });
  document.querySelector("#target-form").onsubmit = saveTarget;
}

async function saveTarget(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  let extra;
  try { extra = JSON.parse(form.get("extra") || "{}"); } catch (_) { return toast("추가 설정 JSON 형식을 확인하세요."); }
  const body = { hostname: form.get("hostname"), ip: form.get("ip"), role: form.get("role"), port: Number(form.get("port")), username: form.get("username"), password: form.get("password"), checks: form.getAll("checks"), extra, enabled: form.has("enabled") };
  const url = state.editingTarget ? `/api/targets/${state.editingTarget}` : "/api/targets";
  await api(url, { method: state.editingTarget ? "PUT" : "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  state.editingTarget = null; toast("접속장치 정보를 저장했습니다."); await renderTargets();
}

async function renderResults() {
  try {
    await reloadTargets();
    const overview = await api("/api/overview");
    if (!overview.available) return renderUnavailable(overview);
    const rows = await api(`/api/results/by-date?page_size=${state.pageSize}`);
    const runs = groupResultRuns(rows.rows);
    if (state.resultRun >= runs.length) state.resultRun = 0;
    const selectedRun = runs[state.resultRun];
    const devices = selectedRun ? [...new Set(selectedRun.rows.map(row => row.ip))] : [];
    if (!devices.includes(state.resultDevice)) state.resultDevice = devices[0] || "";
    const rawDetailRows = selectedRun ? selectedRun.rows.filter(row => row.ip === state.resultDevice) : [];
    const detailRows = filterSortResults(rawDetailRows);
    const metrics = overview.metrics;
    const counts = selectedRun ? countStatuses(selectedRun.rows) : {};
    content.innerHTML = `<section class="result-head"><div><small>COMPLIANCE RUNS</small><h2>점검 결과</h2><p>실행 일시를 선택하고 장치별 상세 판정 결과를 확인합니다.</p></div><span>최근 ${time(overview.last_checked)}</span></section><section class="run-overview"><div><small>SELECTED RUN</small><h3>${selectedRun ? time(selectedRun.startedAt) : "실행 기록 없음"}</h3><p>${devices.length}대 장치 · ${selectedRun?.rows.length || 0}개 항목</p></div>${metric("양호", counts["양호"] || 0, "success")}${metric("취약", counts["취약"] || 0, "danger")}${metric("검토·오류", (counts["검토필요"] || 0) + (counts["오류"] || 0), "warning")}${metric("해당없음", counts["해당없음"] || 0)}</section><section class="panel run-panel"><header><div><small>RUN HISTORY</small><h3>실행 일시</h3><p>1회 실행 단위로 묶은 점검 기록입니다.</p></div><span>${runs.length}회</span></header><div class="run-tabs">${runs.map((run, index) => `<button data-run="${index}" class="${state.resultRun === index ? "active" : ""}"><b>${time(run.startedAt)}</b><span>${new Set(run.rows.map(row => row.ip)).size}대 · ${run.rows.length}건</span></button>`).join("")}</div><header class="device-result-head"><div><small>DEVICES</small><h3>점검 장치</h3></div><span>${devices.length}대</span></header><div class="result-devices">${devices.map(ip => { const device = targets.find(item => item[2] === ip); const deviceRows = selectedRun.rows.filter(row => row.ip === ip); const deviceCounts = countStatuses(deviceRows); return `<button data-result-device="${escapeHtml(ip)}" class="${state.resultDevice === ip ? "active" : ""}"><b>${escapeHtml(device?.[1] || ip)}</b><span>${escapeHtml(ip)} · ${deviceRows.length}개</span><small>취약 ${deviceCounts["취약"] || 0} · 검토 ${(deviceCounts["검토필요"] || 0) + (deviceCounts["오류"] || 0)}</small></button>`; }).join("")}</div><div class="device-detail-title"><div><small>DEVICE DETAIL</small><h3>${escapeHtml(targets.find(item => item[2] === state.resultDevice)?.[1] || state.resultDevice || "장치를 선택하세요")}</h3></div><span>${detailRows.length} / ${rawDetailRows.length}건</span></div><div class="result-tools"><select id="detail-type"><option value="">전체 유형</option>${[...new Map(rawDetailRows.map(row => [row.asset_type,row.asset_label])).entries()].map(([id,label]) => `<option value="${id}" ${state.type === id ? "selected" : ""}>${escapeHtml(label)}</option>`).join("")}</select><select id="detail-status"><option value="">전체 판정</option>${["양호","취약","검토필요","해당없음","오류"].map(value => `<option ${state.status === value ? "selected" : ""}>${value}</option>`).join("")}</select><input id="detail-query" value="${escapeHtml(state.query)}" placeholder="코드·항목·판정 사유 검색"><button id="detail-apply">필터 적용</button><button id="detail-reset">초기화</button></div>${historyTable(detailRows)}</section>`;
    document.querySelectorAll("[data-run]").forEach(button => button.onclick = () => { state.resultRun = Number(button.dataset.run); state.resultDevice = ""; renderResults(); });
    document.querySelectorAll("[data-result-device]").forEach(button => button.onclick = () => { state.resultDevice = button.dataset.resultDevice; renderResults(); });
    document.querySelector("#detail-apply").onclick = () => { state.type = document.querySelector("#detail-type").value; state.status = document.querySelector("#detail-status").value; state.query = document.querySelector("#detail-query").value.trim(); renderResults(); };
    document.querySelector("#detail-reset").onclick = () => { state.type = ""; state.status = ""; state.query = ""; state.resultSort = "observed_at"; state.resultOrder = "desc"; renderResults(); };
    document.querySelectorAll("[data-sort]").forEach(button => button.onclick = event => { event.stopPropagation(); const field = button.dataset.sort; state.resultOrder = state.resultSort === field && state.resultOrder === "asc" ? "desc" : "asc"; state.resultSort = field; renderResults(); });
    bindResultDetails();
  } catch (error) { content.innerHTML = `<section class="error"><b>결과를 불러오지 못했습니다.</b><span>${escapeHtml(error.message)}</span></section>`; }
}

function renderUnavailable(data) { content.innerHTML = `<section class="waiting"><div><small>COMPLIANCE READY</small><h2>결과 DB 연결을 기다리고 있습니다.</h2><p>${escapeHtml(data.message)}</p><button id="back-run">점검 실행 화면으로</button></div><aside><i></i><span>연결 대기</span><b>${escapeHtml(data.database.database || "jjt_db")}</b></aside></section>`; document.querySelector("#back-run").onclick = () => switchView("run"); }
function metric(label, value, tone = "") { return `<article class="${tone}"><span>${label}</span><b>${value}</b></article>`; }
function table(rows) { if (!rows.length) return `<div class="empty">선택 조건에 맞는 점검 결과가 없습니다.</div>`; return `<div class="table"><table><thead><tr><th>점검일</th><th>IP</th><th>코드</th><th>상태</th><th>점검 항목</th><th>판정 사유</th></tr></thead><tbody>${rows.map(row => `<tr><td>${time(row.check_date)}</td><td>${escapeHtml(row.ip)}</td><td>${escapeHtml(row.code)}</td><td><span class="pill ${row.status === "취약" ? "danger" : row.status === "양호" ? "success" : "warning"}">${escapeHtml(row.status)}</span></td><td>${escapeHtml(row.title)}</td><td>${escapeHtml(row.reason)}</td></tr>`).join("")}</tbody></table></div>`; }
function historyTable(rows) { if (!rows.length) return `<div class="empty">조건에 맞는 점검 결과가 없습니다.</div>`; const head = (field,label) => `<button data-sort="${field}">${label}${state.resultSort === field ? (state.resultOrder === "asc" ? " ↑" : " ↓") : " ↕"}</button>`; return `<div class="result-sheet"><table><thead><tr><th>${head("observed_at","점검 시각")}</th><th>${head("asset_label","점검 유형")}</th><th>${head("code","코드")}</th><th>${head("title","점검 항목")}</th><th>${head("status","판정")}</th><th>상세</th></tr></thead><tbody>${rows.map((row, index) => `<tr class="result-summary" data-result="${index}" tabindex="0" aria-expanded="false"><td>${time(row.observed_at)}</td><td>${escapeHtml(row.asset_label)}</td><td><b>${escapeHtml(row.code)}</b></td><td><strong>${escapeHtml(row.title)}</strong></td><td><i class="pill ${row.status === "취약" ? "danger" : row.status === "양호" ? "success" : "warning"}">${escapeHtml(row.status)}</i></td><td><button class="row-toggle" aria-label="상세 결과 펼치기">＋</button></td></tr><tr class="result-detail"><td colspan="6"><table class="detail-sheet"><tbody><tr><th>대상 장치</th><td>${escapeHtml(row.ip)}</td><th>점검 유형</th><td>${escapeHtml(row.asset_label)}</td></tr><tr><th>결과 구분</th><td>${row.record_kind === "current" ? "현재 결과" : "변경 이력"}</td><th>점검 코드</th><td>${escapeHtml(row.code)}</td></tr><tr><th>점검 항목</th><td colspan="3">${escapeHtml(row.title)}</td></tr><tr><th>판정 사유</th><td colspan="3">${escapeHtml(row.reason || "판정 사유가 기록되지 않았습니다.")}</td></tr><tr><th>점검 시각</th><td colspan="3">${time(row.observed_at)}</td></tr></tbody></table></td></tr>`).join("")}</tbody></table></div>`; }
function bindResultDetails() { document.querySelectorAll(".result-summary").forEach(row => { const toggle = () => { const open = row.classList.toggle("open"); row.setAttribute("aria-expanded", open); row.nextElementSibling.classList.toggle("open", open); row.querySelector(".row-toggle").textContent = open ? "−" : "＋"; }; row.onclick = toggle; row.onkeydown = event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); toggle(); } }; }); }
function groupResultRuns(rows) { const sorted = [...rows].sort((a, b) => new Date(b.observed_at) - new Date(a.observed_at)); const runs = []; sorted.forEach(row => { const stamp = new Date(row.observed_at); const current = runs[runs.length - 1]; if (!current || Math.abs(current.earliest - stamp) > 60000) runs.push({ startedAt: row.observed_at, earliest: stamp, rows: [row] }); else { current.rows.push(row); current.earliest = stamp; } }); return runs; }
function countStatuses(rows) { return rows.reduce((counts, row) => { counts[row.status] = (counts[row.status] || 0) + 1; return counts; }, {}); }
function filterSortResults(rows) { const q = state.query.toLowerCase(); const filtered = rows.filter(row => (!state.type || row.asset_type === state.type) && (!state.status || row.status === state.status) && (!q || [row.code,row.title,row.reason,row.asset_label].some(value => String(value || "").toLowerCase().includes(q)))); return filtered.sort((a,b) => { const left = state.resultSort === "observed_at" ? new Date(a.observed_at).getTime() : String(a[state.resultSort] || ""); const right = state.resultSort === "observed_at" ? new Date(b.observed_at).getTime() : String(b[state.resultSort] || ""); const result = typeof left === "number" ? left-right : left.localeCompare(right,"ko"); return state.resultOrder === "asc" ? result : -result; }); }
async function checkHealth() { try { const data = await api("/api/health"); document.querySelector("#db-state").textContent = data.database.available ? "DB CONNECTED" : "DB WAITING"; document.querySelector("#db-dot").className = data.database.available ? "ok" : ""; } catch (_) { document.querySelector("#db-state").textContent = "DB OFFLINE"; } }
async function api(url, options = {}) { const response = await fetch(url, options); const data = await response.json(); if (!response.ok) throw new Error(data.error || "요청 실패"); return data; }
function query(values) { return new URLSearchParams(Object.entries(values).filter(([, value]) => value !== "")).toString(); }
function time(value) { if (!value) return "—"; return new Date(value).toLocaleString("ko-KR", { timeZone: "Asia/Seoul", hour12: false }) + " KST"; }
function escapeHtml(value) { return String(value ?? "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]); }
function toast(message) { const node = document.querySelector("#toast"); node.textContent = message; node.classList.add("show"); setTimeout(() => node.classList.remove("show"), 2600); }
function labelCheck(value) { return checks.find(item => item[0] === value)?.[1] || value; }
function statusLabel(value) { return ({ connected: "SSH 정상", reachable: "Port 정상", auth_failed: "인증 실패", unreachable: "연결 실패", unknown: "미확인" })[value] || "미확인"; }
