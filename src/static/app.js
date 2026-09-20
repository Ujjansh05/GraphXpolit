(() => {
  const $ = (id) => document.getElementById(id);
  const root = $("root"), target = $("target"), mode = $("mode"), scan = $("scan"), cancel = $("cancel"), query = $("query"), status = $("status"), scanResult = $("scan-result"), message = $("message"), results = $("results"), source = $("source");
  root.value = window.GRAPHXPLOIT_ROOT || "";
  let activeJob = null;
  const request = async (path, body) => {
    const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", "X-GraphXploit-Token": window.GRAPHXPLOIT_TOKEN }, body: JSON.stringify(body) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Request failed");
    return data;
  };
  const setStatus = (value) => { status.textContent = value; };
  async function pollJob() {
    if (!activeJob) return;
    const response = await fetch(`/api/v1/jobs/${encodeURIComponent(activeJob)}`, { headers: { "X-GraphXploit-Token": window.GRAPHXPLOIT_TOKEN } });
    const data = await response.json();
    if (!response.ok) { setStatus(data.error || "Job failed"); return; }
    if (data.status === "running") { setTimeout(pollJob, 300); return; }
    cancel.disabled = true; scan.disabled = false; activeJob = null; setStatus(data.status);
    scanResult.classList.remove("hidden");
    scanResult.textContent = data.error || (data.summary ? `${data.summary.files_seen} files seen\n${data.summary.files_parsed} parsed, ${data.summary.files_skipped} unchanged\n${data.summary.symbols} symbols, ${data.summary.relationships} relationships\nIndex: ${data.summary.database}` : "Scan ended.");
  }
  async function showSource(item) {
    try {
      source.classList.remove("hidden"); source.textContent = "Loading source excerpt…";
      const startLine = Math.max(1, (item.line || 1) - 4);
      const data = await request("/api/v1/source", { root: root.value.trim(), path: item.path, start_line: startLine, end_line: startLine + 16 });
      source.textContent = data.content || "No source text is available for this symbol.";
    } catch (error) { source.textContent = error.message; }
  }
  scan.addEventListener("click", async () => {
    try { scan.disabled = true; cancel.disabled = false; setStatus("Scanning"); scanResult.classList.add("hidden"); const data = await request("/api/v1/scan", { root: root.value.trim() }); activeJob = data.id; pollJob(); }
    catch (error) { scan.disabled = false; cancel.disabled = true; setStatus("Ready"); scanResult.classList.remove("hidden"); scanResult.textContent = error.message; }
  });
  cancel.addEventListener("click", async () => { if (activeJob) { await request(`/api/v1/jobs/${encodeURIComponent(activeJob)}/cancel`, {}); setStatus("Cancelling"); } });
  query.addEventListener("click", async () => {
    try {
      if (!root.value.trim() || !target.value.trim()) throw new Error("Enter both a project directory and a target.");
      query.disabled = true; results.innerHTML = ""; message.textContent = "Analyzing indexed relationships…";
      const data = await request(`/api/v1/${mode.value}`, { root: root.value.trim(), target: target.value.trim(), depth: 5 });
      message.textContent = data.message || `${data.results.length} result${data.results.length === 1 ? "" : "s"}${data.complete ? "" : " (partial due to limit)"}.`;
      const shown = data.candidates && data.candidates.length ? data.candidates : data.results;
      for (const item of shown) {
        const entry = document.createElement("article"); entry.className = "result"; entry.tabIndex = 0;
        entry.title = "Open read-only source excerpt";
        entry.addEventListener("click", () => showSource(item));
        entry.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") { event.preventDefault(); showSource(item); }
        });
        const title = document.createElement("div"); title.className = "title"; title.textContent = item.qualified_name; entry.append(title);
        const meta = document.createElement("div"); meta.className = "meta"; meta.textContent = `${item.kind} · ${item.path}:${item.line}`; entry.append(meta);
        if (item.evidence_path && item.evidence_path.length > 1) { const path = document.createElement("div"); path.className = "path"; path.textContent = item.evidence_path.join(" → "); entry.append(path); }
        results.append(entry);
      }
    } catch (error) { message.textContent = error.message; }
    finally { query.disabled = false; }
  });
})();
