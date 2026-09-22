(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const els = {
    root: $("root"), scan: $("scan"), cancel: $("cancel"), status: $("status"),
    scanResult: $("scan-result"), edition: $("edition"), target: $("target"),
    search: $("search"), searchResults: $("search-results"), direction: $("direction"),
    depth: $("depth"), graph: $("graph"), graphMessage: $("graph-message"),
    svg: $("graph-svg"), viewport: $("viewport"), edges: $("edges"), nodes: $("nodes"),
    graphWrap: $("graph-wrap"), inspectorMeta: $("inspector-meta"), source: $("source"),
    gitMode: $("git-mode"), gitBase: $("git-base"), gitAnalyze: $("git-analyze"),
    gitMessage: $("git-message"), gitResults: $("git-results"), question: $("question"),
    chatTarget: $("chat-target"), budget: $("token-budget"), budgetLabel: $("token-budget-label"),
    preview: $("preview"), chatMessage: $("chat-message"), previewBox: $("preview-box"),
    previewSummary: $("preview-summary"), evidence: $("evidence"), selectAll: $("select-all"),
    copyContext: $("copy-context"), approve: $("approve-check"), ask: $("ask"),
    answer: $("answer"), answerText: $("answer-text"), answerMeta: $("answer-meta")
  };
  const state = {
    job: null, capabilities: null, preview: null,
    transform: { x: 0, y: 0, scale: 1 }, dragging: null
  };
  const SVG_NS = "http://www.w3.org/2000/svg";
  els.root.value = window.GRAPHXPLOIT_ROOT || "";

  function setStatus(text) { els.status.textContent = text; }
  function setMessage(element, text, error) {
    element.textContent = text || "";
    element.classList.toggle("error", Boolean(error));
  }
  function api(path, body, method) {
    const options = {
      method: method || "POST",
      headers: { "X-GraphXploit-Token": window.GRAPHXPLOIT_TOKEN }
    };
    if (body !== undefined) {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    return fetch(path, options).then(async (response) => {
      const data = await response.json().catch(() => ({ error: "Invalid local server response." }));
      if (!response.ok) throw new Error(data.error || "Request failed.");
      return data;
    });
  }
  function rootValue() {
    const value = els.root.value.trim();
    if (!value) throw new Error("Choose a project directory first.");
    return value;
  }
  function clear(element) { element.replaceChildren(); }
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((item) => item.classList.toggle("active", item === tab));
      document.querySelectorAll(".panel").forEach((panel) => panel.classList.add("hidden"));
      $(tab.dataset.panel + "-panel").classList.remove("hidden");
    });
  });

  async function loadCapabilities() {
    try {
      state.capabilities = await api("/api/v1/capabilities", undefined, "GET");
      els.edition.textContent = "v2.1 " + state.capabilities.edition;
      if (!state.capabilities.ai_enabled) {
        els.ask.textContent = "AI edition required";
        els.chatMessage.textContent = "Lite edition builds and exports compact local context. Install the AI archive to send approved evidence to an OpenAI-compatible endpoint.";
      }
    } catch (error) {
      els.edition.textContent = "Offline";
      setMessage(els.chatMessage, error.message, true);
    }
  }

  async function pollJob() {
    if (!state.job) return;
    try {
      const data = await api("/api/v1/jobs/" + encodeURIComponent(state.job), undefined, "GET");
      if (data.status === "running") {
        window.setTimeout(pollJob, 350);
        return;
      }
      state.job = null;
      els.scan.disabled = false;
      els.cancel.disabled = true;
      setStatus(data.status);
      els.scanResult.classList.remove("hidden");
      if (data.error) {
        els.scanResult.textContent = data.error;
      } else if (data.summary) {
        const s = data.summary;
        els.scanResult.textContent =
          s.files_seen + " files seen · " + s.files_parsed + " parsed · " + s.files_skipped +
          " unchanged\n" + s.symbols + " symbols · " + s.relationships +
          " relationships · generation " + s.generation + "\nIndex: " + s.database;
      }
    } catch (error) {
      state.job = null;
      els.scan.disabled = false;
      els.cancel.disabled = true;
      setStatus("Scan failed");
      els.scanResult.classList.remove("hidden");
      els.scanResult.textContent = error.message;
    }
  }

  els.scan.addEventListener("click", async () => {
    try {
      els.scan.disabled = true;
      els.cancel.disabled = false;
      els.scanResult.classList.add("hidden");
      setStatus("Scanning");
      const data = await api("/api/v1/scan", { root: rootValue(), verify: false });
      state.job = data.id;
      pollJob();
    } catch (error) {
      els.scan.disabled = false;
      els.cancel.disabled = true;
      setStatus("Ready");
      els.scanResult.classList.remove("hidden");
      els.scanResult.textContent = error.message;
    }
  });
  els.cancel.addEventListener("click", async () => {
    if (!state.job) return;
    try {
      await api("/api/v1/jobs/" + encodeURIComponent(state.job) + "/cancel", {});
      setStatus("Cancelling");
    } catch (error) {
      setStatus(error.message);
    }
  });

  function chooseTarget(item) {
    els.target.value = item.qualified_name;
    els.searchResults.classList.add("hidden");
    showSource(item);
  }
  function renderSearch(data) {
    clear(els.searchResults);
    if (!data.items.length) {
      els.searchResults.append(el("span", "muted", "No indexed symbols matched."));
    }
    data.items.forEach((item) => {
      const button = el("button", "suggestion");
      button.type = "button";
      button.append(el("span", "", item.qualified_name));
      button.append(el("small", "", item.kind + " · " + item.path + ":" + item.line));
      button.addEventListener("click", () => chooseTarget(item));
      els.searchResults.append(button);
    });
    els.searchResults.classList.remove("hidden");
  }
  els.search.addEventListener("click", async () => {
    try {
      const query = els.target.value.trim();
      if (!query) throw new Error("Enter a symbol or filename to search.");
      setMessage(els.graphMessage, "Searching local index…");
      renderSearch(await api("/api/v1/search", { root: rootValue(), query: query, limit: 25 }));
      setMessage(els.graphMessage, "Choose a result or visualize an exact target.");
    } catch (error) {
      setMessage(els.graphMessage, error.message, true);
    }
  });
  els.target.addEventListener("keydown", (event) => {
    if (event.key === "Enter") els.search.click();
  });

  async function showSource(item) {
    try {
      els.inspectorMeta.textContent = item.kind + " · " + item.path + ":" + item.line;
      els.source.classList.remove("hidden");
      els.source.textContent = "Loading source excerpt…";
      const start = Math.max(1, (item.line || 1) - 4);
      const data = await api("/api/v1/source", {
        root: rootValue(), path: item.path, start_line: start, end_line: start + 24
      });
      els.source.textContent = data.content || "No source excerpt is available.";
    } catch (error) {
      els.source.textContent = error.message;
    }
  }

  function svgNode(name, attrs) {
    const node = document.createElementNS(SVG_NS, name);
    Object.keys(attrs || {}).forEach((key) => node.setAttribute(key, String(attrs[key])));
    return node;
  }
  function shortText(value, length) {
    return value.length > length ? value.slice(0, length - 1) + "…" : value;
  }
  function applyTransform() {
    const t = state.transform;
    els.viewport.setAttribute("transform", "translate(" + t.x + " " + t.y + ") scale(" + t.scale + ")");
  }
  function renderGraph(data) {
    clear(els.edges);
    clear(els.nodes);
    if (!data.nodes.length) {
      setMessage(els.graphMessage, data.message || "Target is ambiguous or has no indexed graph. Use Search to select a qualified name.", true);
      return;
    }
    const byDepth = new Map();
    data.nodes.forEach((node) => {
      const depth = Number(node.depth) || 0;
      if (!byDepth.has(depth)) byDepth.set(depth, []);
      byDepth.get(depth).push(node);
    });
    const maxRows = Math.max.apply(null, Array.from(byDepth.values()).map((items) => items.length));
    const width = Math.max(1000, (Math.max.apply(null, Array.from(byDepth.keys())) + 1) * 240 + 180);
    const height = Math.max(600, maxRows * 92 + 80);
    els.svg.setAttribute("viewBox", "0 0 " + width + " " + height);
    const positions = new Map();
    byDepth.forEach((items, depth) => {
      const gap = height / (items.length + 1);
      items.forEach((node, index) => positions.set(node.id, { x: 60 + depth * 240, y: gap * (index + 1) - 31 }));
    });
    const defs = svgNode("defs");
    const marker = svgNode("marker", { id: "arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" });
    marker.append(svgNode("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: "#50667b" }));
    defs.append(marker);
    els.edges.append(defs);
    data.edges.forEach((edge) => {
      const a = positions.get(edge.source), b = positions.get(edge.target);
      if (!a || !b) return;
      const line = svgNode("path", {
        d: "M " + (a.x + 170) + " " + (a.y + 31) + " C " + (a.x + 205) + " " + (a.y + 31) + ", " + (b.x - 35) + " " + (b.y + 31) + ", " + b.x + " " + (b.y + 31),
        class: "graph-edge"
      });
      const title = svgNode("title");
      title.textContent = edge.kind;
      line.append(title);
      els.edges.append(line);
    });
    data.nodes.forEach((item) => {
      const p = positions.get(item.id);
      const group = svgNode("g", { class: "graph-node" + (item.selected ? " selected" : ""), transform: "translate(" + p.x + " " + p.y + ")", tabindex: "0", role: "button" });
      group.append(svgNode("rect", { width: 170, height: 62 }));
      const title = svgNode("text", { x: 10, y: 25 });
      title.textContent = shortText(item.label || item.id, 24);
      const kind = svgNode("text", { x: 10, y: 45, class: "node-kind" });
      kind.textContent = shortText(item.kind + " · " + item.path, 29);
      const tooltip = svgNode("title");
      tooltip.textContent = item.id + "\n" + item.path + ":" + item.line;
      group.append(title, kind, tooltip);
      group.addEventListener("click", () => showSource(item));
      group.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          showSource(item);
        }
      });
      els.nodes.append(group);
    });
    state.transform = { x: 0, y: 0, scale: 1 };
    applyTransform();
    setMessage(els.graphMessage, (data.message || (data.nodes.length + " nodes · " + data.edges.length + " relationships")) + (data.complete ? "" : " · partial result"));
  }

  els.graph.addEventListener("click", async () => {
    try {
      const target = els.target.value.trim();
      if (!target) throw new Error("Choose a target symbol first.");
      els.graph.disabled = true;
      setMessage(els.graphMessage, "Building bounded local graph…");
      const data = await api("/api/v1/graph", {
        root: rootValue(),
        target: target,
        depth: Number(els.depth.value) || 4,
        reverse: els.direction.value === "impact"
      });
      renderGraph(data);
    } catch (error) {
      setMessage(els.graphMessage, error.message, true);
    } finally {
      els.graph.disabled = false;
    }
  });

  els.graphWrap.addEventListener("wheel", (event) => {
    event.preventDefault();
    const factor = event.deltaY < 0 ? 1.1 : 0.9;
    state.transform.scale = Math.min(2.5, Math.max(0.35, state.transform.scale * factor));
    applyTransform();
  }, { passive: false });
  els.graphWrap.addEventListener("pointerdown", (event) => {
    state.dragging = { x: event.clientX, y: event.clientY, tx: state.transform.x, ty: state.transform.y };
    els.graphWrap.classList.add("dragging");
    els.graphWrap.setPointerCapture(event.pointerId);
  });
  els.graphWrap.addEventListener("pointermove", (event) => {
    if (!state.dragging) return;
    state.transform.x = state.dragging.tx + (event.clientX - state.dragging.x);
    state.transform.y = state.dragging.ty + (event.clientY - state.dragging.y);
    applyTransform();
  });
  const endDrag = () => { state.dragging = null; els.graphWrap.classList.remove("dragging"); };
  els.graphWrap.addEventListener("pointerup", endDrag);
  els.graphWrap.addEventListener("pointercancel", endDrag);

  els.gitMode.addEventListener("change", () => {
    els.gitBase.disabled = els.gitMode.value !== "branch";
  });
  els.gitMode.dispatchEvent(new Event("change"));
  els.gitAnalyze.addEventListener("click", async () => {
    clear(els.gitResults);
    try {
      els.gitAnalyze.disabled = true;
      setMessage(els.gitMessage, "Reading bounded Git diff and mapping changed lines…");
      const data = await api("/api/v1/git-impact", {
        root: rootValue(), mode: els.gitMode.value, base: els.gitBase.value.trim() || "main"
      });
      setMessage(els.gitMessage, data.message || (data.changes.length + " changed indexed symbols") + (data.complete ? "" : " · partial result"));
      data.changes.forEach((change) => {
        const details = el("details", "result");
        const summary = el("summary", "", change.qualified_name);
        details.append(summary, el("div", "meta", change.status + " · " + change.kind + " · " + change.path + ":" + change.line));
        if (change.affected.length) {
          const list = el("ul", "impact-list");
          change.affected.forEach((item) => {
            const row = el("li", "", item.qualified_name + " — " + item.relationship);
            row.addEventListener("click", () => showSource(item));
            list.append(row);
          });
          details.append(list);
        } else {
          details.append(el("p", "muted", "No indexed dependants found."));
        }
        els.gitResults.append(details);
      });
    } catch (error) {
      setMessage(els.gitMessage, error.message, true);
    } finally {
      els.gitAnalyze.disabled = false;
    }
  });

  function selectedEvidence() {
    return Array.from(els.evidence.querySelectorAll('input[type="checkbox"]:checked')).map((box) => box.value);
  }
  function updateAskState() {
    els.ask.disabled = !state.preview || !els.approve.checked || selectedEvidence().length === 0 || !state.capabilities || !state.capabilities.ai_enabled;
  }
  function renderPreview(preview) {
    state.preview = preview;
    clear(els.evidence);
    els.previewSummary.textContent = preview.evidence.length + " evidence items · about " + preview.estimated_tokens.toLocaleString() + " tokens · revision " + preview.revision.slice(0, 10);
    preview.evidence.forEach((item) => {
      const label = el("label", "evidence-item");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = item.id;
      checkbox.checked = true;
      checkbox.addEventListener("change", updateAskState);
      const content = el("div");
      content.append(el("strong", "", "[" + item.id + "] " + item.qualified_name));
      content.append(el("div", "meta", item.kind + " · " + item.path + ":" + item.start_line + "-" + item.end_line + " · " + item.estimated_tokens + " tokens"));
      content.append(el("div", "muted", item.relationship));
      if (item.source) content.append(el("pre", "", item.source));
      label.append(checkbox, content);
      els.evidence.append(label);
    });
    els.approve.checked = false;
    els.previewBox.classList.remove("hidden");
    els.answer.classList.add("hidden");
    updateAskState();
  }

  els.budget.addEventListener("input", () => {
    els.budgetLabel.textContent = Number(els.budget.value).toLocaleString() + " token budget";
  });
  els.preview.addEventListener("click", async () => {
    try {
      if (!els.question.value.trim()) throw new Error("Enter a question first.");
      els.preview.disabled = true;
      setMessage(els.chatMessage, "Selecting compact evidence locally…");
      const data = await api("/api/v1/context", {
        root: rootValue(),
        question: els.question.value.trim(),
        target: els.chatTarget.value.trim() || null,
        budget_tokens: Number(els.budget.value)
      });
      renderPreview(data);
      setMessage(els.chatMessage, "Review source below. Only checked evidence will be sent after approval.");
    } catch (error) {
      setMessage(els.chatMessage, error.message, true);
    } finally {
      els.preview.disabled = false;
    }
  });
  els.selectAll.addEventListener("click", () => {
    const boxes = Array.from(els.evidence.querySelectorAll('input[type="checkbox"]'));
    const check = boxes.some((box) => !box.checked);
    boxes.forEach((box) => { box.checked = check; });
    updateAskState();
  });
  els.approve.addEventListener("change", updateAskState);
  els.copyContext.addEventListener("click", async () => {
    if (!state.preview) return;
    const chosen = new Set(selectedEvidence());
    const parts = ["Question: " + state.preview.question];
    state.preview.evidence.filter((item) => chosen.has(item.id)).forEach((item) => {
      parts.push("\n[" + item.id + "] " + item.qualified_name + "\n" + item.path + ":" + item.start_line + "\n" + (item.source || ""));
    });
    try {
      await navigator.clipboard.writeText(parts.join("\n"));
      setMessage(els.chatMessage, "Selected compact context copied.");
    } catch (_) {
      setMessage(els.chatMessage, "Clipboard access was unavailable; use the visible preview to copy context.", true);
    }
  });
  els.ask.addEventListener("click", async () => {
    if (!state.preview) return;
    try {
      els.ask.disabled = true;
      setMessage(els.chatMessage, "Sending only approved evidence…");
      const data = await api("/api/v1/chat", {
        preview_id: state.preview.preview_id,
        evidence_ids: selectedEvidence(),
        approved: els.approve.checked
      });
      els.answerText.textContent = data.answer;
      const tokenText = data.provider_input_tokens == null
        ? "Estimated input: " + data.estimated_input_tokens + " tokens"
        : "Provider usage: " + data.provider_input_tokens + " input / " + (data.provider_output_tokens || 0) + " output tokens";
      els.answerMeta.textContent = tokenText + " · citations: " + (data.citations.join(", ") || "none") + (data.citation_warning ? " · " + data.citation_warning : "");
      els.answer.classList.remove("hidden");
      setMessage(els.chatMessage, "Answer received.");
    } catch (error) {
      setMessage(els.chatMessage, error.message, true);
    } finally {
      updateAskState();
    }
  });

  loadCapabilities();
})();
