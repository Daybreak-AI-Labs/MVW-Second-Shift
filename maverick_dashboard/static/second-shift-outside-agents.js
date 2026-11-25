(function () {
  function slug(text) {
    return String(text || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64);
  }
  var nameIn = document.getElementById("xa-name"), idIn = document.getElementById("xa-id");
  // Re-adding an agent that already exists keeps its spending period unless
  // the person picks one; a new agent starts per month.
  var periodIn = document.getElementById("xa-budget-period"), periodPicked = false;
  if (periodIn) periodIn.addEventListener("change", function () { periodPicked = true; });
  function existingAgent(id) {
    return Array.prototype.some.call(document.querySelectorAll("[data-xa-reset-budget]"),
      function (el) { return el.getAttribute("data-xa-reset-budget") === id; });
  }
  if (nameIn) nameIn.addEventListener("input", function () {
    idIn.value = slug(nameIn.value);
    if (!periodIn || periodPicked) return;
    var keep = existingAgent(idIn.value);
    periodIn.options[0].hidden = !keep;
    periodIn.value = keep ? "" : "monthly";
  });
  // Allowed actions: one row per action with your risk rating.
  var rows = document.getElementById("xa-tools"), n = 0;
  function addRow() {
    var i = ++n, row = document.createElement("div");
    row.className = "xa-tool-row"; row.style.cssText = "display:flex; gap: var(--space-2); margin-bottom: var(--space-2); flex-wrap: wrap;";
    var toolSel = document.createElement("input"); toolSel.className = "input"; toolSel.setAttribute("aria-label", "Action " + i);
    toolSel.dataset.role = "tool"; toolSel.maxLength = 128; toolSel.placeholder = "The action’s name on its platform";
    toolSel.style.cssText = "flex: 2 1 16rem; width: auto;";
    var riskSel = document.createElement("select"); riskSel.className = "select"; riskSel.setAttribute("aria-label", "Your risk rating for action " + i);
    riskSel.dataset.role = "risk"; riskSel.style.cssText = "flex: 1 1 12rem; width: auto;";
    [["", "Use the agent’s own rating"], ["low", "Low risk"], ["medium", "Medium risk"], ["high", "High risk"]].forEach(function (x) {
      var o = document.createElement("option"); o.value = x[0]; o.textContent = x[1]; riskSel.appendChild(o);
    });
    var rm = document.createElement("button"); rm.type = "button"; rm.className = "btn btn--ghost"; rm.textContent = "Remove";
    rm.setAttribute("aria-label", "Remove action " + i);
    rm.addEventListener("click", function () { row.remove(); });
    row.appendChild(toolSel); row.appendChild(riskSel); row.appendChild(rm); rows.appendChild(row);
  }
  var addTool = document.getElementById("xa-tools-add");
  if (addTool) addTool.addEventListener("click", addRow);
  function fields(form) {
    var f = new FormData(form);
    var num = function (k) { var v = String(f.get(k) || "").trim(); return v === "" ? null : Number(v); };
    var allow = [];
    (rows ? rows.querySelectorAll(".xa-tool-row") : []).forEach(function (row) {
      var t = row.querySelector('[data-role="tool"]').value.trim(), risk = row.querySelector('[data-role="risk"]').value;
      if (t) allow.push(risk ? t + ":" + risk : t);
    });
    return {
      id: String(f.get("id") || "").trim().toLowerCase() || slug(f.get("display_name")),
      platform: String(f.get("platform") || "custom"),
      description: String(f.get("description") || "").trim() || String(f.get("display_name") || "").trim(),
      owner: String(f.get("owner") || "").trim(),
      owner_object_id: String(f.get("owner_object_id") || ""),
      department: String(f.get("department") || "").trim(),
      max_risk: String(f.get("max_risk") || "") || null,
      allow_tools: allow,
      external_ref: String(f.get("external_ref") || "").trim() || null,
      max_dollars: num("max_dollars"),
      expires_days: num("expires_days"),
      budget_period: String(f.get("budget_period") || "") || null,
    };
  }
  var form = document.getElementById("xa-add");
  // Owner picker: only on the page when the Entra directory is on. Typing an email still works.
  var ownerIn = document.getElementById("xa-owner"), ownerList = document.getElementById("xa-owner-list");
  var ownerOid = document.getElementById("xa-owner-oid"), ownerNote = document.getElementById("xa-owner-note");
  if (ownerIn && ownerList && ownerOid) {
    var ownerTimer = null, ownerSeq = 0;
    var closeList = function () { ownerList.hidden = true; ownerList.textContent = ""; ownerIn.setAttribute("aria-expanded", "false"); };
    var say = function (text) { if (ownerNote) ownerNote.textContent = text; };
    ownerIn.addEventListener("input", function () {
      ownerOid.value = "";  // typing again drops a person chosen before
      clearTimeout(ownerTimer);
      var text = ownerIn.value.trim();
      if (text.length < 2) { closeList(); return; }
      ownerTimer = setTimeout(async function () {
        var mine = ++ownerSeq;
        try {
          var out = await window.mvFetchJSON("/api/v1/directory/people?q=" + encodeURIComponent(text), {}, "search your directory");
          if (mine !== ownerSeq) return;
          ownerList.textContent = "";
          (out.people || []).forEach(function (p) {
            var li = document.createElement("li"), b = document.createElement("button");
            b.type = "button"; b.className = "btn btn--ghost"; b.setAttribute("role", "option");
            b.textContent = p.display_name + " (" + p.email + ")" + (p.job_title ? ", " + p.job_title : "");
            b.addEventListener("click", function () {
              ownerIn.value = p.email; ownerOid.value = p.object_id; closeList();
              say("Owner chosen: " + p.display_name + ".");
            });
            li.appendChild(b); ownerList.appendChild(li);
          });
          ownerList.hidden = !ownerList.children.length;
          ownerIn.setAttribute("aria-expanded", ownerList.hidden ? "false" : "true");
          say(ownerList.children.length ? "Choose a person from the list, or keep typing." : "Nobody found. You can type an email instead.");
        } catch (e) {
          if (mine !== ownerSeq) return;
          closeList(); say("The people search is not available right now. Type the owner's email instead.");
        }
      }, 300);
    });
  }
  // A starter rule set fills the limits; the person can change any of them before saving.
  var starterIn = document.getElementById("xa-starter"), starters = {};
  try { starters = JSON.parse(document.getElementById("xa-starters").textContent); } catch (e) { starters = {}; }
  if (starterIn && form) starterIn.addEventListener("change", function () {
    var st = starters[starterIn.value], note = document.getElementById("xa-starter-note");
    if (!st) return;
    var v = st.values;
    form.elements.max_risk.value = v.max_risk || "";
    form.elements.approval_at.value = v.approval_at || "";
    form.elements.max_dollars.value = v.max_dollars == null ? "" : v.max_dollars;
    form.elements.budget_period.value = v.budget_period || "monthly"; periodPicked = true;
    form.elements.expires_days.value = v.expires_days == null ? "" : String(v.expires_days);
    if (note) note.textContent = st.summary + " Change any limit below before you save. These are starting points chosen by the developers, not your policy; an administrator should review them.";
  });
  if (form) form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var body = fields(form);
    if (!body.id) { window.mvToast("Give the agent a name.", { error: true }); return; }
    body.starter = starterIn && starterIn.value ? starterIn.value : null;
    window.xaCall("/api/v1/external-agents", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }, "Agent added.", false, "add the agent").then(function (out) {
      // Straight on to connecting it: the guide opens on the same page.
      if (out) window.location.assign("/external-agents?connect=" + encodeURIComponent(body.id) + "#xa-connect");
    });
  });
  // "Add this agent" on a Watched row fills the form without leaving the page; the link works without script too.
  document.addEventListener("click", function (event) {
    var link = event.target.closest ? event.target.closest("[data-pc-add]") : null;
    if (!link) return;
    var name = document.getElementById("xa-name"), ref = document.getElementById("xa-external-ref");
    var platform = document.querySelector('#xa-add select[name="platform"]');
    if (!name || !ref) return;
    event.preventDefault();
    name.value = link.getAttribute("data-name") || "";
    name.dispatchEvent(new Event("input", { bubbles: true }));
    ref.value = link.getAttribute("data-ref") || "";
    if (platform && link.getAttribute("data-platform")) platform.value = link.getAttribute("data-platform");
    document.getElementById("xa-add").scrollIntoView({ behavior: "smooth", block: "start" });
    name.focus();
  });
  Array.prototype.forEach.call(document.querySelectorAll("#xa-filters select"), function (sel) {
    sel.addEventListener("change", function () { sel.form.submit(); });
  });
})();
