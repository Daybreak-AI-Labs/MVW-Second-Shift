(function () {
  var status = document.getElementById("ap-status"), count = document.getElementById("ap-count");
  function say(text) { if (status) status.textContent = text; }
  function left() { return document.querySelectorAll("[data-approval]:not([data-decided])").length; }

  // A risky approval needs the person to say they have read it; the most
  // serious also asks them to type the word. The server requires both.
  async function acknowledge(label, risk) {
    if (risk !== "high" && risk !== "critical") return {};
    if (risk === "critical") {
      var typed = await window.mvForm("Approve a critical-risk action", [
        { key: "confirmation", label: "Type approve to confirm", type: "text", required: true,
          help: "You are approving: " + label + ". This is rated critical risk." },
      ], { okText: "Approve" });
      if (!typed) return null;
      return { acknowledged: true, confirmation: String(typed.confirmation || "").trim().toLowerCase() };
    }
    var ok = await window.mvConfirm("Approve “" + label + "”? It is rated high risk. " +
      "Approving means you have read what it will do.", { okText: "Approve" });
    return ok ? { acknowledged: true } : null;
  }

  async function reason(label) {
    var answer = await window.mvForm("Reject “" + label + "”", [
      { key: "reason", label: "Why? (optional)", type: "text", required: false,
        help: "The reason is written to the audit record." },
    ], { okText: "Reject" });
    if (!answer) return null;
    var text = String(answer.reason || "").trim();
    return text ? { reason: text } : {};
  }

  async function decide(button) {
    var item = button.closest("[data-approval]"), action = button.getAttribute("data-ap-decide");
    var id = item.getAttribute("data-approval"), label = item.getAttribute("data-label") || "this request";
    var body = action === "approve" ? await acknowledge(label, item.getAttribute("data-risk")) : await reason(label);
    if (body === null) return;
    var buttons = item.querySelectorAll("[data-ap-decide]");
    var was = Array.prototype.map.call(buttons, function (b) { return b.disabled; });
    buttons.forEach(function (b) { b.disabled = true; });
    say(action === "approve" ? "Approving…" : "Rejecting…");
    function restore() { buttons.forEach(function (b, i) { b.disabled = was[i]; }); }
    var headers = { "Content-Type": "application/json" };
    if (button.dataset.binding) headers["X-Second-Shift-Approval-Binding"] = button.dataset.binding;
    var response;
    try {
      response = await fetch("/api/v1/approvals/" + encodeURIComponent(id) + "/" + action, {
        method: "POST", credentials: "same-origin", headers: headers, body: JSON.stringify(body) });
    } catch (error) {
      restore();
      say("The decision could not be sent. Check your connection and try again.");
      window.mvToast("The decision could not be sent.", { error: true });
      return;
    }
    if (response.status === 202) {
      restore();
      say("Your decision is saved but not in effect yet while the record is finished. It is safe to try again.");
      window.mvToast("Decision saved, not in effect yet. It is safe to try again.", { error: true });
      return;
    }
    if (response.status !== 204) {
      restore();
      var failure = await window.mvErrorResponse(response);
      say(window.mvErrorText(failure, action === "approve" ? "approve this request" : "reject this request"));
      window.mvFail(failure, action === "approve" ? "approve this request" : "reject this request");
      return;
    }
    var state = response.headers.get("X-Second-Shift-Approval-State") || "";
    if (state === "pending") {
      // Recorded, but more approvers are needed before the action is allowed.
      var got = response.headers.get("X-Second-Shift-Approval-Count") || "?";
      var need = response.headers.get("X-Second-Shift-Approval-Required") || "?";
      buttons.forEach(function (b) { b.disabled = b.getAttribute("data-ap-decide") === "approve"; });
      var progress = item.querySelector("[data-ap-progress]");
      if (!progress) {
        progress = document.createElement("p"); progress.className = "muted"; progress.setAttribute("data-ap-progress", "");
        item.querySelector("[data-ap-actions]").before(progress);
      }
      progress.textContent = "Your approval is recorded. " + got + " of " + need +
        " required approvals received. The action is not allowed yet.";
      say("Your approval is recorded. More approvers are needed before it goes ahead.");
      return;
    }
    item.setAttribute("data-decided", state || action);
    buttons.forEach(function (b) { b.disabled = true; b.setAttribute("aria-disabled", "true"); });
    var outcome = item.querySelector("[data-ap-outcome]");
    var approved = state ? state === "approved" : action === "approve";
    if (outcome) {
      outcome.hidden = false; outcome.textContent = approved ? "Approved" : "Rejected";
      outcome.className = "badge " + (approved ? "active" : "failure");
    }
    if (count) { count.textContent = left() + " waiting"; count.className = "badge " + (left() ? "pending" : "active"); }
    say((approved ? "Approved: " : "Rejected: ") + label + ".");
    window.mvToast(approved ? "Approved." : "Rejected.", { quiet: true });
  }

  document.addEventListener("click", function (event) {
    var button = event.target.closest ? event.target.closest("[data-ap-decide]") : null;
    if (button && !button.disabled) decide(button);
  });
})();
