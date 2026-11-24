/* The agent factory pages: the new-agent flow and one agent's page (editor, test cases, tests, release, export).
   Everything that came from a person or a model is put on the page with textContent, never as markup. */
(function () {
  'use strict';
  var RISKS = ['low', 'medium', 'high'];
  var E = window.mvEl;

  function json(id) {
    var el = document.getElementById(id);
    if (!el) return null;
    try { return JSON.parse(el.textContent); } catch (_) { return null; }
  }
  var status = json('fx-status') || {};
  var perms = json('fx-perms') || {};
  var skillSettings = {};  // settings of a skill already in the definition, kept when the person saves

  async function api(method, url, body, what) {
    var opts = { method: method, serverDetail: 'Something went wrong. Try again.' };
    if (body !== undefined) opts.body = body;
    return window.mvFetchJSON(url, opts, what);
  }
  function who(x) { return String(x || '').replace(/^user:/, ''); }
  function when(ts) { return ts ? new Date(ts * 1000).toLocaleString() : ''; }
  function money(n) { return n == null ? 'not worked out' : '$' + Number(n).toFixed(4); }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
  function badge(text, kind) { return E('span', 'badge' + (kind ? ' ' + kind : ''), text); }
  function field(label, input) {
    var l = E('label'); l.appendChild(document.createTextNode(label)); l.appendChild(input); return l;
  }

  /* ---- export -------------------------------------------------------------------------------------------- */

  var TARGETS = [
    { id: 'azure', title: 'Azure container', needs: 'An Azure subscription with a Container Apps environment, a Key Vault and a container registry. The package builds the image in your registry and creates one Container App with its own managed identity.' },
    { id: 'aws', title: 'AWS Bedrock AgentCore container', needs: 'An AWS account in a Region where Bedrock AgentCore is available, Docker and the AWS CLI. The package builds an ARM64 image for Amazon ECR and creates the AgentCore runtime; keys are read from AWS Secrets Manager.' },
    { id: 'foundry', title: 'Microsoft Foundry agent', needs: 'A Foundry project with a model deployment, and the skills service running in Azure (the package has it). The agent’s only tools are the skills service, which asks Second Shift before every call.' }
  ];

  function releasedVersion() {
    var found = null;
    agent.versions.forEach(function (v) { if (v.state === 'released') found = v; });
    return found;
  }

  function downloadZip(out) {
    var raw = atob(out.package_base64), bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    var url = URL.createObjectURL(new Blob([bytes], { type: 'application/zip' }));
    var a = document.createElement('a'); a.href = url; a.download = out.filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function showKey(box, out) {
    clear(box);
    if (!out.key) return;
    var k = out.key;
    var p = E('p', null, 'The agent’s Second Shift access key. This is the only time it is shown. It replaces the agent’s earlier key, which no longer works.');
    var code = E('input'); code.type = 'text'; code.readOnly = true; code.value = k.value; code.setAttribute('aria-label', 'Access key'); code.style.width = '100%';
    var copy = E('button', 'btn btn--ghost', 'Copy the key'); copy.type = 'button';
    copy.addEventListener('click', function () { window.mvCopy(k.value); });
    box.appendChild(p); box.appendChild(code); box.appendChild(copy);
    k.where_to_store.forEach(function (w) { box.appendChild(E('p', 'muted', w)); });
    box.appendChild(E('p', 'muted', 'It is not in the package you downloaded. Anyone with this key can act as the agent.'));
  }

  function renderExport() {
    var box = document.getElementById('fx-export'); if (!box) return;
    clear(box);
    var v = releasedVersion();
    if (!v) { box.appendChild(E('p', 'muted', 'Only a released version can be exported. Release this agent first.')); return; }
    box.appendChild(E('p', null, 'Download version ' + v.number + ' as a package you deploy yourself. Each package holds exactly this version’s definition and never a secret. The agent is governed by Second Shift from its first action in all three places.'));
    if (!perms.admin) { box.appendChild(E('p', 'muted', 'Exporting needs the administrator role.')); return; }
    TARGETS.forEach(function (t) {
      var card = E('div', 'panel'); card.id = 'fx-export-' + t.id; card.style.marginTop = 'var(--space-2)';
      card.appendChild(E('h3', null, t.title));
      card.appendChild(E('p', 'muted', t.needs));
      var urlIn, connIn;
      if (t.id === 'foundry') {
        urlIn = E('input'); urlIn.type = 'url'; urlIn.placeholder = 'https://your-skills-service.example.com'; urlIn.id = 'fx-skills-url';
        connIn = E('input'); connIn.type = 'text'; connIn.placeholder = '/subscriptions/.../connections/skills-key'; connIn.id = 'fx-connection-id';
        card.appendChild(field('Address of the skills service (optional for a download; the README says where it goes)', urlIn));
        card.appendChild(field('Project connection resource id (optional for a download)', connIn));
      }
      var mint = E('input'); mint.type = 'checkbox'; mint.id = 'fx-mint-' + t.id;
      var label = E('label'); label.appendChild(mint); label.appendChild(document.createTextNode(' Make a new access key for the agent and show it once. The agent’s current key stops working.'));
      card.appendChild(label);
      var keyBox = E('div'); keyBox.style.marginTop = 'var(--space-2)';
      var btn = E('button', 'btn btn--primary', 'Download the package'); btn.type = 'button'; btn.id = 'fx-download-' + t.id;
      btn.addEventListener('click', async function () {
        if (mint.checked && !(await window.mvConfirm('Make a new access key for ' + agent.name + '? Its current key stops working at once, so anything using it must be given the new one.', { okText: 'Make the key and download', danger: true }))) return;
        btn.disabled = true;
        try {
          var out = await api('POST', '/api/v1/factory/agents/' + encodeURIComponent(agent.id) + '/versions/' + v.number + '/exports/' + t.id,
            { mint_key: mint.checked, skills_url: urlIn ? urlIn.value.trim() : '', connection_id: connIn ? connIn.value.trim() : '' }, 'make the package');
          downloadZip(out); showKey(keyBox, out); mint.checked = false;
          window.mvToast('The package was downloaded.');
        } catch (e) { window.mvToast(e.message, { error: true }); }
        btn.disabled = false;
      });
      card.appendChild(btn); card.appendChild(keyBox);
      if (t.id === 'foundry') card.appendChild(foundryPush(v, urlIn, connIn));
      box.appendChild(card);
    });
    box.appendChild(E('p', 'muted', 'Pushing straight to Azure Container Apps or AWS is not built in this version: download the package and follow its README.'));
  }

  function foundryPush(v, urlIn, connIn) {
    var wrap = E('div'); wrap.id = 'fx-push'; wrap.style.marginTop = 'var(--space-3)';
    var f = status.foundry_push || {};
    wrap.appendChild(E('h4', null, 'Push to Foundry'));
    if (!f.allowed) {
      wrap.appendChild(E('p', 'muted', 'Pushing to Foundry is turned off. An administrator can turn it on with allow_push = true in the [factory.foundry] settings. Until then, download the package and follow its README.'));
      return wrap;
    }
    if (!f.ready) {
      wrap.appendChild(E('p', 'error', 'Pushing to Foundry is on but not set up yet:'));
      var ul = E('ul'); (f.problems || []).forEach(function (x) { ul.appendChild(E('li', null, x)); }); wrap.appendChild(ul);
      return wrap;
    }
    var name = agent.foundry_agent_name;
    wrap.appendChild(E('p', 'muted', 'Second Shift signs in with its own credentials and creates the agent ' + name + ' in the project ' + f.project + '. It needs the skills service address and the project connection above. The request is recorded in the audit log and is sent once.'));
    var mode = E('select'); mode.id = 'fx-push-mode';
    [['create', 'Create a new agent'], ['new_version', 'Add a version to the existing agent']].forEach(function (m) { var o = E('option', null, m[1]); o.value = m[0]; mode.appendChild(o); });
    wrap.appendChild(field('What to do', mode));
    if (agent.foundry) wrap.appendChild(E('p', 'muted', 'Pushed before as ' + agent.foundry.agent + ' in ' + agent.foundry.project + ' on ' + when(agent.foundry.pushed_at) + '.'));
    var go = E('button', 'btn btn--primary', 'Push to Foundry'); go.type = 'button'; go.id = 'fx-push-go';
    go.addEventListener('click', async function () {
      var verb = mode.value === 'create' ? 'Create the agent ' + name + ' in the project ' + f.project : 'Add version ' + v.number + ' to the agent ' + name + ' in the project ' + f.project;
      if (!(await window.mvConfirm(verb + '? Second Shift sends this once and does not retry. You cannot undo it from here.', { okText: 'Push to Foundry' }))) return;
      go.disabled = true;
      try {
        var out = await api('POST', '/api/v1/factory/agents/' + encodeURIComponent(agent.id) + '/versions/' + v.number + '/push/foundry',
          { confirm_project: f.project, confirm_agent: name, skills_url: urlIn.value.trim(), connection_id: connIn.value.trim(), mode: mode.value }, 'push to Foundry');
        window.mvToast(out.message);
        refresh();
      } catch (e) { window.mvToast(e.message, { error: true }); }
      go.disabled = false;
    });
    wrap.appendChild(go);
    return wrap;
  }

  /* ---- the editor ---------------------------------------------------------------------------------------- */

  function fillEditor(def) {
    var form = document.getElementById('fx-editor');
    if (!form) return;
    document.getElementById('fx-name').value = def.name || '';
    document.getElementById('fx-description').value = def.description || '';
    document.getElementById('fx-instructions').value = def.instructions || '';
    var chosen = {};
    skillSettings = {};
    (def.skills || []).forEach(function (s) { chosen[s.name] = s; if (s.settings && Object.keys(s.settings).length) skillSettings[s.name] = s.settings; });
    var box = document.getElementById('fx-skills');
    clear(box);
    (status.skills || []).forEach(function (sk) {
      var row = E('div', 'fx-skill');
      row.style.cssText = 'display:grid; grid-template-columns:auto 1fr auto; gap:var(--space-2); align-items:start';
      var cb = E('input'); cb.type = 'checkbox'; cb.id = 'fx-skill-' + sk.name; cb.checked = !!chosen[sk.name];
      var text = E('label'); text.setAttribute('for', cb.id);
      text.appendChild(E('strong', null, sk.name.replace(/_/g, ' ')));
      var d = E('span', 'muted', sk.description); d.style.display = 'block'; d.style.fontSize = 'var(--text-sm)'; text.appendChild(d);
      var sel = E('select', 'select'); sel.id = 'fx-risk-' + sk.name; sel.setAttribute('aria-label', 'Risk rating for ' + sk.name.replace(/_/g, ' '));
      RISKS.forEach(function (r, i) {
        if (i < RISKS.indexOf(sk.default_risk)) return;  // a rating can be raised, never lowered
        var o = E('option', null, r + ' risk'); o.value = r; sel.appendChild(o);
      });
      sel.value = (chosen[sk.name] && chosen[sk.name].risk) || sk.default_risk;
      row.appendChild(cb); row.appendChild(text); row.appendChild(sel); box.appendChild(row);
    });
    var lbox = document.getElementById('fx-limits');
    clear(lbox);
    var limits = def.limits || status.default_limits || {};
    Object.keys(status.limits || {}).forEach(function (key) {
      if (key === 'max_cost_dollars' && !status.has_prices) return;
      var input = E('input', 'input'); input.type = 'number'; input.id = 'fx-limit-' + key; input.min = '0'; input.step = key === 'max_cost_dollars' ? '0.01' : '1';
      input.value = limits[key] == null ? '' : limits[key];
      if (key === 'max_cost_dollars') input.placeholder = 'No limit';
      lbox.appendChild(field(status.limits[key], input));
    });
    var note = document.getElementById('fx-model-note');
    var m = def.model;
    if (note) note.textContent = m ? 'Model: ' + m.deployment + ' (' + String(m.provider).replace('foundry_', 'Foundry, ') + '). An administrator chooses the model in the settings.' : '';
  }

  function readEditor() {
    var skills = [];
    (status.skills || []).forEach(function (sk) {
      var cb = document.getElementById('fx-skill-' + sk.name);
      if (!cb || !cb.checked) return;
      var entry = { name: sk.name };
      var risk = document.getElementById('fx-risk-' + sk.name).value;
      if (risk !== sk.default_risk) entry.risk = risk;
      if (skillSettings[sk.name]) entry.settings = skillSettings[sk.name];
      skills.push(entry);
    });
    var limits = {};
    Object.keys(status.limits || {}).forEach(function (key) {
      var input = document.getElementById('fx-limit-' + key);
      if (!input) return;
      if (input.value === '') { if (key === 'max_cost_dollars') limits[key] = null; return; }
      limits[key] = Number(input.value);
    });
    return {
      name: document.getElementById('fx-name').value,
      description: document.getElementById('fx-description').value,
      instructions: document.getElementById('fx-instructions').value,
      skills: skills, limits: limits
    };
  }

  /* ---- the new-agent page -------------------------------------------------------------------------------- */

  function newPage() {
    var form = document.getElementById('fx-brief');
    var brief = null;
    form.addEventListener('submit', async function (ev) {
      ev.preventDefault();
      var statusEl = document.getElementById('fx-propose-status');
      var btn = document.getElementById('fx-propose');
      brief = {
        purpose: document.getElementById('fx-purpose').value, users: document.getElementById('fx-users').value,
        may: document.getElementById('fx-may').value, must_not: document.getElementById('fx-must-not').value
      };
      document.getElementById('fx-problems').hidden = true;
      document.getElementById('fx-editor-wrap').hidden = true;
      btn.disabled = true; statusEl.textContent = 'Asking the model. This can take a minute.';
      try {
        var out = await api('POST', '/api/v1/factory/draft', { brief: brief }, 'draft the agent');
        statusEl.textContent = '';
        showNotes(out);
        if (!out.ok) {
          var list = document.getElementById('fx-problem-list'); clear(list);
          out.reasons.forEach(function (r) { list.appendChild(E('li', null, r)); });
          document.getElementById('fx-excerpt').textContent = out.excerpt || '';
          document.getElementById('fx-problems').hidden = false;
          document.getElementById('fx-problems').scrollIntoView({ block: 'nearest' });
          return;
        }
        var def = Object.assign({ model: null }, out.parts, { limits: Object.assign({}, status.default_limits, out.parts.limits || {}) });
        fillEditor(def);
        document.getElementById('fx-editor-wrap').hidden = false;
        document.getElementById('fx-name').focus();
      } catch (e) { statusEl.textContent = ''; window.mvToast(e.message, { error: true }); }
      finally { btn.disabled = false; }
    });
    document.getElementById('fx-editor').addEventListener('submit', async function (ev) {
      ev.preventDefault();
      var save = document.getElementById('fx-save'); save.disabled = true;
      try {
        var agent = await api('POST', '/api/v1/factory/agents', { brief: brief, parts: readEditor() }, 'save the agent');
        window.location.assign('/factory/' + encodeURIComponent(agent.id));
      } catch (e) { window.mvToast(e.message, { error: true }); save.disabled = false; }
    });
  }

  function showNotes(out) {
    var box = document.getElementById('fx-notes');
    var lines = (out.notes || []).slice();
    if (out.usage && out.usage.input_tokens != null) lines.push('Drafting used ' + out.usage.input_tokens + ' input and ' + out.usage.output_tokens + ' output tokens' + (out.usage.cost != null ? ' (about ' + money(out.usage.cost) + ').' : '.'));
    clear(box);
    lines.forEach(function (l) { box.appendChild(E('p', 'muted', l)); });
    box.hidden = !lines.length;
  }

  /* ---- one agent's page ---------------------------------------------------------------------------------- */

  var agent = null;
  var poll = null;

  function tip() { return agent.versions[agent.versions.length - 1]; }

  var filled = '';

  function render(next, partial) {
    agent = next;
    var t = tip();
    document.getElementById('fx-title').textContent = agent.name;
    var sub = 'Version ' + t.number + ' · ' + t.state_label + ' · identity ' + agent.agent_id;
    document.getElementById('fx-subtitle').textContent = sub;
    renderRelease(t); renderTests(t); renderExport();
    if (!partial) { renderEditor(t); renderCases(t); renderVersions(); }
    var running = t.tests && t.tests.status === 'running';
    if (running && !poll) poll = setInterval(refresh, 2000);
    if (!running && poll) { clearInterval(poll); poll = null; }
  }

  async function refresh() {
    try {
      var next = await api('GET', '/api/v1/factory/agents/' + encodeURIComponent(agent.id), undefined, 'refresh this page');
      var again = tip().tests && tip().tests.status === 'running' && next.versions[next.versions.length - 1].tests && next.versions[next.versions.length - 1].tests.status === 'running';
      render(next, again);
      if (!again && poll) { clearInterval(poll); poll = null; }
    }
    catch (e) { if (poll) { clearInterval(poll); poll = null; } window.mvToast(e.message, { error: true }); }
  }

  async function act(method, url, body, what, done) {
    try {
      var out = await api(method, url, body, what);
      render(out);
      if (done) window.mvToast(done);
      return out;
    } catch (e) { window.mvToast(e.message, { error: true }); return null; }
  }

  function renderRelease(t) {
    var box = document.getElementById('fx-release'); clear(box);
    var head = E('p'); head.style.margin = '0';
    var kind = t.state === 'released' ? 'active' : (t.state === 'waiting_for_approval' ? 'warn' : '');
    head.appendChild(badge(t.state_label, kind)); head.appendChild(document.createTextNode(' Version ' + t.number));
    box.appendChild(head);
    var a = t.approval;
    var say = function (text, cls) { var p = E('p', cls || 'muted', text); p.style.margin = 'var(--space-2) 0 0'; box.appendChild(p); return p; };
    if (t.state === 'draft') say(t.gate.reason || 'Run the tests, then submit it for release.');
    if (t.state === 'tested') {
      say('Every test case passed on exactly this version. It can be submitted for release; a different person must approve it.');
      if (perms.build) {
        var b = E('button', 'btn btn--primary', 'Submit for release'); b.type = 'button'; b.id = 'fx-submit'; b.style.marginTop = 'var(--space-2)';
        b.addEventListener('click', async function () {
          if (!(await window.mvConfirm('Submit version ' + t.number + ' of ' + agent.name + ' for release? A different person has to approve it on the Approvals page. You cannot change it while it waits.', { okText: 'Submit for release' }))) return;
          act('POST', '/api/v1/factory/agents/' + encodeURIComponent(agent.id) + '/versions/' + t.number + '/submit', {}, 'submit the version', 'Submitted. It now waits for approval.');
        });
        box.appendChild(b);
      }
    }
    if (t.state === 'waiting_for_approval') {
      var p = say('Waiting for a different person to approve it' + (a && a.submitted_by ? ' (submitted by ' + who(a.submitted_by) + ' on ' + when(a.submitted_at) + ')' : '') + '. It is released as soon as they do.');
      var link = E('a', null, 'Open the Approvals page'); link.href = '/approvals'; p.appendChild(document.createTextNode(' ')); p.appendChild(link);
      if (a && a.release_problem) say(a.release_problem, 'error');
    }
    if (t.state === 'released') {
      var q = say('Live since ' + when(t.released_at) + '. It is enrolled as an outside agent, so it is governed from its first action.');
      var l2 = E('a', null, 'See it on the Outside agents page'); l2.setAttribute('href', ['', 'external-agents', encodeURIComponent(agent.agent_id)].join('/'));
      q.appendChild(document.createTextNode(' ')); q.appendChild(l2);
      if (a && a.drift_note) say(a.drift_note);
      if (perms.admin) {
        var r = E('button', 'btn btn--ghost btn--danger', 'Retire this agent'); r.type = 'button'; r.id = 'fx-retire'; r.style.marginTop = 'var(--space-2)';
        r.addEventListener('click', async function () {
          if (!(await window.mvConfirm('Retire ' + agent.name + '? It is removed from the outside agents, so its access keys stop working straight away.', { okText: 'Retire', danger: true }))) return;
          act('POST', '/api/v1/factory/agents/' + encodeURIComponent(agent.id) + '/retire', {}, 'retire the agent', 'The agent is retired.');
        });
        box.appendChild(r);
      }
    }
    if (t.state === 'retired') say('Retired' + (t.retired_at ? ' on ' + when(t.retired_at) : '') + '. Editing it starts a new version.');
    if (a && a.outcome && t.state !== 'released' && a.note) say(a.note);
  }

  function renderEditor(t) {
    var form = document.getElementById('fx-editor');
    if (!form) return;
    var key = t.number + ':' + t.revision;
    if (key !== filled) { fillEditor(t.definition); filled = key; }
    var locked = t.state === 'waiting_for_approval';
    Array.prototype.forEach.call(form.querySelectorAll('input, textarea, select, button'), function (el) { el.disabled = locked; });
    var save = document.getElementById('fx-save');
    save.textContent = (t.state === 'released' || t.state === 'retired') ? 'Save as version ' + (t.number + 1) : 'Save changes';
    var s = document.getElementById('fx-save-status');
    s.textContent = locked ? 'It is waiting for approval, so it cannot be changed.' : (t.state === 'tested' ? 'Any change means the tests have to run again.' : '');
  }

  var CASE = { editing: null };

  function renderCases(t) {
    var box = document.getElementById('fx-cases'); clear(box);
    var kinds = status.check_kinds || {};
    if (!agent.cases.length) box.appendChild(E('p', 'muted', 'No test cases yet. A test case is an input for the agent and the checks its answer must pass. A version can be released only when every case passes.'));
    agent.cases.forEach(function (c) {
      var row = E('div'); row.style.cssText = 'border-top:1px solid var(--border,#3333);padding:var(--space-2) 0';
      row.appendChild(E('strong', null, c.name));
      var inp = E('div', 'muted', c.input.length > 240 ? c.input.slice(0, 240) + '…' : c.input); inp.style.whiteSpace = 'pre-wrap'; row.appendChild(inp);
      var ul = E('ul'); ul.style.margin = '0'; ul.style.paddingLeft = '1.2rem';
      c.checks.forEach(function (ch) { ul.appendChild(E('li', null, (kinds[ch.kind] || ch.kind) + ': ' + ch.value)); });
      row.appendChild(ul);
      if (perms.build && t.state !== 'waiting_for_approval') {
        var edit = E('button', 'btn btn--ghost', 'Edit'); edit.type = 'button';
        edit.setAttribute('aria-label', 'Edit test case ' + c.name);
        edit.addEventListener('click', function () { CASE.editing = c; renderCaseForm(); document.getElementById('fx-case-form').scrollIntoView({ block: 'nearest' }); });
        var del = E('button', 'btn btn--ghost btn--danger', 'Remove'); del.type = 'button';
        del.setAttribute('aria-label', 'Remove test case ' + c.name);
        del.addEventListener('click', async function () {
          if (!(await window.mvConfirm('Remove the test case "' + c.name + '"? The tests will need to run again.', { okText: 'Remove', danger: true }))) return;
          act('DELETE', '/api/v1/factory/agents/' + encodeURIComponent(agent.id) + '/cases/' + encodeURIComponent(c.id), undefined, 'remove the test case', 'Test case removed.');
        });
        row.appendChild(edit); row.appendChild(document.createTextNode(' ')); row.appendChild(del);
      }
      box.appendChild(row);
    });
    if (perms.build && t.state !== 'waiting_for_approval') {
      var form = E('form'); form.id = 'fx-case-form'; form.style.cssText = 'margin-top:var(--space-3); display:grid; gap:var(--space-2)';
      box.appendChild(form); renderCaseForm();
    } else if (!perms.build) box.appendChild(E('p', 'muted', 'Adding test cases needs the operator role.'));
  }

  function checkRow(kind, value) {
    var row = E('div'); row.className = 'fx-check'; row.style.cssText = 'display:grid; grid-template-columns:minmax(10rem,1fr) 2fr auto; gap:var(--space-2)';
    var sel = E('select', 'select'); sel.setAttribute('aria-label', 'Kind of check');
    Object.keys(status.check_kinds || {}).forEach(function (k) { var o = E('option', null, status.check_kinds[k]); o.value = k; sel.appendChild(o); });
    sel.value = kind || 'answer_contains';
    var val = E('input', 'input'); val.setAttribute('aria-label', 'Value to check'); val.maxLength = 500; val.value = value == null ? '' : value;
    var rm = E('button', 'btn btn--ghost', 'Remove check'); rm.type = 'button';
    rm.addEventListener('click', function () { if (row.parentNode.children.length > 1) row.remove(); });
    row.appendChild(sel); row.appendChild(val); row.appendChild(rm);
    return row;
  }

  function renderCaseForm() {
    var form = document.getElementById('fx-case-form'); clear(form);
    var c = CASE.editing;
    form.appendChild(E('h3', null, c ? 'Change test case' : 'Add a test case'));
    var name = E('input', 'input'); name.id = 'fx-case-name'; name.maxLength = 200; name.value = c ? c.name : '';
    var input = E('textarea', 'textarea'); input.id = 'fx-case-input'; input.rows = 3; input.maxLength = 20000; input.value = c ? c.input : '';
    form.appendChild(field('Name', name)); form.appendChild(field('What the agent is asked', input));
    var checks = E('div'); checks.id = 'fx-case-checks'; checks.style.cssText = 'display:grid; gap:var(--space-2)';
    (c ? c.checks : [{ kind: 'answer_contains', value: '' }]).forEach(function (ch) { checks.appendChild(checkRow(ch.kind, ch.value)); });
    form.appendChild(E('span', null, 'Checks the run must pass')); form.appendChild(checks);
    var add = E('button', 'btn btn--ghost', 'Add another check'); add.type = 'button'; add.addEventListener('click', function () { checks.appendChild(checkRow()); });
    var save = E('button', 'btn btn--primary', c ? 'Save test case' : 'Add test case'); save.type = 'submit'; save.id = 'fx-case-save';
    form.appendChild(add);
    var bar = E('p'); bar.appendChild(save);
    if (c) { var cancel = E('button', 'btn btn--ghost', 'Cancel'); cancel.type = 'button'; cancel.addEventListener('click', function () { CASE.editing = null; renderCaseForm(); }); bar.appendChild(document.createTextNode(' ')); bar.appendChild(cancel); }
    form.appendChild(bar);
    form.onsubmit = async function (ev) {
      ev.preventDefault();
      var body = { name: name.value, input: input.value, checks: Array.prototype.map.call(checks.children, function (row) {
        return { kind: row.querySelector('select').value, value: row.querySelector('input').value };
      }) };
      var base = '/api/v1/factory/agents/' + encodeURIComponent(agent.id) + '/cases';
      var editing = CASE.editing; CASE.editing = null;
      await act(editing ? 'PUT' : 'POST', editing ? base + '/' + encodeURIComponent(editing.id) : base, body, 'save the test case', 'Test case saved.');
    };
  }

  function renderTests(t) {
    var box = document.getElementById('fx-tests'); clear(box);
    var tests = t.tests;
    var running = tests && tests.status === 'running';
    if (perms.build && (t.state === 'draft' || t.state === 'tested')) {
      var run = E('button', 'btn btn--primary', running ? 'Tests are running…' : 'Run tests'); run.type = 'button'; run.id = 'fx-run-tests'; run.disabled = !!running || !status.ready;
      run.addEventListener('click', function () {
        act('POST', '/api/v1/factory/agents/' + encodeURIComponent(agent.id) + '/versions/' + t.number + '/tests', {}, 'start the tests', 'The tests have started.');
      });
      box.appendChild(run);
      var limits = E('p', 'muted', 'Each case runs through the agent with the real model. A run is limited to ' + status.max_test_cases + ' cases, ' + status.max_case_seconds + ' seconds a case, ' +
        status.max_test_run_seconds + ' seconds in all and $' + status.max_test_run_cost_dollars + ' in all (set by an administrator). Test runs do not count as the agent’s activity.');
      limits.style.fontSize = 'var(--text-sm)'; box.appendChild(limits);
    }
    if (!tests) { box.appendChild(E('p', 'muted', 'The tests have not been run on this version.')); return; }
    var sum = E('p');
    var passed = tests.passed_count + ' of ' + tests.case_count + ' passed';
    sum.appendChild(badge(running ? 'Running' : (tests.passed && !tests.stale ? 'All passed' : (tests.stale ? 'Out of date' : 'Not all passed')), running ? 'warn' : (tests.passed && !tests.stale ? 'active' : 'failure')));
    sum.appendChild(document.createTextNode(' ' + passed + ' · cost ' + money(tests.total_cost) + (tests.estimated_cost != null ? ' (estimated ' + money(tests.estimated_cost) + ')' : '') + ' · started ' + when(tests.started_at) + ' by ' + who(tests.started_by)));
    box.appendChild(sum);
    if (tests.stale) box.appendChild(E('p', 'muted', 'The version or its test cases changed after this run, so these results no longer count. Run the tests again.'));
    if (tests.note) box.appendChild(E('p', 'muted', tests.note));
    tests.results.forEach(function (r) { box.appendChild(resultView(r)); });
  }

  function resultView(r) {
    var d = E('details'); d.className = 'fx-result'; d.open = r.status !== 'passed'; d.style.cssText = 'border-top:1px solid var(--border,#3333);padding:var(--space-2) 0';
    var s = E('summary');
    s.appendChild(badge(r.status === 'passed' ? 'Passed' : (r.status === 'failed' ? 'Failed' : 'Could not run'), r.status === 'passed' ? 'active' : 'failure'));
    s.appendChild(document.createTextNode(' ' + r.name + ' · ' + money(r.cost) + ' · ' + r.seconds + ' s'));
    d.appendChild(s);
    if (r.reason) d.appendChild(E('p', 'muted', r.reason));
    var ul = E('ul'); ul.style.paddingLeft = '1.2rem';
    r.checks.forEach(function (c) { ul.appendChild(E('li', null, (c.passed ? 'Passed: ' : 'Failed: ') + ((status.check_kinds || {})[c.kind] || c.kind) + ' ' + c.value + '. ' + c.detail)); });
    d.appendChild(ul);
    d.appendChild(E('p', 'muted', 'Tools used: ' + (r.tools.length ? r.tools.join(', ') : 'none') + ' · ' + r.model_steps + ' model step(s) · ' + r.input_tokens + ' tokens in, ' + r.output_tokens + ' out'));
    if (r.screens.length) {
      var sc = E('ul'); sc.style.paddingLeft = '1.2rem';
      r.screens.forEach(function (x) { sc.appendChild(E('li', null, 'Checked ' + x.tool + ' (' + x.risk + ' risk): ' + (x.allowed ? 'allowed' : 'refused') + '. ' + x.detail)); });
      d.appendChild(E('p', null, 'Every check with Second Shift:')); d.appendChild(sc);
    }
    if (r.steps.length) { var st = E('ol'); st.style.paddingLeft = '1.2rem'; r.steps.forEach(function (x) { st.appendChild(E('li', null, x)); }); d.appendChild(E('p', null, 'Steps taken:')); d.appendChild(st); }
    if (r.files.length) d.appendChild(E('p', 'muted', 'Files made: ' + r.files.map(function (f) { return f.name + ' (' + f.size + ' bytes)'; }).join(', ')));
    if (r.answer) { d.appendChild(E('p', null, 'The answer:')); var pre = E('pre', null, r.answer); pre.style.whiteSpace = 'pre-wrap'; d.appendChild(pre); }
    return d;
  }

  function renderVersions() {
    var box = document.getElementById('fx-versions'); clear(box);
    agent.versions.slice().reverse().forEach(function (v) {
      var row = E('div'); row.style.cssText = 'border-top:1px solid var(--border,#3333);padding:var(--space-2) 0';
      var h = E('p'); h.style.margin = '0'; h.appendChild(E('strong', null, 'Version ' + v.number + ' ')); h.appendChild(badge(v.state_label, v.state === 'released' ? 'active' : ''));
      row.appendChild(h);
      row.appendChild(E('p', 'muted', 'Made by ' + who(v.made_by) + ' · last changed by ' + who(v.last_changed_by) + ' on ' + when(v.last_changed_at) + ' · revision ' + v.revision + ' · fingerprint ' + v.config_digest.slice(0, 12)));
      var hist = E('ul'); hist.style.cssText = 'margin:0;padding-left:1.2rem;font-size:var(--text-sm)';
      v.history.slice(-5).forEach(function (x) { hist.appendChild(E('li', 'muted', when(x.at) + ' · ' + who(x.by) + ' · ' + x.what)); });
      row.appendChild(hist);
      box.appendChild(row);
    });
  }

  function agentPage() {
    agent = json('fx-agent');
    var form = document.getElementById('fx-editor');
    if (form) form.addEventListener('submit', async function (ev) {
      ev.preventDefault();
      var t = tip();
      var save = document.getElementById('fx-save'); save.disabled = true;
      var out = await act('PUT', '/api/v1/factory/agents/' + encodeURIComponent(agent.id) + '/definition',
        { parts: readEditor(), base_version: t.number, base_revision: t.revision }, 'save your changes', 'Saved.');
      if (!out) save.disabled = false;
    });
    render(agent);
  }

  document.addEventListener('DOMContentLoaded', function () {
    if (document.getElementById('fx-brief')) newPage();
    else if (document.getElementById('fx-agent')) agentPage();
  });
})();
