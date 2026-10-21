/* Warden admin panel. Classic script, no build step. The DOM is built with createElement and
   textContent only; credentials come from the browser's Basic-auth prompt. */
(function () {
  "use strict";

  var REFRESH_MS = 5000;
  var EVENT_LIMIT = 200;
  var AUTH_MESSAGE = "Authentication required — reload the page";

  var state = {
    activeVersion: null,
    savedText: null, // editor text of the last save that returned valid:true
    editorLoaded: false,
    timer: null,
    eventsBusy: false
  };

  function $(id) { return document.getElementById(id); }

  function isObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
  function asArray(v) { return Array.isArray(v) ? v : []; }
  function asText(v) {
    if (typeof v === "string") { return v; }
    if (typeof v === "number" || typeof v === "boolean") { return String(v); }
    return "";
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined) { node.textContent = text; }
    return node;
  }

  function clear(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
  }

  function showNotice(message) {
    var notice = $("notice");
    notice.textContent = message || "";
    notice.hidden = !message;
  }

  // Resolves to {status, body} or rejects with an Error whose message is user-presentable.
  function api(method, path, body) {
    var init = { method: method, credentials: "same-origin", cache: "no-store", headers: {} };
    if (body !== undefined) {
      init.body = body;
      init.headers["Content-Type"] = "application/json";
    }
    return fetch(path, init).then(function (response) {
      if (response.status === 401) {
        showNotice(AUTH_MESSAGE);
        throw new Error(AUTH_MESSAGE);
      }
      return response.text().then(function (text) {
        var parsed = null;
        try { parsed = JSON.parse(text); } catch (e) { parsed = null; }
        return { status: response.status, body: parsed };
      });
    }, function () {
      throw new Error("Network error");
    });
  }

  /* ---------- tabs ---------- */

  var tabIds = ["policy", "events"];

  function selectTab(name, focus) {
    tabIds.forEach(function (id) {
      var selected = id === name;
      var tab = $("tab-" + id);
      tab.setAttribute("aria-selected", selected ? "true" : "false");
      tab.tabIndex = selected ? 0 : -1;
      $("panel-" + id).hidden = !selected;
      if (selected && focus) { tab.focus(); }
    });
    updateRefresh();
    if (name === "events") { loadEvents(); }
  }

  function initTabs() {
    tabIds.forEach(function (id, index) {
      var tab = $("tab-" + id);
      tab.addEventListener("click", function () { selectTab(id, false); });
      tab.addEventListener("keydown", function (event) {
        var target = null;
        if (event.code === "ArrowRight") { target = tabIds[(index + 1) % tabIds.length]; }
        else if (event.code === "ArrowLeft") { target = tabIds[(index + tabIds.length - 1) % tabIds.length]; }
        else if (event.code === "Home") { target = tabIds[0]; }
        else if (event.code === "End") { target = tabIds[tabIds.length - 1]; }
        if (target) {
          event.preventDefault();
          selectTab(target, true);
        }
      });
    });
  }

  /* ---------- policy ---------- */

  function emptyRow(text, columns) {
    var row = el("tr");
    var cell = el("td", "muted", text);
    cell.colSpan = columns;
    row.appendChild(cell);
    return row;
  }

  function renderRules(policy) {
    var body = $("rules-body");
    clear(body);
    var rules = isObject(policy) ? asArray(policy.rules) : [];
    if (rules.length === 0) {
      body.appendChild(emptyRow("No rules", 5));
      return;
    }
    rules.forEach(function (rule) {
      var r = isObject(rule) ? rule : {};
      var row = el("tr");
      row.appendChild(el("td", "mono", asText(r.id)));
      row.appendChild(el("td", "", asText(r.description)));
      row.appendChild(el("td", "num", String(asArray(r.targets).length)));
      row.appendChild(el("td", "num", String(asArray(r.processes).length)));
      row.appendChild(el("td", "", asText(r.action)));
      body.appendChild(row);
    });
  }

  function setStatus(message, kind) {
    var status = $("status");
    status.textContent = message || "";
    status.className = "status" + (kind ? " " + kind : "");
  }

  function renderErrors(errors) {
    var list = $("errors");
    clear(list);
    asArray(errors).forEach(function (error) {
      var e = isObject(error) ? error : {};
      list.appendChild(el("li", "", asText(e.path) + ": " + asText(e.message)));
    });
  }

  function updatePublish() {
    var button = $("publish");
    var next = typeof state.activeVersion === "number" ? state.activeVersion + 1 : "";
    button.textContent = next === "" ? "Publish" : "Publish v" + next;
    button.disabled = !(state.savedText !== null && $("draft-text").value === state.savedText);
  }

  // Shows the validation result; returns true when it says valid.
  function applyValidation(validation) {
    var v = isObject(validation) ? validation : {};
    var errors = asArray(v.errors);
    renderErrors(errors);
    if (v.valid === true) {
      setStatus("Valid", "ok");
      return true;
    }
    setStatus(errors.length === 1 ? "1 error" : errors.length + " errors", "bad");
    return false;
  }

  function loadPolicy() {
    return api("GET", "/api/v1/admin/policy").then(function (res) {
      var data = isObject(res.body) ? res.body : {};
      var active = isObject(data.active) ? data.active : {};
      var version = typeof active.version === "number" ? active.version : null;
      state.activeVersion = version;
      $("active-badge").textContent = "Active v" + (version === null ? "?" : version);
      renderRules(active.policy);

      var editor = $("draft-text");
      var draft = isObject(data.draft) ? data.draft : null;
      if (!state.editorLoaded) {
        if (draft && typeof draft.text === "string") {
          editor.value = draft.text;
          if (isObject(draft.validation) && applyValidation(draft.validation)) {
            state.savedText = editor.value;
          }
        } else {
          var policy = isObject(active.policy) ? active.policy : { schemaVersion: 1, rules: [] };
          editor.value = JSON.stringify(Object.assign({}, policy, { version: 0 }), null, 2);
        }
        state.editorLoaded = true;
      }
      updatePublish();
    }).catch(function (error) {
      setStatus(error.message, "bad");
    });
  }

  function saveDraft() {
    var text = $("draft-text").value;
    $("save-draft").disabled = true;
    setStatus("Saving…", "");
    api("PUT", "/api/v1/admin/policy/draft", text).then(function (res) {
      if (res.status !== 200) {
        renderErrors([]);
        setStatus("Save failed (HTTP " + res.status + ")", "bad");
        state.savedText = null;
      } else {
        state.savedText = applyValidation(res.body) ? text : null;
      }
      updatePublish();
    }).catch(function (error) {
      setStatus(error.message, "bad");
    }).then(function () {
      $("save-draft").disabled = false;
    });
  }

  function publish() {
    $("publish").disabled = true;
    api("POST", "/api/v1/admin/policy/publish").then(function (res) {
      var body = isObject(res.body) ? res.body : {};
      if (res.status === 200 && typeof body.version === "number") {
        state.savedText = null;
        renderErrors([]);
        setStatus("Published v" + body.version, "ok");
        return loadPolicy();
      }
      if (res.status === 422) {
        renderErrors(body.errors);
        setStatus("The draft is invalid", "bad");
      } else if (res.status === 409) {
        setStatus("There is no draft to publish", "bad");
      } else {
        setStatus("Publish failed (HTTP " + res.status + ")", "bad");
      }
      state.savedText = null;
      updatePublish();
    }).catch(function (error) {
      setStatus(error.message, "bad");
      updatePublish();
    });
  }

  /* ---------- events ---------- */

  function processText(proc) {
    var p = isObject(proc) ? proc : {};
    return asText(p.signingId) || asText(p.path) || "?";
  }

  function formatTime(ts) {
    var text = asText(ts);
    var date = new Date(text);
    return isNaN(date.getTime()) ? text : date.toLocaleString();
  }

  function renderEvents(events) {
    var body = $("events-body");
    clear(body);
    var list = asArray(events);
    if (list.length === 0) {
      body.appendChild(emptyRow("No events", 6));
      return;
    }
    list.forEach(function (item) {
      var e = isObject(item) ? item : {};
      var blocked = e.decision === "deny";
      var row = el("tr");
      row.appendChild(el("td", "", formatTime(e.ts)));
      row.appendChild(el("td", "", asText(e.agentId)));
      var proc = processText(e.process);
      if (isObject(e.responsible)) { proc += " ← " + processText(e.responsible); }
      row.appendChild(el("td", "mono", proc));
      row.appendChild(el("td", "mono", asText(e.file)));
      var decision = el("td");
      decision.appendChild(el("span", "badge " + (blocked ? "blocked" : "ok"), blocked ? "Blocked" : "OK"));
      row.appendChild(decision);
      row.appendChild(el("td", "mono", asText(e.ruleId)));
      body.appendChild(row);
    });
  }

  function loadEvents() {
    if (state.eventsBusy) { return; }
    state.eventsBusy = true;
    api("GET", "/api/v1/admin/events?limit=" + EVENT_LIMIT).then(function (res) {
      if (res.status !== 200) { throw new Error("Could not load events (HTTP " + res.status + ")"); }
      renderEvents(isObject(res.body) ? res.body.events : []);
      $("events-updated").textContent = "Updated " + new Date().toLocaleTimeString();
    }).catch(function (error) {
      $("events-updated").textContent = error.message;
    }).then(function () {
      state.eventsBusy = false;
    });
  }

  function eventsVisible() {
    return !$("panel-events").hidden && !document.hidden;
  }

  function updateRefresh() {
    if (eventsVisible()) {
      if (state.timer === null) { state.timer = window.setInterval(loadEvents, REFRESH_MS); }
    } else if (state.timer !== null) {
      window.clearInterval(state.timer);
      state.timer = null;
    }
  }

  /* ---------- init ---------- */

  function init() {
    initTabs();
    $("save-draft").addEventListener("click", saveDraft);
    $("publish").addEventListener("click", publish);
    $("draft-text").addEventListener("input", updatePublish);
    document.addEventListener("visibilitychange", function () {
      updateRefresh();
      if (eventsVisible()) { loadEvents(); }
    });
    loadPolicy();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
