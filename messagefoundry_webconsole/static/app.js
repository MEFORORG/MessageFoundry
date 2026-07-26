// SPDX-License-Identifier: AGPL-3.0-or-later
// First-party JS for the /ui ops dashboard (ADR 0065). No third-party JS — CSP script-src 'self'.
//
// Dispatch registry: each page feature registers a (hook-selector, init) pair via feature(); on load
// (the script is deferred, so the DOM is parsed) each init runs only if its namespaced data-* hook is
// present on this page. A page lane adds ONE feature() block — parallel lanes never collide on a shared
// entry point. Every fragment swapped in is SERVER-RENDERED and server-escaped (see
// messagefoundry/api/webui/_html.py el()), so no un-escaped message/HL7 data is ever handled here.
(function () {
  "use strict";

  var inits = [];
  function feature(hookSelector, fn) {
    inits.push([hookSelector, fn]);
  }

  // SECURITY controls register here instead, and the runner starts them FIRST (see the bottom of
  // this file). A security control must not share a failure domain with — or be ordered behind —
  // cosmetic page enhancers: the registry is replayed in registration order, so a control sitting
  // ninth of fourteen depended on eight unrelated inits not throwing, on exactly the PHI pages
  // (Messages, Dead letters) it exists to protect. Each init is also isolated in its own try/catch
  // by the runner, so one broken feature can no longer disable the rest.
  var securityInits = [];
  function securityFeature(hookSelector, fn) {
    securityInits.push([hookSelector, fn]);
  }

  // [security].allowed_client_networks: the engine's source-network gate refuses OUTSIDE the app, so a
  // denial is a 403 that matches none of the auth branches below. Without this the pollers would keep
  // painting the last-good table forever and the health box would hide itself as if it were an RBAC
  // outcome — a console that LOOKS alive but is frozen, which is exactly how an operator whose
  // workstation was renumbered mid-session experiences it. The engine marks its network denials with a
  // dedicated header so we can tell them apart from a genuine permission 403 and navigate instead: a
  // full page load lands on the engine's denial page, which names the setting and shows the address the
  // engine actually observed.
  function mfNetworkDenied(resp) {
    return resp.status === 403 && resp.headers.get("X-MessageFoundry-Denied") === "client-network";
  }

  // ASVS 14.3.1 — "the server has ended this session", for a fetch. EVERY fetch below sets
  // redirect:"manual", which is load-bearing and was the bug this replaces: a same-origin 303 is
  // followed TRANSPARENTLY under the default redirect:"follow", so a status test for the redirect
  // could never be observed in a real browser — the expiry branch was dead code and the poller
  // instead assigned a 200 LOGIN PAGE into the container it was refreshing. With redirect:"manual"
  // the auth redirect surfaces as an opaque response (type "opaqueredirect", status 0) that this
  // recognises, so the page actually reloads and the server can send the operator to the login page.
  // The explicit status tests stay for a non-browser client and for the engine answering 401.
  function mfSessionEnded(resp) {
    return (
      resp.type === "opaqueredirect" ||
      resp.status === 0 ||
      resp.status === 303 ||
      resp.status === 401
    );
  }

  // Auto-retry after a successful step-up re-auth: submit the pending action form (server-rendered,
  // same-origin, action already validated as a replay path). Graceful: if this doesn't run, the user
  // clicks the visible "Continue" button instead.
  feature("form[data-autosubmit]", function (pending) {
    pending.submit();
  });

  // Live connections view: poll the same-origin fragment named in data-poll and, when available, take
  // updates over the /ws/stats WebSocket (stopping the poll while the socket is open).
  feature("[data-poll]", function (container) {
    var url = container.getAttribute("data-poll");
    var intervalMs = parseInt(container.getAttribute("data-poll-ms") || "5000", 10);
    if (!url || !(intervalMs > 0)) return;

    async function tick() {
      // Pause the live swap while an operator is dragging a column resize: the swap REPLACES the whole
      // table element, which detaches the <th> being dragged — the column snaps back to its old width and
      // the drag loses its target. The next tick after the drag ends resumes the live view. (The resize
      // feature sets body.mf-col-resizing for the duration of the drag.)
      if (document.body.classList.contains("mf-col-resizing")) return;
      try {
        var resp = await fetch(url, {
          credentials: "same-origin",
          redirect: "manual", // an auth 303 must SURFACE, not be followed into a 200 login page
          headers: { "X-Requested-With": "fetch" },
          cache: "no-store",
        });
        if (resp.ok) {
          // Server-rendered + server-escaped fragment (same-origin); safe to assign as markup.
          var htmlText = await resp.text();
          // Re-check the resize guard AFTER the awaits: a column drag may have started mid-fetch (the
          // top-of-tick check is TOCTOU on its own). Swapping now would detach the <th> being dragged;
          // skip this swap — the next tick resumes the live view.
          if (document.body.classList.contains("mf-col-resizing")) return;
          container.innerHTML = htmlText;
        } else if (mfSessionEnded(resp) || mfNetworkDenied(resp)) {
          // Session expired, or the source-network gate refused us — reload so the server can redirect
          // to the login page / serve its network-denial page instead of freezing on stale data.
          window.location.reload();
        }
      } catch (e) {
        // Transient network/engine hiccup — leave the last good view in place and retry next tick.
      }
    }

    var pollTimer = setInterval(tick, intervalMs);

    // Live updates over the /ws/stats WebSocket (M-ws + enrichment). The server pushes the rendered
    // connections fragment (drives the table) plus the queue-by-status counts. While the socket is open
    // we STOP polling; if it drops we resume the poll (fallback). The same-origin handshake carries the
    // mf_session cookie automatically (browsers can't set the WS Authorization header) — the server
    // authorizes it via that cookie, CSWSH-guarded by a same-origin Origin check + SameSite=Strict.
    // Every update is a server-rendered, already-escaped fragment / store counts — no client-side
    // markup building.
    var livestats = document.getElementById("livestats");
    try {
      var proto = location.protocol === "https:" ? "wss:" : "ws:";
      var ws = new WebSocket(proto + "//" + location.host + "/ws/stats");
      ws.onopen = function () {
        if (pollTimer) {
          clearInterval(pollTimer);
          pollTimer = null;
        }
      };
      ws.onmessage = function (e) {
        try {
          var d = JSON.parse(e.data) || {};
          // Same resize guard as the poll: don't swap the table out from under an in-progress column drag
          // (the livestats counts below are unaffected — they don't touch the table).
          if (
            typeof d.connections_html === "string" &&
            !document.body.classList.contains("mf-col-resizing")
          ) {
            container.innerHTML = d.connections_html; // server-rendered + server-escaped fragment
          }
          if (livestats && d.outbox_by_status) {
            var by = d.outbox_by_status;
            var parts = Object.keys(by).map(function (k) {
              return k + ": " + by[k];
            });
            livestats.textContent = parts.length ? "Queue — " + parts.join("   ") : "";
          }
        } catch (_) {
          /* ignore a malformed frame */
        }
      };
      var resumePoll = function () {
        if (!pollTimer) {
          pollTimer = setInterval(tick, intervalMs);
        }
      };
      ws.onclose = resumePoll;
      ws.onerror = resumePoll;
    } catch (_) {
      /* WebSocket unavailable — the polled table remains the live view */
    }
  });

  // --- Connection controls: bulk-action toolbar over a checkbox selection ----------------------
  // The toolbar (action <select> + Apply + feedback) lives in the STABLE dashboard shell OUTSIDE
  // [data-poll], so its init runs once and the 5s poll / ~1s /ws/stats swaps that replace #conns never
  // wipe it. The per-row checkboxes DO live inside #conns and are destroyed on every swap — a JS Set
  // keyed by the stable server-minted _row_key (checkbox .value) survives it, the change listener is
  // DELEGATED to the persistent [data-poll] node, and a MutationObserver re-hydrates cb.checked after
  // each swap. Purge eligibility keys on data-paused (paused AND quiesced), NOT the collapsed display
  // status, so a failed/filtered-but-paused outbound stays purgeable. JS filtering is UX-only — the
  // engine is the sole authority for the role/state matrix. CSP script-src 'self': DOM APIs +
  // programmatic form submit / window.location only, NEVER innerHTML from connection data.
  feature("[data-mf-conns-toolbar]", function (toolbar) {
    var poll = document.querySelector("[data-poll]");
    if (!poll) return; // no live table on this page → nothing to drive
    var select = toolbar.querySelector("[data-mf-conns-action]");
    var applyBtn = toolbar.querySelector("[data-mf-conns-apply]");
    var feedback = toolbar.querySelector("[data-mf-conns-feedback]");
    var selected = new Set(); // keyed by checkbox .value (the stable _row_key)

    function rowCheckboxes() {
      return poll.querySelectorAll("[data-mf-conns-cb]");
    }
    function selectAllBox() {
      return poll.querySelector("[data-mf-conns-all]");
    }
    function actionLabel(a) {
      switch (a) {
        case "start":
          return "Start";
        case "stop":
          return "Stop";
        case "restart":
          return "Restart";
        case "reset":
          return "Reset stats";
        case "purge-top":
          return "Purge top";
        case "purge-all":
          return "Purge all";
        default:
          return a;
      }
    }

    // Partition the live selection for the chosen action. Purge keeps only a stopped-AND-quiesced
    // outbound (data-role destination && data-paused==='1'), deduped by destination; every other action
    // accepts both roles. Reads data-* LIVE from the DOM so a status that flipped under the poll is
    // honored. Returns the eligible targets + skip counts (UX only; the server re-derives eligibility).
    function plan() {
      var action = select ? select.value : "";
      var isPurge = action === "purge-top" || action === "purge-all";
      var keys = []; // row keys for bulk-control / reset-many (both roles)
      var seenDest = {};
      var dests = []; // deduped destinations for purge
      var skippedInbound = 0;
      var skippedNotStopped = 0;
      var cbs = rowCheckboxes();
      for (var i = 0; i < cbs.length; i++) {
        var cb = cbs[i];
        if (!selected.has(cb.value)) continue;
        if (isPurge) {
          if (cb.getAttribute("data-role") !== "destination") {
            skippedInbound++;
            continue;
          }
          if (cb.getAttribute("data-paused") !== "1") {
            skippedNotStopped++;
            continue;
          }
          var dest = cb.getAttribute("data-dest") || "";
          if (!Object.prototype.hasOwnProperty.call(seenDest, dest)) {
            seenDest[dest] = true;
            dests.push(dest);
          }
        } else {
          keys.push(cb.value);
        }
      }
      return {
        action: action,
        isPurge: isPurge,
        keys: keys,
        dests: dests,
        skippedInbound: skippedInbound,
        skippedNotStopped: skippedNotStopped,
      };
    }

    // Recompute the feedback string + enable Apply only when ≥1 eligible target.
    function refresh() {
      var p = plan();
      var label = actionLabel(p.action);
      var eligible = p.isPurge ? p.dests.length : p.keys.length;
      var msg;
      if (p.isPurge) {
        msg = label + " → " + p.dests.length + " outbound" + (p.dests.length === 1 ? "" : "s");
        var skips = p.skippedInbound + p.skippedNotStopped;
        if (skips > 0) {
          var reasons = [];
          if (p.skippedInbound) reasons.push(p.skippedInbound + " inbound");
          if (p.skippedNotStopped) reasons.push(p.skippedNotStopped + " not-stopped");
          msg += "; skipped " + skips + ": " + reasons.join(", ");
        }
      } else if (eligible === 0) {
        msg = ""; // idle: no clutter text — feedback only appears once an action targets a selection
      } else {
        msg = label + " → " + eligible + " selected";
      }
      if (feedback) feedback.textContent = msg;
      if (applyBtn) applyBtn.disabled = eligible < 1;
    }

    // Recompute the select-all header checkbox's checked/indeterminate from the live Set.
    function syncSelectAll() {
      var box = selectAllBox();
      if (!box) return;
      var cbs = rowCheckboxes();
      var checked = 0;
      for (var i = 0; i < cbs.length; i++) {
        if (selected.has(cbs[i].value)) checked++;
      }
      box.checked = cbs.length > 0 && checked === cbs.length;
      box.indeterminate = checked > 0 && checked < cbs.length;
    }

    // After every swap (poll tick AND ws push): re-apply cb.checked from the Set, recompute select-all,
    // and PRUNE any key whose input has vanished (a removed/reconfigured connection). Strictly
    // read-value/set-checked — never innerHTML, and it never suppresses the swap (the operator must keep
    // seeing status flip running→stopping→stopped, which is what unlocks Purge).
    function rehydrate() {
      var cbs = rowCheckboxes();
      var present = {};
      for (var i = 0; i < cbs.length; i++) {
        present[cbs[i].value] = true;
        cbs[i].checked = selected.has(cbs[i].value);
      }
      selected.forEach(function (key) {
        if (!present[key]) selected.delete(key);
      });
      syncSelectAll();
      refresh();
    }

    // Build + submit a transient same-origin POST form (never innerHTML). actionValue is the
    // bulk-control action (start/stop/restart); null for reset-many (which takes only repeated sel).
    function submitBulk(url, actionValue, keys) {
      var form = document.createElement("form");
      form.method = "post";
      form.action = url;
      if (actionValue != null) {
        var a = document.createElement("input");
        a.type = "hidden";
        a.name = "action";
        a.value = actionValue;
        form.appendChild(a);
      }
      for (var i = 0; i < keys.length; i++) {
        var inp = document.createElement("input");
        inp.type = "hidden";
        inp.name = "sel";
        inp.value = keys[i];
        form.appendChild(inp);
      }
      document.body.appendChild(form);
      form.submit();
    }

    // Delegated to the persistent [data-poll] node (only its children are swapped): a row checkbox
    // toggles its .value in the Set; the select-all box checks/unchecks every rendered row + syncs.
    poll.addEventListener("change", function (ev) {
      var t = ev.target;
      if (!t || !t.hasAttribute) return;
      if (t.hasAttribute("data-mf-conns-cb")) {
        if (t.checked) selected.add(t.value);
        else selected.delete(t.value);
        syncSelectAll();
        refresh();
      } else if (t.hasAttribute("data-mf-conns-all")) {
        var cbs = rowCheckboxes();
        for (var i = 0; i < cbs.length; i++) {
          // Select-all applies to the VISIBLE rows only: when checking, skip a row the filter has hidden
          // (offsetParent is null for a display:none row) so the operator never sweeps in — and then
          // Stop/Restart/Reset — connections they can't see. Unchecking still clears every row.
          if (t.checked && cbs[i].offsetParent === null) continue;
          cbs[i].checked = t.checked;
          if (t.checked) selected.add(cbs[i].value);
          else selected.delete(cbs[i].value);
        }
        refresh();
      }
    });

    if (select) select.addEventListener("change", refresh);

    if (applyBtn) {
      applyBtn.addEventListener("click", function () {
        var p = plan();
        if (p.isPurge) {
          if (p.dests.length < 1) return;
          var scope = p.action === "purge-all" ? "all" : "top";
          // A step-up + dual-control destructive op: NAVIGATE (GET) into the server's unlock/confirm
          // flow — deliberately NOT a fetch, so the opaqueredirect success-vs-step-up ambiguity that
          // would sink a fetch-loop never arises. The confirm page carries its own POST to purge-bulk.
          var q = "/ui/connections/purge-confirm?scope=" + encodeURIComponent(scope);
          for (var i = 0; i < p.dests.length; i++) {
            q += "&dest=" + encodeURIComponent(p.dests[i]);
          }
          window.location.assign(q);
          return;
        }
        if (p.keys.length < 1) return;
        if (p.action === "reset") {
          submitBulk("/ui/statistics/reset-many", null, p.keys);
        } else {
          submitBulk("/ui/connections/bulk-control", p.action, p.keys);
        }
      });
    }

    // Re-hydrate on every #conns swap (poll + ws), and once now (the fragment is already rendered).
    new MutationObserver(rehydrate).observe(poll, { childList: true, subtree: true });
    rehydrate();
  });

  // --- L5a: WebAuthn passkey ceremonies (ADR 0068 §6) -----------------------------------------
  // The ceremony OPTIONS ride server-rendered data-* attributes (never an inline script — CSP is
  // 'self'-only); only the verify legs are fetch POSTs. Progressive enhancement: without
  // window.PublicKeyCredential the buttons explain themselves and the TOTP/password path is
  // untouched. Buttons are disabled for the ceremony's duration (a double-click would race the
  // sign-count compare-and-set into a false clone signal). fetch uses redirect:"manual" — a stale
  // step-up 303 surfaces as an opaqueredirect we can act on (following it would innerHTML a login
  // page — the dead branch lesson from the poll feature).

  function b64urlToBytes(s) {
    var pad = "===".slice(0, (4 - (s.length % 4)) % 4);
    var raw = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out.buffer;
  }
  function bytesToB64url(buf) {
    var bytes = new Uint8Array(buf);
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function statusNode(button) {
    var node = document.querySelector("[data-mf-webauthn-status]");
    return {
      set: function (text) {
        if (node) node.textContent = text;
      },
    };
  }

  // Registration: parse the creation options from the data attribute, run the browser ceremony,
  // POST the attestation + label to the verify endpoint, then navigate per the server's answer.
  feature("[data-mf-webauthn-create]", function (button) {
    var status = statusNode(button);
    if (!window.PublicKeyCredential) {
      button.disabled = true;
      status.set("This browser does not support passkeys.");
      return;
    }
    button.addEventListener("click", async function () {
      var labelInput = document.querySelector("input[name=label]");
      var label = labelInput ? labelInput.value.trim() : "";
      if (!label) {
        status.set("Name this passkey first.");
        return;
      }
      button.disabled = true;
      status.set("Follow your browser's prompt…");
      try {
        var options = JSON.parse(button.getAttribute("data-mf-webauthn-create"));
        options.challenge = b64urlToBytes(options.challenge);
        options.user.id = b64urlToBytes(options.user.id);
        (options.excludeCredentials || []).forEach(function (c) {
          c.id = b64urlToBytes(c.id);
        });
        var cred = await navigator.credentials.create({ publicKey: options });
        var resp = await fetch("/ui/account/webauthn/verify", {
          method: "POST",
          credentials: "same-origin",
          redirect: "manual",
          headers: { "Content-Type": "application/json", "X-Requested-With": "fetch" },
          cache: "no-store",
          body: JSON.stringify({
            label: label,
            response: {
              id: cred.id,
              rawId: bytesToB64url(cred.rawId),
              type: cred.type,
              clientExtensionResults: cred.getClientExtensionResults(),
              response: {
                clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
                attestationObject: bytesToB64url(cred.response.attestationObject),
                transports:
                  cred.response.getTransports && cred.response.getTransports(),
              },
            },
          }),
        });
        if (resp.type === "opaqueredirect") {
          // Stale step-up window mid-ceremony: walk the registered continuation explicitly.
          window.location.assign(
            "/ui/reauth?next=" + encodeURIComponent("/ui/account/webauthn/enroll")
          );
          return;
        }
        var data = await resp.json();
        if (data.ok && data.redirect) {
          window.location.assign(data.redirect);
          return;
        }
        status.set(data.error || "Passkey enrollment failed.");
      } catch (e) {
        status.set("Passkey enrollment was cancelled or failed.");
      }
      button.disabled = false;
    });
  });

  // Step-up assertion: run the get() ceremony against the staged options and POST the assertion
  // to the reauth passkey leg. On success the MFA leg is satisfied — the operator still enters
  // the password below (the mandatory leg that stamps step-up freshness + re-anchors, ADR 0068).
  feature("[data-mf-webauthn-get]", function (button) {
    var status = statusNode(button);
    if (!window.PublicKeyCredential) {
      button.disabled = true;
      status.set("This browser does not support passkeys — use your password/code.");
      return;
    }
    button.addEventListener("click", async function () {
      button.disabled = true;
      status.set("Follow your browser's prompt…");
      try {
        var options = JSON.parse(button.getAttribute("data-mf-webauthn-get"));
        options.challenge = b64urlToBytes(options.challenge);
        (options.allowCredentials || []).forEach(function (c) {
          c.id = b64urlToBytes(c.id);
        });
        var cred = await navigator.credentials.get({ publicKey: options });
        var resp = await fetch("/ui/reauth/webauthn", {
          method: "POST",
          credentials: "same-origin",
          redirect: "manual",
          headers: { "Content-Type": "application/json", "X-Requested-With": "fetch" },
          cache: "no-store",
          body: JSON.stringify({
            response: {
              id: cred.id,
              rawId: bytesToB64url(cred.rawId),
              type: cred.type,
              clientExtensionResults: cred.getClientExtensionResults(),
              response: {
                clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
                authenticatorData: bytesToB64url(cred.response.authenticatorData),
                signature: bytesToB64url(cred.response.signature),
                userHandle:
                  cred.response.userHandle && bytesToB64url(cred.response.userHandle),
              },
            },
          }),
        });
        if (resp.type === "opaqueredirect") {
          window.location.reload(); // session expired — let the server redirect to login
          return;
        }
        var data = await resp.json();
        if (data.ok) {
          // ASVS 6.3.3: on the /ui/mfa sign-in gate the assertion COMPLETES the ceremony — there is
          // no password still owed, so navigate. Without this a passkey-only user (no TOTP, so no
          // code field and no submit button on that page) verifies successfully and is stranded on
          // a dead page, which is the deadlock ADR 0068 decision 1(d) exists to prevent.
          var done = button.getAttribute("data-mf-webauthn-done");
          if (done) {
            status.set("Passkey verified — continuing…");
            window.location.assign(done);
            return;
          }
          // On the step-up reauth page the password is still owed, so stay put and unlock it.
          status.set("Passkey verified — enter your password to continue.");
          var codeInput = document.querySelector("input[name=code]");
          if (codeInput) codeInput.disabled = true; // either factor satisfies; this one just did
          var pw = document.querySelector("input[name=password]");
          if (pw) pw.focus();
          return; // leave the button disabled: the ceremony is done for this challenge
        }
        status.set(data.error || "Passkey verification failed.");
      } catch (e) {
        status.set("Passkey prompt was cancelled or failed.");
      }
      button.disabled = false;
    });
  });

  // --- Adjustable tables: click-to-sort + drag-to-resize columns, remembered per table -----------
  // Enhances every server-rendered grid table (data-mf-table, emitted by _html.rows_table). Pure DOM
  // APIs only — never innerHTML from cell data (CSP script-src 'self'; cells are already server-escaped;
  // sort/compare read textContent). Sort is CLIENT-SIDE: it reorders the rows currently in the tbody —
  // exact for full-data tables; on the server-paginated Messages/Dead-letters it sorts the shown page
  // only (by design, owner-chosen: zero engine changes). Column widths + the last sort persist in
  // localStorage keyed by pathname + the table's ordinal on the page, so they survive reloads AND the
  // Connections poll/ws swaps (which REPLACE the table element — a MutationObserver on [data-poll]
  // re-enhances the fresh table and re-applies both). Coexists with the connections checkbox selection,
  // which is keyed by row value, so reordering rows never disturbs it. localStorage failures (private
  // mode / quota) degrade to session-only, never throw.
  feature("[data-mf-table]", function () {
    var PREFIX = "mfcols:v2:"; // v2: reset stale widths once so the fill-to-container default applies
    var MINW = 50; // minimum column width (px)
    var reorderFrom = null; // ORIGINAL index of the column being drag-reordered (one drag at a time)
    function readState(key) {
      try {
        return JSON.parse(localStorage.getItem(PREFIX + key)) || {};
      } catch (_) {
        return {};
      }
    }
    function writeState(key, st) {
      try {
        localStorage.setItem(PREFIX + key, JSON.stringify(st));
      } catch (_) {
        /* private mode / quota — this session's adjustments simply don't persist */
      }
    }
    // Ordinal among all enhanced tables on the page — stable across reload AND a live swap (the
    // connections fragment always renders one table at the same position).
    function tableKey(table) {
      var all = document.querySelectorAll("[data-mf-table]");
      return location.pathname + "#" + Array.prototype.indexOf.call(all, table);
    }

    // Detect a column's sort type by sampling its body cells: numeric (counts) / date / text.
    function colType(tbody, ci) {
      var numeric = true,
        dateish = true,
        seen = 0;
      for (var i = 0; i < tbody.rows.length && seen < 16; i++) {
        var cell = tbody.rows[i].cells[ci];
        if (!cell) continue;
        var t = cell.textContent.trim();
        if (!t || t === "—") continue; // skip blanks / em-dash placeholders
        seen++;
        // Numeric only when the WHOLE token is a number (+ optional unit like "5s"/"12%"/"1,234") — a
        // bare parseFloat would accept the leading year of "2026-07-07 ..." and mis-tag timestamps as num.
        if (numeric && !/^-?[\d,]+(\.\d+)?\s*[a-z%]*$/i.test(t)) numeric = false;
        if (dateish && isNaN(Date.parse(t))) dateish = false;
      }
      if (seen === 0) return "text";
      // Numeric wins over date (a bare "2026" is a count, not a year); a year-first timestamp fails the
      // strict numeric test above and falls through to date.
      return numeric ? "num" : dateish ? "date" : "text";
    }
    function cellVal(tr, ci, type) {
      var cell = tr.cells[ci];
      var t = cell ? cell.textContent.trim() : "";
      if (type === "num") {
        var n = parseFloat(t.replace(/[, ]/g, ""));
        return isNaN(n) ? -Infinity : n;
      }
      if (type === "date") {
        var d = Date.parse(t);
        return isNaN(d) ? -Infinity : d;
      }
      return t.toLowerCase();
    }
    // Reorder the tbody. dir "none" restores the server/original ROW order captured in data-mf-ord. The
    // column is identified by its stable ORIGINAL index; we sort by its CURRENT display position so a
    // reordered column still sorts the right cells.
    function applySort(table, orig, dir) {
      var tbody = table.tBodies[0];
      if (!tbody) return;
      var ci = displayIdx(table, orig);
      var rows = Array.prototype.slice.call(tbody.rows);
      if (dir === "none") {
        rows.sort(function (a, b) {
          return (+a.getAttribute("data-mf-ord") || 0) - (+b.getAttribute("data-mf-ord") || 0);
        });
      } else {
        var type = colType(tbody, ci);
        var sign = dir === "asc" ? 1 : -1;
        rows.sort(function (a, b) {
          var va = cellVal(a, ci, type),
            vb = cellVal(b, ci, type);
          return va < vb ? -sign : va > vb ? sign : 0;
        });
      }
      for (var i = 0; i < rows.length; i++) tbody.appendChild(rows[i]);
    }
    // Map a stable ORIGINAL column index to its CURRENT display position (cellIndex) — columns reorder,
    // so state keys by the original index and looks up the live position on demand.
    function displayIdx(table, orig) {
      var cells = table.tHead ? table.tHead.rows[0].cells : [];
      for (var i = 0; i < cells.length; i++) {
        if (+cells[i].getAttribute("data-mf-orig") === orig) return i;
      }
      return orig;
    }
    // The current column order = the sequence of ORIGINAL indices in display order.
    function currentOrder(table) {
      var cells = table.tHead ? table.tHead.rows[0].cells : [],
        o = [];
      for (var i = 0; i < cells.length; i++) o.push(+cells[i].getAttribute("data-mf-orig"));
      return o;
    }
    // Reorder <col>s, header <th>s, and every body <td> to the given display order (array of ORIGINAL
    // indices). Uniform: every element carries data-mf-orig, so it works from any current arrangement —
    // used to apply a saved order onto a fresh server render AND to commit a drag.
    function applyOrder(table, order) {
      if (!order || !order.length) return;
      var parents = [];
      var cg = table.querySelector("colgroup.mf-cols");
      if (cg) parents.push(cg);
      if (table.tHead && table.tHead.rows[0]) parents.push(table.tHead.rows[0]);
      var tb = table.tBodies[0];
      if (tb) for (var r = 0; r < tb.rows.length; r++) parents.push(tb.rows[r]);
      for (var p = 0; p < parents.length; p++) {
        var byOrig = {},
          kids = parents[p].children;
        for (var k = 0; k < kids.length; k++) byOrig[kids[k].getAttribute("data-mf-orig")] = kids[k];
        for (var j = 0; j < order.length; j++) {
          var c = byOrig[order[j]];
          if (c) parents[p].appendChild(c); // appendChild moves it — builds display order left→right
        }
      }
    }
    // Widths live on an injected <colgroup class="mf-cols">; the table width is their SUM, so there is no
    // leftover space to redistribute (the "snaps back wider" fix). Store the intended number, never read
    // back offsetWidth (which would drift on each refresh).
    function colsOf(table) {
      var cg = table.querySelector("colgroup.mf-cols");
      return cg ? cg.children : [];
    }
    function applyWidths(table, widths) {
      var cols = colsOf(table),
        sum = 0;
      for (var i = 0; i < cols.length; i++) {
        var o = cols[i].getAttribute("data-mf-orig");
        var w = widths[o == null ? i : o]; // widths keyed by ORIGINAL index (stable across reorder)
        if (w) {
          cols[i].style.width = w + "px";
          sum += w;
        }
      }
      if (sum) table.style.width = sum + "px";
    }
    // aria-sort + arrow on exactly the active column (by ORIGINAL index); "none" (orig -1) clears all.
    function markHeaders(table, orig, dir) {
      var cells = table.tHead ? table.tHead.rows[0].cells : [];
      for (var i = 0; i < cells.length; i++) {
        var active = +cells[i].getAttribute("data-mf-orig") === orig && dir !== "none";
        var arrow = cells[i].querySelector(".mf-sort-arrow");
        if (arrow) arrow.textContent = active ? (dir === "asc" ? " ▲" : " ▼") : "";
        if (active) cells[i].setAttribute("aria-sort", dir === "asc" ? "ascending" : "descending");
        else cells[i].removeAttribute("aria-sort");
      }
    }

    function enhance(table) {
      if (table.__mfEnhanced) return; // this element is already wired
      table.__mfEnhanced = true;
      var head = table.tHead && table.tHead.rows[0];
      if (!head) return;
      var st = readState(tableKey(table));
      var ncols = head.cells.length;

      // Contain a widened table's horizontal overflow to the table, not the page.
      if (!table.parentElement || !table.parentElement.classList.contains("mf-table-scroll")) {
        var wrap = document.createElement("div");
        wrap.className = "mf-table-scroll";
        table.parentNode.insertBefore(wrap, table);
        wrap.appendChild(table);
      }

      // Tag each row with its server/original ROW order (for tri-state "none") and each cell with its
      // original COLUMN index (so applyOrder can permute the <td>s by data-mf-orig).
      var tb = table.tBodies[0];
      if (tb)
        Array.prototype.forEach.call(tb.rows, function (r, i) {
          r.setAttribute("data-mf-ord", i);
          for (var c = 0; c < r.cells.length; c++) r.cells[c].setAttribute("data-mf-orig", c);
        });

      // Capture each column's natural width BEFORE fixed layout so the initial look is unchanged; a
      // stored width (the intended number) wins when present.
      var natural = [];
      Array.prototype.forEach.call(head.cells, function (th) {
        natural.push(th.offsetWidth);
      });
      var widths = [];
      for (var wi = 0; wi < ncols; wi++) widths[wi] = (st.widths && st.widths[wi]) || natural[wi];

      // Fill to the container's right edge. The table uses an explicit width = sum(col widths) so a resized
      // column keeps its exact width (no width:100% "snap back wider" redistribution). But when that sum
      // falls SHORT of the space available — few columns, or remembered narrow widths — the table stops
      // before the right edge. Grow the LAST resizable column to absorb the slack so the table stays flush
      // with the container's right edge (a real data-grid look); the other columns keep their exact widths.
      // When columns already overflow (sum >= space) it's left alone → horizontal scroll, unchanged. Uses the
      // scroll-wrap's clientWidth (padding-box, minus any scrollbar); it's re-run on each poll re-enhance, so
      // the live table re-fills after a window resize.
      var availW = table.parentElement ? table.parentElement.clientWidth : 0;
      var sumW = 0;
      for (var sw = 0; sw < widths.length; sw++) sumW += widths[sw];
      var noStored = !(st.widths && st.widths.length);
      if (availW && sumW) {
        var lastIdx = ncols - 1;
        while (lastIdx > 0 && head.cells[lastIdx].querySelector("input")) lastIdx--; // skip control cols
        var delta = availW - sumW;
        if (delta > 0) {
          widths[lastIdx] += delta; // grow the last column to reach the right edge
        } else if (noStored && -delta <= 32 && widths[lastIdx] + delta >= MINW) {
          // Trim a SMALL rounding overshoot on a fresh table: the natural widths are summed integer
          // offsetWidths (border-box), which can total a few px OVER the container and trip overflow-x:auto —
          // a spurious horizontal scrollbar on a table that visually fits (e.g. the narrow key/value info
          // tables on the connection-detail + status pages). A large (content-driven) overflow is left to
          // scroll, and a user-resized column (stored widths) is never trimmed.
          widths[lastIdx] += delta;
        }
      }
      table.__mfWidths = widths.slice(); // seed for a first resize (numeric intent, never offsetWidth)

      // Inject <colgroup> + switch to fixed layout with an explicit table width = sum(widths). Each
      // <col> carries data-mf-orig so widths stay keyed to their column through a reorder.
      var cg = document.createElement("colgroup");
      cg.className = "mf-cols";
      for (var ci0 = 0; ci0 < ncols; ci0++) {
        var col0 = document.createElement("col");
        col0.setAttribute("data-mf-orig", ci0);
        cg.appendChild(col0);
      }
      table.insertBefore(cg, table.firstChild);
      table.classList.add("mf-adjustable");
      applyWidths(table, widths);

      Array.prototype.forEach.call(head.cells, function (th, ci) {
        th.setAttribute("data-mf-orig", ci); // stable column identity (state keys + reorder)
        // Skip control columns (the connections select-all checkbox): width only, no sort/resize/reorder.
        if (th.querySelector("input")) return;

        // Sort: wrap the header label in a native <button> (Enter/Space + focus for free — W3C APG).
        if (!th.querySelector(".mf-sort")) {
          var btn = document.createElement("button");
          btn.type = "button";
          btn.className = "mf-sort";
          while (th.firstChild) btn.appendChild(th.firstChild); // move the (server-escaped) label in
          var arrow = document.createElement("span");
          arrow.className = "mf-sort-arrow";
          btn.appendChild(arrow);
          th.appendChild(btn);
          btn.addEventListener("click", function () {
            var cur = readState(tableKey(table));
            var dir; // tri-state cycle: unsorted/other → asc → desc → none
            if (cur.sortCol !== ci) dir = "asc";
            else if (cur.sortDir === "asc") dir = "desc";
            else if (cur.sortDir === "desc") dir = "none";
            else dir = "asc";
            if (dir === "none") {
              delete cur.sortCol;
              delete cur.sortDir;
            } else {
              cur.sortCol = ci;
              cur.sortDir = dir;
            }
            writeState(tableKey(table), cur);
            applySort(table, ci, dir);
            markHeaders(table, dir === "none" ? -1 : ci, dir);
          });
        }

        // Resize: a handle that is a SIBLING of the sort button, so a drag never lands on the button.
        if (!th.querySelector(".mf-resize")) {
          var handle = document.createElement("span");
          handle.className = "mf-resize";
          th.appendChild(handle);
          // Pointer Events + setPointerCapture: the drag keeps receiving pointermove/pointerup even off
          // the handle/window, so it never gets stuck; pointerup/pointercancel always fire, clearing the
          // mf-col-resizing flag (which pauses the live swap so a refresh cannot detach the dragged column).
          handle.addEventListener("pointerdown", function (ev) {
            ev.preventDefault();
            ev.stopPropagation();
            handle.setPointerCapture(ev.pointerId);
            var w = (readState(tableKey(table)).widths || table.__mfWidths).slice();
            var startX = ev.clientX,
              startW = w[ci] || natural[ci];
            document.body.classList.add("mf-col-resizing");
            function move(e) {
              w[ci] = Math.max(MINW, startW + (e.clientX - startX));
              applyWidths(table, w);
            }
            function end() {
              handle.removeEventListener("pointermove", move);
              handle.removeEventListener("pointerup", end);
              handle.removeEventListener("pointercancel", end);
              handle.removeEventListener("lostpointercapture", end);
              document.body.classList.remove("mf-col-resizing");
              var cur = readState(tableKey(table));
              cur.widths = w; // persist the INTENDED numbers, not a measured offsetWidth
              writeState(tableKey(table), cur);
              table.__mfWidths = w.slice();
            }
            handle.addEventListener("pointermove", move);
            handle.addEventListener("pointerup", end);
            handle.addEventListener("pointercancel", end);
            // Defense-in-depth: if the captured handle is ever removed from the DOM mid-drag (a full
            // re-render), the browser fires lostpointercapture — run end() so the flag can never wedge.
            handle.addEventListener("lostpointercapture", end);
          });
          // Double-click a handle: reset that column to its natural width.
          handle.addEventListener("dblclick", function (ev) {
            ev.preventDefault();
            ev.stopPropagation();
            var cur = readState(tableKey(table));
            var w2 = (cur.widths || table.__mfWidths).slice();
            w2[ci] = natural[ci];
            applyWidths(table, w2);
            cur.widths = w2;
            writeState(tableKey(table), cur);
            table.__mfWidths = w2.slice();
          });
        }

        // Reorder: native drag-and-drop on the header. Dragging the header body reorders the column; the
        // sort button (click) and the resize handle (its pointerdown preventDefault suppresses the native
        // drag) stay separate gestures. The checkbox column returned above, so it is never draggable.
        th.draggable = true;
        th.addEventListener("dragstart", function (ev) {
          reorderFrom = +th.getAttribute("data-mf-orig");
          try {
            ev.dataTransfer.effectAllowed = "move";
            ev.dataTransfer.setData("text/plain", String(reorderFrom));
          } catch (_) {}
        });
        th.addEventListener("dragover", function (ev) {
          if (reorderFrom == null) return;
          ev.preventDefault(); // permit the drop
          th.classList.add("mf-drop");
        });
        th.addEventListener("dragleave", function () {
          th.classList.remove("mf-drop");
        });
        th.addEventListener("drop", function (ev) {
          ev.preventDefault();
          th.classList.remove("mf-drop");
          var toOrig = +th.getAttribute("data-mf-orig");
          if (reorderFrom == null || reorderFrom === toOrig) return;
          var order = currentOrder(table);
          var fp = order.indexOf(reorderFrom),
            tp = order.indexOf(toOrig);
          if (fp < 0 || tp < 0) return;
          order.splice(fp, 1);
          order.splice(tp, 0, reorderFrom); // move the dragged column to the drop target's slot
          applyOrder(table, order);
          var cur = readState(tableKey(table));
          cur.order = order;
          writeState(tableKey(table), cur);
        });
        th.addEventListener("dragend", function () {
          reorderFrom = null;
          var hcells = table.tHead ? table.tHead.rows[0].cells : [];
          for (var i = 0; i < hcells.length; i++) hcells[i].classList.remove("mf-drop");
        });
      });

      // Apply a saved column order onto this (freshly server-rendered, original-order) table.
      if (st.order && st.order.length === ncols) applyOrder(table, st.order);

      // Re-apply a remembered sort to this render (sortCol is the stable ORIGINAL column index).
      if (typeof st.sortCol === "number" && st.sortCol < ncols) {
        applySort(table, st.sortCol, st.sortDir || "asc");
        markHeaders(table, st.sortCol, st.sortDir || "asc");
      }
    }

    function enhanceAll() {
      var tables = document.querySelectorAll("[data-mf-table]");
      for (var i = 0; i < tables.length; i++) enhance(tables[i]);
    }
    enhanceAll();
    // The connections table is the only live one: its [data-poll] container swaps in a fresh table each
    // tick — re-enhance it (idempotent; enhanced elements are skipped). Static pages need no observer.
    var poll = document.querySelector("[data-poll]");
    if (poll) new MutationObserver(enhanceAll).observe(poll, { childList: true, subtree: true });
  });

  // --- Connections filter box: hide rows that don't match the typed query + the Flagged-only toggle ---
  // Both controls live in the un-polled shell, so their state survives the ~1s live swap; app.js filters
  // the table's rows and re-applies after each poll/ws swap (MutationObserver on [data-poll]). A row is
  // visible iff (text query matches) AND (Flagged-only off OR the row's selection checkbox is
  // data-flagged="1", #131). display:none only — the server still sends every row and a hidden row's
  // checkbox stays in the selection Set (the filter is view-only). Coexists with sort + column resize.
  feature("[data-mf-conns-filter]", function (input) {
    var poll = document.querySelector("[data-poll]");
    if (!poll) return; // no live table on this page
    var flaggedOnly = document.querySelector("[data-mf-conns-flagged]");
    function apply() {
      var q = input.value.trim().toLowerCase();
      var onlyFlagged = !!(flaggedOnly && flaggedOnly.checked);
      var rows = poll.querySelectorAll("tbody tr");
      for (var i = 0; i < rows.length; i++) {
        var textHit = !q || rows[i].textContent.toLowerCase().indexOf(q) !== -1;
        var cb = rows[i].querySelector("[data-mf-conns-cb]");
        var flagHit = !onlyFlagged || (cb && cb.getAttribute("data-flagged") === "1");
        rows[i].style.display = textHit && flagHit ? "" : "none";
      }
    }
    input.addEventListener("input", apply);
    if (flaggedOnly) flaggedOnly.addEventListener("change", apply);
    // Re-apply after each swap (fresh rows) and after a sort re-append. Style-only changes don't feed
    // back into this observer (it watches childList), so no loop.
    new MutationObserver(apply).observe(poll, { childList: true, subtree: true });
    apply();
  });

  // --- Generic fragment poller (BACKLOG #76) -------------------------------------------------------
  // Fetch a server-rendered, server-escaped fragment named in data-fragment-url on an interval and swap
  // it into this container's innerHTML. Used by the Flow & trends page (/ui/monitoring/live) so the
  // status-colored inline-SVG data-flow graph + the queue-trend chart refresh without a WebSocket. A
  // DISTINCT hook from [data-poll] (no ws, no connections-table entanglement); same server-render
  // security model — the fragment is already escaped, never client-built markup (CSP script-src 'self').
  // The initial content is server-rendered into the container, so the first swap is one interval later.
  feature("[data-mf-fragment]", function (container) {
    var url = container.getAttribute("data-fragment-url");
    var ms = parseInt(container.getAttribute("data-fragment-ms") || "5000", 10);
    if (!url || !(ms > 0)) return;
    async function tick() {
      try {
        var resp = await fetch(url, {
          credentials: "same-origin",
          redirect: "manual", // an auth 303 must SURFACE, not be followed into a 200 login page
          headers: { "X-Requested-With": "fetch" },
          cache: "no-store",
        });
        if (resp.ok) {
          container.innerHTML = await resp.text(); // server-rendered + server-escaped fragment
        } else if (mfSessionEnded(resp) || mfNetworkDenied(resp)) {
          // Session expired, or the source-network gate refused us — never freeze on stale data.
          window.location.reload();
        }
      } catch (e) {
        // Transient network/engine hiccup — leave the last good view in place and retry next tick.
      }
    }
    setInterval(tick, ms);
  });

  // --- Live engine-health + alerts nav glyphs ------------------------------------------------------
  // ---------------------------------------------------------------------------------------------
  // SESSION WATCHDOG (ASVS 14.3.1). A rendered console page can hold PHI in the DOM long after the
  // server has ended the session — the tab keeps showing it because nothing asks. This discards it.
  //
  // Anchored to the SERVER, never to local DOM activity. That distinction is the whole control: the
  // server's idle clock only advances on real requests, so a watchdog reset by mouse/keyboard would
  // sit happily on a poll-less PHI page keeping the rendered chart alive for hours after the session
  // it belongs to was terminated — precisely the exposure this requirement is about. Three legs, all
  // server-derived:
  //
  //   1. VERDICT — GET /ui/session-status with redirect:"manual". The server 303s to the login page
  //      the moment the session is idle-expired, absolute-expired or revoked (including "sign out
  //      everywhere else" and an admin disable), and that surfaces here as an opaque redirect. It is
  //      probed with activity=false server-side, so probing never keeps the session alive.
  //   2. ABSOLUTE — the probe returns the deadline as REMAINING SECONDS, converted to a local
  //      monotonic-ish deadline on arrival. Never a wall-clock the page would have to trust against
  //      its own system time, and read from the session record so a federated session capped by the
  //      IdP's id_token.exp is respected rather than over-stated from settings.
  //   3. STALE CONTACT — if no probe has SUCCEEDED for STALE_LIMIT_MS the page can no longer confirm
  //      the session at all (engine down, network gone, laptop offline). It terminates anyway: an
  //      unconfirmable session is not a licence to keep PHI on screen. This bound is deliberately far
  //      tighter than any sane server idle timeout, so it never pre-empts a healthy session.
  //
  // Terminating BLANKS THE DOCUMENT FIRST and only then navigates. Ordering matters: location.replace
  // can fail or hang when the engine is unreachable — exactly leg 3's scenario — and a failed
  // navigation would otherwise leave the PHI on screen indefinitely. Blanking is unconditional and
  // synchronous, so the offline case is covered whether or not the navigation ever completes.
  // Registered as a SECURITY control (securityFeature, not feature): started before every page
  // enhancer and isolated from their failures — see the registry comment at the top of this file.
  securityFeature("[data-mf-session-watchdog]", function () {
    var PROBE_MS = 30000; // heartbeat; activity=false server-side, so it never slides the idle clock
    var TICK_MS = 1000; // deadline check — cheap, and keeps the fire granularity tight
    var STALE_LIMIT_MS = 300000; // no CONFIRMED-live server response for 5 min => discard the DOM
    var EXPIRED_URL = "/ui/login?e=expired";

    var lastServerContact = Date.now(); // the page render itself was a server interaction
    var absoluteDeadline = null; // ms epoch, from the probe's remaining-seconds
    var terminated = false;

    function terminate() {
      if (terminated) return;
      terminated = true;
      try {
        // Blank BEFORE navigating (see above). replaceChildren() drops every rendered node; the
        // title goes too so a tab preview cannot leak the message/patient context either.
        if (document.body) document.body.replaceChildren();
        document.title = "Session ended — MessageFoundry";
      } catch (e) {
        // Never let a DOM edge case skip the navigation below.
      }
      try {
        window.location.replace(EXPIRED_URL);
      } catch (e) {
        window.location.href = EXPIRED_URL;
      }
    }

    async function probe() {
      if (terminated) return;
      try {
        var resp = await fetch("/ui/session-status", {
          credentials: "same-origin",
          redirect: "manual", // an auth 303 must SURFACE, not be followed into a 200 login page
          headers: { "X-Requested-With": "fetch" },
          cache: "no-store",
        });
        if (resp.type === "opaqueredirect" || resp.status === 0 || resp.status === 303) {
          terminate(); // the server has ended this session
          return;
        }
        if (resp.status === 401 || resp.status === 403) {
          terminate();
          return;
        }
        if (!resp.ok) return; // a 5xx is an engine problem, not a session verdict — let leg 3 decide
        var data = JSON.parse(await resp.text()) || {};
        lastServerContact = Date.now();
        var secs = data.expires_secs;
        absoluteDeadline = typeof secs === "number" ? Date.now() + secs * 1000 : null;
      } catch (e) {
        // Unreachable engine / offline: do NOT refresh lastServerContact — leg 3 is the answer.
      }
    }

    function tick() {
      if (terminated) return;
      var now = Date.now();
      if (absoluteDeadline !== null && now >= absoluteDeadline) {
        terminate();
        return;
      }
      if (now - lastServerContact >= STALE_LIMIT_MS) terminate();
    }

    probe();
    setInterval(probe, PROBE_MS);
    setInterval(tick, TICK_MS);
  });

  // The nav renders on EVERY page, so this is the one always-on poller. It fetches the metadata-only
  // GET /ui/nav-status (~15s) and recolors two server-rendered <span> glyphs via classList + title/
  // aria-label only — never innerHTML (CSP script-src 'self'; the count is a number, set as text/aria, not
  // markup). Engine health: ok=green, warn=orange, down=blinking-red; a fetch/network failure means the
  // ENGINE itself is unreachable → down. Alerts: gray at zero, else colored by worst severity; a null
  // payload (viewer lacks monitoring:diagnose) HIDES the bell rather than showing a gray "no alerts" it
  // isn't cleared to trust. A 403 (no monitoring:read at all) hides the whole cluster.
  feature("[data-mf-nav-status]", function (box) {
    var heart = box.querySelector("[data-mf-nav-health]");
    var bell = box.querySelector("[data-mf-nav-alerts]");
    var HEALTH_CLS = ["health-unknown", "health-ok", "health-warn", "health-down"];
    var ALERT_CLS = ["alerts-unknown", "alerts-none", "alerts-info", "alerts-warning", "alerts-critical"];

    function setClass(node, all, one) {
      if (!node) return;
      for (var i = 0; i < all.length; i++) node.classList.remove(all[i]);
      node.classList.add(one);
    }
    function label(node, text) {
      if (!node) return;
      node.setAttribute("title", text);
      node.setAttribute("aria-label", text);
    }
    function setHealth(state, reason) {
      var cls =
        state === "ok"
          ? "health-ok"
          : state === "warn"
            ? "health-warn"
            : state === "down"
              ? "health-down"
              : "health-unknown";
      setClass(heart, HEALTH_CLS, cls);
      label(heart, "Engine health: " + (reason || state || "unknown"));
    }
    function setAlerts(info) {
      if (!bell) return;
      if (!info) {
        bell.style.display = "none"; // no monitoring:diagnose → don't imply "no alerts"
        return;
      }
      bell.style.display = "";
      var n = info.count || 0;
      var sev = info.severity;
      var cls =
        n === 0
          ? "alerts-none"
          : sev === "critical"
            ? "alerts-critical"
            : sev === "warning"
              ? "alerts-warning"
              : "alerts-info";
      setClass(bell, ALERT_CLS, cls);
      label(
        bell,
        n === 0
          ? "No active alerts"
          : n + " active alert" + (n === 1 ? "" : "s") + (sev ? " (worst: " + sev + ")" : "")
      );
    }
    async function poll() {
      try {
        var resp = await fetch("/ui/nav-status", {
          credentials: "same-origin",
          redirect: "manual", // don't FOLLOW an auth 303 into the login page (see below)
          headers: { "X-Requested-With": "fetch" },
          cache: "no-store",
        });
        // Session expired: require_ui answers 303 → /ui/login. With redirect:"manual" that surfaces as an
        // opaque redirect (type "opaqueredirect", status 0) instead of being transparently followed into a
        // 200 login PAGE — which we'd then JSON.parse and, on the throw, falsely paint the heart blinking-red
        // "engine unreachable". Treat it as a no-op: the next real navigation takes the user to login. (Same
        // idiom as the step-up fetches above.)
        if (resp.type === "opaqueredirect" || resp.status === 0) return;
        if (mfNetworkDenied(resp)) {
          // NOT an RBAC outcome — the source-network gate refused us. Navigating surfaces the engine's
          // denial page (which names the setting and the observed address) instead of silently hiding
          // the box, which would read as "you lack monitoring:read".
          window.location.reload();
          return;
        }
        if (resp.status === 403) {
          box.style.display = "none"; // not permitted to see engine status at all
          return;
        }
        if (resp.status === 401) return; // auth edge — don't alarm; a navigation redirects to login
        if (!resp.ok) {
          setHealth("down", "status unavailable");
          return;
        }
        var d = JSON.parse(await resp.text()) || {};
        setHealth(d.health, d.reason);
        setAlerts(Object.prototype.hasOwnProperty.call(d, "alerts") ? d.alerts : null);
      } catch (e) {
        setHealth("down", "engine unreachable"); // network error → the engine/API is down
      }
    }
    poll();
    setInterval(poll, 15000);
  });

  // Edit-and-resubmit editor (ADR 0090 §9, BACKLOG #153). Reveal a "Modified" badge as soon as the
  // edited COPY differs from the pristine original, enable a Revert button that restores the original
  // copy, and show the direct-outbound field only when "Send directly" is chosen. Pure client-side
  // progressive enhancement — the Resubmit itself is an ordinary server-validated, same-origin form POST
  // (no fetch), so the step-up/unlock re-auth flow applies unchanged and the feature is optional. The
  // ORIGINAL message is never touched: this edits a copy the server rendered from the audited raw view.
  feature("[data-mf-edit]", function (form) {
    var ta = form.querySelector("#edit-raw");
    var badge = form.querySelector("#edit-modified");
    var revert = form.querySelector("#edit-revert");
    var toRow = form.querySelector("#edit-to-row");
    var toInput = form.querySelector("#edit-to");
    if (!ta) return;
    // Normalize CR/CRLF → LF on BOTH sides: a browser textarea normalizes the DOM value's newlines, so
    // comparing against the raw (\r-delimited HL7) attribute would flag "modified" on open with no edit.
    function norm(s) {
      return (s || "").replace(/\r\n?/g, "\n");
    }
    var original = norm(ta.getAttribute("data-original"));
    function sync() {
      var changed = norm(ta.value) !== original;
      if (badge) badge.hidden = !changed;
      if (revert) revert.disabled = !changed;
    }
    ta.addEventListener("input", sync);
    if (revert)
      revert.addEventListener("click", function () {
        ta.value = ta.getAttribute("data-original") || "";
        sync();
        ta.focus();
      });
    function modeSync() {
      var checked = form.querySelector("input[name=mode]:checked");
      var isDirect = checked && checked.value === "direct";
      if (toRow) toRow.hidden = !isDirect;
      if (toInput) toInput.required = !!isDirect;
    }
    Array.prototype.forEach.call(
      form.querySelectorAll("input[name=mode]"),
      function (r) {
        r.addEventListener("change", modeSync);
      }
    );
    sync();
    modeSync();
  });

  // Runtime log-verbosity control (BACKLOG #171, ADR 0130). A server-rendered <select> whose current
  // value is the live level; changing it PATCHes the same-origin /ui proxy of PATCH /logging/level. The
  // override is EPHEMERAL — it resets on a process restart (and NOT on /config/reload) — so the status
  // line says so. On failure the select reverts to the last-applied value (no silent divergence).
  feature("[data-mf-log-level]", function (select) {
    var status = document.querySelector("[data-mf-log-level-status]");
    var current = select.value;
    select.addEventListener("change", async function () {
      var next = select.value;
      if (status) status.textContent = "Applying…";
      try {
        var resp = await fetch("/ui/logging/level", {
          method: "PATCH",
          credentials: "same-origin",
          redirect: "manual", // an auth 303 must SURFACE, not be followed into a 200 login page
          headers: { "Content-Type": "application/json", "X-Requested-With": "fetch" },
          body: JSON.stringify({ level: next }),
          cache: "no-store",
        });
        if (mfSessionEnded(resp) || mfNetworkDenied(resp)) {
          window.location.reload(); // session expired, or refused by the source-network gate
          return;
        }
        if (resp.ok) {
          var data = await resp.json();
          current = data.level || next;
          select.value = current;
          if (status)
            status.textContent =
              "Log level set to " + current + " (ephemeral — resets on restart).";
        } else {
          select.value = current; // revert on refusal (e.g. missing monitoring:diagnose / step-up)
          if (status) status.textContent = "Could not change log level (" + resp.status + ").";
        }
      } catch (e) {
        select.value = current;
        if (status) status.textContent = "Network error changing log level.";
      }
    });
  });

  // Redacted application-log viewer (BACKLOG #171, ADR 0130). Pages the same-origin /ui proxy of GET
  // /logs/tail, which returns ALREADY-REDACTED lines (best-effort PHI/secret scrub) counted back from the
  // end of the newest log file. offset counts lines from the END (0 = newest page). Lines are appended as
  // TEXT nodes, never innerHTML — the redacted log is still untrusted content and must never be parsed as
  // markup. Degrades to a message when no log file is configured (available=false).
  feature("[data-mf-log-viewer]", function (root) {
    var out = root.querySelector("[data-mf-log-lines]");
    var olderBtn = root.querySelector("[data-mf-log-older]");
    var newerBtn = root.querySelector("[data-mf-log-newer]");
    var refreshBtn = root.querySelector("[data-mf-log-refresh]");
    var status = root.querySelector("[data-mf-log-status]");
    var limit = parseInt(root.getAttribute("data-mf-log-limit") || "200", 10);
    if (!(limit > 0)) limit = 200;
    var offset = 0;
    var total = 0;

    async function load() {
      if (status) status.textContent = "Loading…";
      try {
        var resp = await fetch("/ui/logs/tail?limit=" + limit + "&offset=" + offset, {
          credentials: "same-origin",
          redirect: "manual", // an auth 303 must SURFACE, not be followed into a 200 login page
          headers: { "X-Requested-With": "fetch" },
          cache: "no-store",
        });
        if (mfSessionEnded(resp) || mfNetworkDenied(resp)) {
          window.location.reload(); // session expired, or refused by the source-network gate
          return;
        }
        if (!resp.ok) {
          if (status) status.textContent = "Could not load log (" + resp.status + ").";
          return;
        }
        var data = await resp.json();
        total = data.total_lines || 0;
        if (out) {
          out.textContent = "";
          if (!data.available) {
            out.textContent = "No application-log file is configured (logging to stdout).";
          } else if (!data.lines.length) {
            out.textContent = "(no log lines)";
          } else {
            data.lines.forEach(function (line) {
              out.appendChild(document.createTextNode(line + "\n"));
            });
          }
        }
        if (newerBtn) newerBtn.disabled = offset <= 0;
        if (olderBtn) olderBtn.disabled = offset + limit >= total;
        if (status) {
          var shown = Math.min(limit, Math.max(0, total - offset));
          status.textContent = data.available
            ? "Lines " +
              (total - offset - shown + 1) +
              "–" +
              (total - offset) +
              " of " +
              total
            : "";
        }
      } catch (e) {
        if (status) status.textContent = "Network error loading log.";
      }
    }

    if (olderBtn)
      olderBtn.addEventListener("click", function () {
        if (offset + limit < total) {
          offset += limit;
          load();
        }
      });
    if (newerBtn)
      newerBtn.addEventListener("click", function () {
        offset = Math.max(0, offset - limit);
        load();
      });
    if (refreshBtn)
      refreshBtn.addEventListener("click", function () {
        offset = 0;
        load();
      });
    load();
  });

  // Bulk message-body export (BACKLOG #124, ADR 0131). Save-all downloads every match of the current
  // search (the server-rendered data-mf-export-url carries the basic filters); save-selected downloads
  // the checked rows (?ids=…). The download STREAMS from the same-origin /ui proxy of GET
  // /messages/export with a live progress readout (messages + bytes) and a Stop control (AbortController).
  // The browser's own download picker chooses the file location — a PHI-safe destination is the
  // operator's responsibility (ADR 0131). One export at a time.
  feature("[data-mf-msg-export]", function (root) {
    var allBtn = root.querySelector("[data-mf-export-all]");
    var selBtn = root.querySelector("[data-mf-export-selected]");
    var stopBtn = root.querySelector("[data-mf-export-stop]");
    var progress = root.querySelector("[data-mf-export-progress]");
    var allUrl = root.getAttribute("data-mf-export-url") || "/ui/messages/export";
    var base = root.getAttribute("data-mf-export-base") || "/ui/messages/export";
    var controller = null;

    function setBusy(busy) {
      if (allBtn) allBtn.disabled = busy;
      if (selBtn) selBtn.disabled = busy;
      if (stopBtn) stopBtn.hidden = !busy;
    }

    function selectedIds() {
      var out = [];
      Array.prototype.forEach.call(
        root.querySelectorAll("[data-mf-export-cb]"),
        function (cb) {
          if (cb.checked && cb.value) out.push(cb.value);
        }
      );
      return out;
    }

    async function run(url, filename) {
      if (controller) return; // one export at a time
      controller = new AbortController();
      setBusy(true);
      if (progress) progress.textContent = "Starting…";
      try {
        var resp = await fetch(url, {
          credentials: "same-origin",
          redirect: "manual", // an auth 303 must SURFACE, not be followed into a 200 login page
          headers: { "X-Requested-With": "fetch" },
          cache: "no-store",
          signal: controller.signal,
        });
        if (mfSessionEnded(resp) || mfNetworkDenied(resp)) {
          window.location.reload(); // session expired, or refused by the source-network gate
          return;
        }
        if (!resp.ok) {
          if (progress) progress.textContent = "Export failed (" + resp.status + ").";
          return;
        }
        var reader = resp.body.getReader();
        var chunks = [];
        var bytes = 0;
        var lines = 0;
        for (;;) {
          var step = await reader.read();
          if (step.done) break;
          chunks.push(step.value);
          bytes += step.value.length;
          // Each NDJSON record ends in a newline (0x0A) — count them for a human progress readout.
          for (var i = 0; i < step.value.length; i++) if (step.value[i] === 10) lines++;
          if (progress)
            progress.textContent =
              "Exported " + lines + " messages (" + bytes + " bytes)…";
        }
        var blob = new Blob(chunks, { type: "application/x-ndjson" });
        var href = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = href;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(href);
        if (progress) progress.textContent = "Saved " + lines + " messages.";
      } catch (e) {
        if (e && e.name === "AbortError") {
          if (progress) progress.textContent = "Export stopped.";
        } else if (progress) {
          progress.textContent = "Network error during export.";
        }
      } finally {
        controller = null;
        setBusy(false);
      }
    }

    if (allBtn)
      allBtn.addEventListener("click", function () {
        run(allUrl, "messages-export.ndjson");
      });
    if (selBtn)
      selBtn.addEventListener("click", function () {
        var ids = selectedIds();
        if (!ids.length) {
          if (progress) progress.textContent = "Select at least one message.";
          return;
        }
        var q = ids
          .map(function (id) {
            return "ids=" + encodeURIComponent(id);
          })
          .join("&");
        run(base + "?" + q, "messages-export.ndjson");
      });
    if (stopBtn)
      stopBtn.addEventListener("click", function () {
        if (controller) controller.abort();
      });
    setBusy(false);
  });

  // Deferred script → DOM already parsed. Run each feature whose hook is present on this page.
  // ISOLATED: a throw inside one init must never abort the loop and silently disable everything
  // after it — least of all the session watchdog (ASVS 14.3.1), whose job is discarding rendered
  // PHI. Security controls run FIRST, so they are never behind a page enhancer in either order or
  // failure domain.
  function runInit(pair) {
    var el = document.querySelector(pair[0]);
    if (!el) return;
    try {
      pair[1](el);
    } catch (e) {
      // One broken feature must not disable the rest. Nothing is logged: the console log is a
      // browser-side surface and these inits touch rendered PHI.
    }
  }
  securityInits.forEach(runInit);
  inits.forEach(runInit);
})();
