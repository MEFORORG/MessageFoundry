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
      try {
        var resp = await fetch(url, {
          credentials: "same-origin",
          headers: { "X-Requested-With": "fetch" },
          cache: "no-store",
        });
        if (resp.ok) {
          // Server-rendered + server-escaped fragment (same-origin); safe to assign as markup.
          container.innerHTML = await resp.text();
        } else if (resp.status === 303 || resp.status === 401) {
          // Session expired — reload so the server can redirect to the login page.
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
          if (typeof d.connections_html === "string") {
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
        msg = "Select one or more connections.";
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

  // Deferred script → DOM already parsed. Run each feature whose hook is present on this page.
  inits.forEach(function (pair) {
    var el = document.querySelector(pair[0]);
    if (el) pair[1](el);
  });
})();
