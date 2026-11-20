// Behavior for the static showcase pages. The real consoles implement these
// patterns as React components; this file only demonstrates them.
// Loaded as an external script so the pages run under a strict Content Security Policy.

(function () {
  "use strict";

  const root = document.documentElement;

  // ---------- Theme ----------
  function readStoredTheme() {
    try { return localStorage.getItem("hodor-showcase-theme"); } catch (error) { return null; }
  }
  function storeTheme(theme) {
    try { localStorage.setItem("hodor-showcase-theme", theme); } catch (error) { /* storage unavailable */ }
  }
  function applyTheme(theme) {
    root.dataset.theme = theme;
    document.querySelectorAll("[data-theme-toggle]").forEach(function (button) {
      const next = theme === "dark" ? "light" : "dark";
      button.setAttribute("aria-label", "Switch to " + next + " theme");
      const use = button.querySelector("use");
      if (use) use.setAttribute("href", "icons.svg#" + (theme === "dark" ? "sun" : "moon"));
    });
  }
  applyTheme(readStoredTheme() || root.dataset.theme || "dark");
  document.addEventListener("click", function (event) {
    if (!event.target.closest("[data-theme-toggle]")) return;
    const next = root.dataset.theme === "dark" ? "light" : "dark";
    applyTheme(next);
    storeTheme(next);
  });

  // ---------- Toasts ----------
  const toastRegion = document.getElementById("toasts");
  function toast(message) {
    if (!toastRegion) return;
    const element = document.createElement("div");
    element.className = "toast";
    element.innerHTML =
      '<svg class="icon" aria-hidden="true"><use href="icons.svg#check-circle"/></svg>' +
      "<span></span>" +
      '<a class="toast__action t-sm" href="#">View audit record</a>';
    element.querySelector("span").textContent = message;
    toastRegion.appendChild(element);
    setTimeout(function () { element.remove(); }, 6000);
  }

  // ---------- Dialogs ----------
  function resetDialog(dialog) {
    dialog.querySelectorAll("[data-step]").forEach(function (step, index) {
      step.hidden = index !== 0;
    });
    dialog.querySelectorAll("input[type=text]").forEach(function (input) { input.value = ""; });
    dialog.querySelectorAll("input[type=checkbox]").forEach(function (input) { input.checked = false; });
    dialog.querySelectorAll("[data-confirm-button], [data-ack-button]").forEach(function (button) {
      button.disabled = true;
      button.classList.remove("is-holding", "is-confirmed");
    });
  }
  function openDialog(id) {
    const dialog = document.getElementById(id);
    if (!dialog || typeof dialog.showModal !== "function") return;
    document.querySelectorAll("dialog[open]").forEach(function (open) { open.close(); });
    resetDialog(dialog);
    dialog.showModal();
    const first = dialog.querySelector("input, [data-palette-input]");
    // The destructive button is never pre-focused (design system, section 6.2).
    if (first) first.focus();
    else {
      const cancel = dialog.querySelector("[data-close]");
      if (cancel) cancel.focus();
    }
  }

  document.addEventListener("click", function (event) {
    const opener = event.target.closest("[data-open]");
    if (opener) {
      event.preventDefault();
      openDialog(opener.dataset.open);
      return;
    }
    const nextStep = event.target.closest("[data-next-step]");
    if (nextStep && !nextStep.disabled) {
      const dialog = nextStep.closest("dialog");
      dialog.querySelectorAll("[data-step]").forEach(function (step) {
        step.hidden = step.dataset.step !== nextStep.dataset.nextStep;
      });
      const cancel = dialog.querySelector("[data-step]:not([hidden]) [data-close]");
      if (cancel) cancel.focus();
      return;
    }
    const completer = event.target.closest("[data-complete]");
    if (completer && !completer.disabled && !completer.hasAttribute("data-hold")) {
      const dialog = completer.closest("dialog");
      if (dialog) dialog.close();
      toast(completer.dataset.complete);
      return;
    }
    const closer = event.target.closest("[data-close]");
    if (closer) {
      const dialog = closer.closest("dialog");
      if (dialog) dialog.close();
    }
  });

  // Enter never triggers the destructive button inside a dialog.
  document.addEventListener("keydown", function (event) {
    if (event.key === "Enter" && event.target.matches("dialog input[type=text]")) {
      event.preventDefault();
    }
  });

  // Type-to-confirm
  document.addEventListener("input", function (event) {
    const input = event.target.closest("[data-confirm-match]");
    if (!input) return;
    const dialog = input.closest("dialog");
    const matches = input.value.trim() === input.dataset.confirmMatch;
    const button = dialog.querySelector("[data-step]:not([hidden]) [data-confirm-button], :scope > .dialog__footer [data-confirm-button]");
    if (button) button.disabled = !matches;
  });

  // Acknowledge before closing the secret panel
  document.addEventListener("change", function (event) {
    if (!event.target.matches("[data-ack]")) return;
    const dialog = event.target.closest("dialog");
    dialog.querySelector("[data-ack-button]").disabled = !event.target.checked;
  });
  // The secret panel cannot be dismissed with Escape before acknowledgement.
  const secretDialog = document.getElementById("dialog-secret");
  if (secretDialog) {
    secretDialog.addEventListener("cancel", function (event) {
      if (!secretDialog.querySelector("[data-ack]").checked) event.preventDefault();
    });
  }

  // ---------- Hold to confirm ----------
  const HOLD_MILLISECONDS = 1500;
  document.querySelectorAll("[data-hold]").forEach(function (button) {
    let timer = null;
    function start(event) {
      if (button.disabled) return;
      if (event.type === "keydown" && event.key !== " " && event.key !== "Enter") return;
      if (event.type === "keydown") { event.preventDefault(); if (event.repeat) return; }
      button.classList.add("is-holding");
      timer = setTimeout(function () {
        button.classList.remove("is-holding");
        button.classList.add("is-confirmed");
        setTimeout(function () {
          const dialog = button.closest("dialog");
          if (dialog) dialog.close();
          toast(button.dataset.complete);
        }, 200);
      }, HOLD_MILLISECONDS);
    }
    function stop() {
      clearTimeout(timer);
      button.classList.remove("is-holding");
    }
    button.addEventListener("pointerdown", start);
    button.addEventListener("keydown", start);
    ["pointerup", "pointerleave", "keyup", "blur"].forEach(function (name) { button.addEventListener(name, stop); });
  });

  // ---------- Copy ----------
  document.addEventListener("click", function (event) {
    const copier = event.target.closest("[data-copy]");
    if (!copier) return;
    const value = copier.dataset.copy;
    const done = function () {
      const holder = copier.closest(".identifier") || copier;
      holder.classList.add("is-copied");
      setTimeout(function () { holder.classList.remove("is-copied"); }, 1500);
    };
    if (navigator.clipboard) navigator.clipboard.writeText(value).then(done, done);
    else done();
  });

  // ---------- Command palette ----------
  const palette = document.getElementById("palette");
  document.addEventListener("keydown", function (event) {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      openDialog("palette");
    }
  });
  if (palette) {
    const input = palette.querySelector("[data-palette-input]");
    function items() {
      return Array.prototype.filter.call(palette.querySelectorAll(".palette__item"), function (item) { return !item.hidden; });
    }
    function select(index) {
      const list = items();
      list.forEach(function (item, position) { item.setAttribute("aria-selected", position === index ? "true" : "false"); });
      if (list[index]) list[index].scrollIntoView({ block: "nearest" });
    }
    input.addEventListener("input", function () {
      const query = input.value.trim().toLowerCase();
      palette.querySelectorAll(".palette__item").forEach(function (item) {
        item.hidden = query !== "" && item.textContent.toLowerCase().indexOf(query) === -1;
      });
      select(0);
    });
    input.addEventListener("keydown", function (event) {
      const list = items();
      const current = list.findIndex(function (item) { return item.getAttribute("aria-selected") === "true"; });
      if (event.key === "ArrowDown") { event.preventDefault(); select(Math.min(current + 1, list.length - 1)); }
      if (event.key === "ArrowUp") { event.preventDefault(); select(Math.max(current - 1, 0)); }
      if (event.key === "Enter" && list[current]) {
        event.preventDefault();
        const target = list[current].dataset.open;
        palette.close();
        if (target) openDialog(target);
      }
    });
  }

  // ---------- Session timer ----------
  const remaining = document.querySelector("[data-session-remaining]");
  if (remaining) {
    let seconds = 14 * 60 + 52;
    const timer = document.getElementById("session-timer");
    function render() {
      const minutes = Math.floor(seconds / 60);
      const rest = String(seconds % 60).padStart(2, "0");
      remaining.textContent = minutes + ":" + rest;
      timer.classList.toggle("is-expiring", seconds <= 120);
    }
    setInterval(function () { if (seconds > 0) { seconds -= 1; render(); } }, 1000);
    ["pointerdown", "keydown"].forEach(function (name) {
      document.addEventListener(name, function () { seconds = 15 * 60; render(); });
    });
  }

  // ---------- Live activity ----------
  const activity = document.getElementById("activity");
  if (activity && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    const events = [
      ["warning", "Unusual sign-in for <strong>lucas.prado</strong>: new country, step-up requested", "198.51.100.23"],
      ["success", "Client secret of <strong>reporting-batch</strong> rotated by Rafaela Lima", "after step-up with a passkey"],
      ["", "Organization <strong>Acme Brasil</strong> invited 4 members", "Marina Costa"]
    ];
    let next = 0;
    setInterval(function () {
      if (next >= events.length) return;
      const [kind, html, meta] = events[next++];
      const item = document.createElement("li");
      item.className = "activity__item is-new";
      item.innerHTML =
        '<span class="activity__marker' + (kind ? " activity__marker--" + kind : "") + '" aria-hidden="true"></span>' +
        '<div><div class="activity__text">' + html + '</div><div class="activity__meta">Just now · ' + meta + "</div></div>";
      activity.prepend(item);
      if (activity.children.length > 5) activity.lastElementChild.remove();
    }, 9000);
  }

  // ---------- Segmented controls ----------
  document.addEventListener("click", function (event) {
    const button = event.target.closest(".segmented button");
    if (!button) return;
    button.parentElement.querySelectorAll("button").forEach(function (other) {
      other.setAttribute("aria-pressed", other === button ? "true" : "false");
    });
  });
})();
