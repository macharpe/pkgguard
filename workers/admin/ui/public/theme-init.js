// External on purpose: the CSP forbids inline script. Runs before first paint to avoid a flash of the wrong theme.
(function () {
  var stored = null;
  try {
    stored = localStorage.getItem("pkgguard-mode");
  } catch (e) {}
  var dark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.setAttribute("data-mode", stored === "dark" || stored === "light" ? stored : dark ? "dark" : "light");
})();
