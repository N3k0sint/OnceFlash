/**
 * OnceFlash — Theme Manager (Dark / Light Mode)
 * Lightweight, zero-dependency, persistent theme toggle.
 */

(function () {
  const STORAGE_KEY = "onceflash_theme";

  function getSystemTheme() {
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches
      ? "light"
      : "dark";
  }

  function getStoredTheme() {
    try {
      return localStorage.getItem(STORAGE_KEY);
    } catch {
      return null;
    }
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {}

    // Update meta theme-color for mobile browser chrome
    let metaThemeColor = document.querySelector('meta[name="theme-color"]');
    if (!metaThemeColor) {
      metaThemeColor = document.createElement("meta");
      metaThemeColor.name = "theme-color";
      document.head.appendChild(metaThemeColor);
    }
    metaThemeColor.setAttribute("content", theme === "light" ? "#f8fafc" : "#0b0f14");

    updateToggleIcons(theme);
  }

  function updateToggleIcons(theme) {
    const sunIcons = document.querySelectorAll(".theme-icon-sun");
    const moonIcons = document.querySelectorAll(".theme-icon-moon");

    sunIcons.forEach((el) => {
      el.style.display = theme === "dark" ? "block" : "none";
    });
    moonIcons.forEach((el) => {
      el.style.display = theme === "light" ? "block" : "none";
    });
  }

  // Initialize immediately on script load
  const initialTheme = getStoredTheme() || getSystemTheme();
  applyTheme(initialTheme);

  // Bind toggle button after DOM is ready
  function bindToggle() {
    const toggleBtn = document.getElementById("theme-toggle-btn");
    if (toggleBtn) {
      // Avoid attaching duplicate listeners
      if (toggleBtn.dataset.themeBound) return;
      toggleBtn.dataset.themeBound = "true";

      toggleBtn.addEventListener("click", () => {
        const currentTheme = document.documentElement.getAttribute("data-theme") || "dark";
        const nextTheme = currentTheme === "dark" ? "light" : "dark";
        applyTheme(nextTheme);
      });
    }
    updateToggleIcons(document.documentElement.getAttribute("data-theme") || "dark");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bindToggle);
  } else {
    bindToggle();
  }

  // Listen to system changes if user hasn't explicitly set a preference
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (e) => {
      if (!getStoredTheme()) {
        applyTheme(e.matches ? "dark" : "light");
      }
    });
  }

  window.OnceFlashTheme = {
    get: () => document.documentElement.getAttribute("data-theme") || "dark",
    set: applyTheme,
    toggle: () => {
      const current = document.documentElement.getAttribute("data-theme") || "dark";
      applyTheme(current === "dark" ? "light" : "dark");
    },
  };
})();
