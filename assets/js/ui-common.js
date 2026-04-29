(function () {
  function createUIContext(options) {
    var opts = options || {};
    var i18n = opts.i18n || {};
    var defaultLang = opts.defaultLang || "zh";
    var langStorageKey = opts.langStorageKey || "lang";
    var themeStorageKey = opts.themeStorageKey || "theme";
    var langButtonLabels = opts.langButtonLabels || { zh: "EN", en: "中文" };
    var onApplyI18n = typeof opts.onApplyI18n === "function" ? opts.onApplyI18n : null;

    var currentLang = localStorage.getItem(langStorageKey) || defaultLang;
    if (!i18n[currentLang]) currentLang = defaultLang;

    var themeMode = localStorage.getItem(themeStorageKey) || "auto";
    var mediaDark = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

    function t(key) {
      var pack = i18n[currentLang] || {};
      return pack[key] || key;
    }

    function f(key) {
      var pack = i18n[currentLang] || {};
      var fields = pack.fields || {};
      return fields[key] || key;
    }

    function shouldUseDarkTheme() {
      if (themeMode === "dark") return true;
      if (themeMode === "light") return false;
      return Boolean(mediaDark && mediaDark.matches);
    }

    function applyTheme() {
      var root = document.documentElement;
      if (shouldUseDarkTheme()) {
        root.setAttribute("data-theme", "dark");
      } else {
        root.removeAttribute("data-theme");
      }

      var themeBtn = document.getElementById("themeBtn");
      if (themeBtn) {
        themeBtn.textContent = themeMode === "light" ? t("themeLight") : themeMode === "dark" ? t("themeDark") : t("themeAuto");
      }
    }

    function applyI18n() {
      document.documentElement.lang = currentLang === "zh" ? "zh-CN" : "en";
      document.title = t("pageTitle");
      document.querySelectorAll("[data-i18n]").forEach(function (el) {
        var key = el.getAttribute("data-i18n");
        el.textContent = t(key);
      });

      var langBtn = document.getElementById("langBtn");
      if (langBtn) {
        langBtn.textContent = currentLang === "zh" ? langButtonLabels.zh : langButtonLabels.en;
      }

      if (onApplyI18n) onApplyI18n(currentLang);
      applyTheme();
    }

    function setLang(lang) {
      if (!i18n[lang]) return;
      currentLang = lang;
      localStorage.setItem(langStorageKey, currentLang);
      applyI18n();
    }

    function toggleLang() {
      setLang(currentLang === "zh" ? "en" : "zh");
    }

    function setTheme(mode) {
      if (mode !== "auto" && mode !== "light" && mode !== "dark") return;
      themeMode = mode;
      localStorage.setItem(themeStorageKey, themeMode);
      applyTheme();
    }

    function toggleTheme() {
      setTheme(themeMode === "auto" ? "light" : themeMode === "light" ? "dark" : "auto");
    }

    function getLang() {
      return currentLang;
    }

    function bindControls(optionsForBind) {
      var bindOpts = optionsForBind || {};
      var langButtonId = bindOpts.langButtonId || "langBtn";
      var themeButtonId = bindOpts.themeButtonId || "themeBtn";
      var onLanguageChanged = typeof bindOpts.onLanguageChanged === "function" ? bindOpts.onLanguageChanged : null;

      var langBtn = document.getElementById(langButtonId);
      if (langBtn) {
        langBtn.addEventListener("click", function () {
          toggleLang();
          if (onLanguageChanged) onLanguageChanged(currentLang);
        });
      }

      var themeBtn = document.getElementById(themeButtonId);
      if (themeBtn) {
        themeBtn.addEventListener("click", function () {
          toggleTheme();
        });
      }
    }

    if (mediaDark && mediaDark.addEventListener) {
      mediaDark.addEventListener("change", function () {
        if (themeMode === "auto") applyTheme();
      });
    }

    return {
      t: t,
      f: f,
      getLang: getLang,
      applyTheme: applyTheme,
      applyI18n: applyI18n,
      setLang: setLang,
      toggleLang: toggleLang,
      setTheme: setTheme,
      toggleTheme: toggleTheme,
      bindControls: bindControls
    };
  }

  window.UICommon = {
    createUIContext: createUIContext
  };
})();
