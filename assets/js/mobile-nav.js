(function () {
  function init(options) {
    var opts = options || {};
    var toggleId = opts.toggleId || "menuToggleBtn";
    var menuId = opts.menuId || "toolbar";
    var mediaQuery = opts.mediaQuery || "(max-width: 980px)";
    var openClass = opts.openClass || "is-open";
    var linkSelector = opts.linkSelector || "a";

    var toggleButton = document.getElementById(toggleId);
    var menu = document.getElementById(menuId);
    if (!toggleButton || !menu || !window.matchMedia) return;

    var media = window.matchMedia(mediaQuery);

    function closeMenu() {
      menu.classList.remove(openClass);
      toggleButton.setAttribute("aria-expanded", "false");
    }

    function syncMenuLayout() {
      if (!media.matches) closeMenu();
    }

    toggleButton.addEventListener("click", function () {
      var isOpen = menu.classList.toggle(openClass);
      toggleButton.setAttribute("aria-expanded", isOpen ? "true" : "false");
    });

    menu.addEventListener("click", function (event) {
      if (!media.matches) return;
      if (event.target && event.target.closest(linkSelector)) closeMenu();
    });

    window.addEventListener("resize", syncMenuLayout);
    syncMenuLayout();
  }

  window.AppMobileNav = {
    init: init
  };
})();
