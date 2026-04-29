(function () {
  var toggleButton = document.getElementById("screenMenuToggle");
  var menu = document.getElementById("screenMenu");
  if (!toggleButton || !menu || !window.matchMedia) return;

  var media = window.matchMedia("(max-width: 720px)");

  function closeMenu() {
    menu.classList.remove("is-open");
    toggleButton.setAttribute("aria-expanded", "false");
  }

  function syncMenu() {
    if (!media.matches) closeMenu();
  }

  toggleButton.addEventListener("click", function () {
    var isOpen = menu.classList.toggle("is-open");
    toggleButton.setAttribute("aria-expanded", isOpen ? "true" : "false");
  });

  menu.addEventListener("click", function (event) {
    if (!media.matches) return;
    if (event.target && event.target.closest("a")) closeMenu();
  });

  window.addEventListener("resize", syncMenu);
  syncMenu();
})();
