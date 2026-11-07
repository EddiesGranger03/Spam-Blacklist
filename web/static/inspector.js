(function () {
  var KEY = 'vsf.inspector.open';
  var dock = document.getElementById('inspector-dock');
  if (!dock) return;

  var paused = false;
  var btn = document.getElementById('dock-pause-btn');

  // Restore open/closed state across page navigations.
  try { dock.open = localStorage.getItem(KEY) === '1'; } catch (e) {}
  dock.addEventListener('toggle', function () {
    try { localStorage.setItem(KEY, dock.open ? '1' : '0'); } catch (e) {}
    if (dock.open) {
      var body = document.getElementById('inspector-table-body');
      if (body && window.htmx) {
        window.htmx.ajax('GET', '/admin/inspector/feed', { source: body, target: body, swap: 'innerHTML' });
      }
    }
  });

  document.body.addEventListener('htmx:afterSwap', function (evt) {
    var td = evt.detail.target;
    var row = td && td.parentElement;
    if (row && row.classList && row.classList.contains('inspector-detail-row')) {
      row.hidden = false;
    }
  });

  dock.addEventListener('click', function (evt) {
    var close = evt.target.closest('.detail-close');
    if (!close) return;
    var row = close.closest('.inspector-detail-row');
    if (row) closeRow(row);
  });

  btn.addEventListener('click', function () {
    paused = !paused;
    btn.textContent = paused ? '▶ Tiếp tục' : '⏸ Tạm dừng';
    dock.classList.toggle('is-paused', paused);
  });

  // Cancel background polling while paused (all) or collapsed (table only).
  // The filter form and clear button target the table but are not the polling
  // element, so they are never blocked.
  function openRows() {
    return dock.querySelectorAll('.inspector-detail-row:not([hidden])');
  }

  function closeRow(row) {
    row.hidden = true;
    row.firstElementChild.innerHTML = '';
  }

  document.body.addEventListener('htmx:beforeRequest', function (evt) {
    var elt = evt.detail.elt;
    var id = elt && elt.id;

    // Clicking a row: toggle its detail; only one detail is open at a time.
    if (elt && elt.classList && elt.classList.contains('inspector-row')) {
      var mine = document.getElementById('detail-' + elt.dataset.id);
      var wasOpen = mine && !mine.hidden;
      openRows().forEach(closeRow);
      if (wasOpen) evt.preventDefault();
      return;
    }

    // Freeze the list while a detail is being read, otherwise the 2s refresh
    // would rebuild the table and collapse it.
    if (id === 'inspector-table-body' && (paused || !dock.open || openRows().length)) evt.preventDefault();
    if (id === 'inspector-stats' && paused) evt.preventDefault();
  });
})();
