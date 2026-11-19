// htmx does not swap 4xx responses by default. The entry form answers 409 (value already exists) with the
// form re-rendered plus an error message, so allow that one status to be swapped into the page.
document.addEventListener('htmx:beforeSwap', function (e) {
  if (e.detail.xhr && e.detail.xhr.status === 409) {
    e.detail.shouldSwap = true;
    e.detail.isError = false;
  }
});
