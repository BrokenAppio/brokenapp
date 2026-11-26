export function render(root) {
  root.innerHTML =
    '<h1>Receiving</h1>' +
    '<p><button id="open-count">Open &amp; count</button></p>' +
    '<div id="count-out"></div>';
  document.getElementById('open-count').addEventListener('click', function () {
    document.getElementById('count-out').textContent = 'Count started for shipment 42';
  });
}
