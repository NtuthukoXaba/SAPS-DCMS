/* SAPS-DCMS – shared page behaviour */
document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) lucide.createIcons();

  // Today's date under the dashboard greeting
  document.querySelectorAll('.js-today').forEach(el => {
    el.textContent = new Date().toLocaleDateString('en-ZA', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' }) + ' · ';
  });

  // Mobile sidebar
  const toggle = document.getElementById('sidebarToggle');
  if (toggle) toggle.addEventListener('click', () => document.getElementById('sidebar').classList.toggle('open'));

  // Pop-up windows: <button data-modal="id" data-x="..."> opens #id and copies data-* into [data-fill="x"] fields
  document.querySelectorAll('[data-modal]').forEach(btn => btn.addEventListener('click', () => {
    const modal = document.getElementById(btn.dataset.modal);
    Object.entries(btn.dataset).forEach(([k, v]) => {
      modal.querySelectorAll(`[data-fill="${k}"]`).forEach(el => {
        if ('value' in el && el.tagName !== 'SPAN' && el.tagName !== 'STRONG') el.value = v; else el.textContent = v;
      });
    });
    modal.classList.add('open');
  }));
  document.querySelectorAll('.modal-backdrop').forEach(m => {
    m.addEventListener('click', e => { if (e.target === m) m.classList.remove('open'); });
    m.querySelectorAll('.js-close').forEach(b => b.addEventListener('click', () => m.classList.remove('open')));
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') document.querySelectorAll('.modal-backdrop.open').forEach(m => m.classList.remove('open'));
  });

  // Confirm dangerous actions: <form data-confirm="Are you sure?">
  document.querySelectorAll('form[data-confirm]').forEach(f => f.addEventListener('submit', e => {
    if (!confirm(f.dataset.confirm)) e.preventDefault();
  }));

  // Clicking a table row with data-href opens it
  document.querySelectorAll('tr[data-href]').forEach(tr => tr.addEventListener('click', e => {
    if (!e.target.closest('a,button,form,select,input')) location.href = tr.dataset.href;
  }));

  // Range sliders show their value
  document.querySelectorAll('input[type=range][data-output]').forEach(r => {
    const out = document.getElementById(r.dataset.output);
    const show = () => out.textContent = r.value + '%';
    r.addEventListener('input', show); show();
  });

  // Success messages fade out after 6 seconds
  document.querySelectorAll('.flash-success').forEach(f => setTimeout(() => f.remove(), 6000));
});
