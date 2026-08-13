const state = {
  bootstrap: null,
  page: location.hash.replace('#', '') || 'home',
  data: {},
  loading: false,
  error: '',
  language: 'en',
  theme: 'system',
  translations: {},
  dialog: null,
};

const ICONS = {
  home: '⌂', devices: '▣', screen: '▭', alerts: '!', activity: '◷', settings: '⚙', about: 'i',
  success: '✓', warning: '!', danger: '✕', info: 'i', offline: '○', online: '●',
};

function t(key) {
  return state.translations[key] || state.bootstrap?.translations?.[key] || key;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (options.method === 'POST') headers['X-GuardianMesh-CSRF'] = getCookie('guardianmesh_console_csrf') || '';
  const response = await fetch(path, { ...options, headers, credentials: 'same-origin' });
  let body = {};
  try { body = await response.json(); } catch (_) { /* noop */ }
  if (!response.ok) throw new Error(body.error || t('errors.action_failed'));
  return body;
}

function getCookie(name) {
  return document.cookie.split('; ').reduce((value, part) => {
    const [key, val] = part.split('=');
    return key === name ? decodeURIComponent(val) : value;
  }, '');
}

async function loadTranslations(language) {
  const response = await fetch(`locales/${language}.json`);
  state.translations = response.ok ? await response.json() : {};
}

function setTheme(theme, persist = true) {
  state.theme = theme;
  const resolved = theme === 'system' ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : theme;
  document.documentElement.setAttribute('data-theme', resolved);
  if (persist) {
    api('/api/action', {
      method: 'POST',
      body: JSON.stringify({ action: 'settings.update', settings: { theme } }),
    }).catch(() => {});
  }
}

async function setLanguage(language, persist = true) {
  state.language = language;
  await loadTranslations(language);
  if (persist) {
    await api('/api/action', {
      method: 'POST',
      body: JSON.stringify({ action: 'settings.update', settings: { language } }),
    }).catch(() => {});
  }
  render();
}

async function safeLoad(key, loader) {
  state.loading = true; render();
  try {
    state.data[key] = await loader();
    state.error = '';
  } catch (error) {
    state.error = error.message;
  } finally {
    state.loading = false; render();
  }
}

function navigate(page) {
  state.page = page;
  location.hash = page;
  loadPage(page);
}

async function loadPage(page) {
  if (page === 'home') return safeLoad('home', () => api('/api/home'));
  if (page === 'devices') return safeLoad('devices', () => api('/api/devices'));
  if (page === 'screen') return safeLoad('screen', () => api('/api/screen'));
  if (page === 'alerts') return safeLoad('alerts', () => api('/api/alerts'));
  if (page === 'activity') return safeLoad('activity', () => api(`/api/activity?limit=100`));
  if (page === 'settings') {
    await safeLoad('settings', () => api('/api/settings'));
    if (!state.data.diagnostics) await safeLoad('diagnostics', () => api('/api/diagnostics'));
    return;
  }
  if (page === 'diagnostics') return safeLoad('diagnostics', () => api('/api/diagnostics'));
  if (page === 'about') return safeLoad('about', () => api('/api/about'));
  render();
}

function devicePage(id) { state.page = `device:${id}`; safeLoad(`device:${id}`, () => api(`/api/device?id=${encodeURIComponent(id)}`)); }

function badge(status) {
  const icon = status.online ? ICONS.success : (status.needs_attention ? ICONS.warning : ICONS.offline);
  const tone = status.trusted ? (status.needs_attention ? 'warning' : 'success') : 'danger';
  return `<span class="badge ${tone}"><i class="icon">${icon}</i>${escapeHtml(t(status.key))}</span>`;
}

function metricCard(label, value) {
  return `<div class="card"><div class="metric-value">${escapeHtml(value)}</div><div class="metric-label">${escapeHtml(t(label))}</div></div>`;
}

function emptyState(title, body, action = '') {
  return `<div class="card empty"><div class="empty-icon">${ICONS.info}</div><h2>${escapeHtml(title)}</h2><p class="muted">${escapeHtml(body)}</p>${action}</div>`;
}

function renderHome() {
  const home = state.data.home;
  if (!home) return loadingOrError();
  return `
    <section class="card"><p class="muted">${escapeHtml(t(home.greeting_key))}</p><h1>${escapeHtml(t('home.protected_message'))}</h1>
      <p>${badge({ key: home.protection.key, online: home.protection.tone === 'success', needs_attention: home.protection.tone === 'warning', trusted: true })}</p></section>
    <section class="grid cols-4">${home.metrics.map((m) => metricCard(m.label_key, m.value)).join('')}</section>
    <section class="card"><h2>${escapeHtml(t('navigation.activity'))}</h2>${renderActivityList(home.recent_activity)}</section>`;
}

function renderDevices() {
  const devices = state.data.devices?.devices || [];
  const addButton = `<button class="button primary" onclick="startPairing()">${escapeHtml(t('actions.add_device'))}</button>`;
  if (!devices.length) return emptyState(t('devices.empty_title'), t('devices.empty_body'), addButton);
  return `<section class="grid" style="justify-items:end;margin-bottom:12px">${addButton}</section>
    <section class="device-list">${devices.map((d) => `
    <article class="card device-card"><div class="device-card-header"><div><div class="device-name">${escapeHtml(d.name)}</div><div class="device-meta"><span>${escapeHtml(d.id)}</span><span>${escapeHtml(d.connection.last_seen)}</span></div></div>${badge(d.status)}</div>
      <div class="device-meta"><span>${t('device.battery')}: ${d.health.battery_percent ?? '—'}%</span><span>${t('device.storage')}: ${d.health.storage_free_gb ?? '—'} GB</span><span>${t('device.uptime')}: ${escapeHtml(d.health.uptime || '—')}</span></div>
      <div><button class="button" onclick="devicePage('${escapeHtml(d.id)}')">${escapeHtml(t('device.advanced'))}</button> <button class="button primary" onclick="selectScreenDevice('${escapeHtml(d.id)}')">${escapeHtml(t('device.view_screen'))}</button></div>
    </article>`).join('')}</section>`;
}

async function startPairing() {
  state.loading = true; render();
  try {
    const result = await api('/api/action', { method: 'POST', body: JSON.stringify({ action: 'pairing.start', method: 'DEMO' }) });
    state.error = '';
    alert(`${t('pairing.session_created')}\n${result.session.id}\n${t('pairing.next_step')}: ${result.session.next_step}`);
    await loadPage('devices');
  } catch (error) {
    state.error = error.message; render();
  }
}

async function renameDevice(id, currentName) {
  const label = prompt(t('device.rename'), currentName);
  if (!label) return;
  await safeAction(() => api('/api/action', { method: 'POST', body: JSON.stringify({ action: 'devices.rename', device_id: id, label }) }), `device:${id}`);
  await loadPage('devices');
}

async function removeDevice(id) {
  if (!confirm(t('device.confirm_remove'))) return;
  await safeAction(() => api('/api/action', { method: 'POST', body: JSON.stringify({ action: 'devices.revoke', device_id: id }) }), 'devices');
}

function renderDeviceDetail() {
  const id = state.page.split(':')[1];
  const detail = state.data[`device:${id}`];
  if (!detail) return loadingOrError();
  const d = detail.device;
  return `<section class="grid cols-2"><article class="card"><h2>${escapeHtml(d.name)}</h2>${badge(d.status)}<dl class="kvs"><dt>ID</dt><dd>${escapeHtml(d.id)}</dd><dt>${t('device.last_seen')}</dt><dd>${escapeHtml(d.connection.last_seen)}</dd><dt>${t('device.battery')}</dt><dd>${d.health.battery_percent ?? '—'}%</dd><dt>${t('device.storage')}</dt><dd>${d.health.storage_free_gb ?? '—'} GB</dd></dl>
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:16px"><button class="button" onclick="renameDevice('${escapeHtml(d.id)}', '${escapeHtml(d.name)}')">${t('device.rename')}</button><button class="button danger" onclick="removeDevice('${escapeHtml(d.id)}')">${t('device.remove')}</button></div></article>
  <article class="card"><h3>${t('device.permissions')}</h3>${renderRequirements(detail.sections.permissions)}</article></section>`;
}

function renderRequirements(req) {
  if (!req) return '';
  return `<div class="requirement-list">${req.steps.map((step) => `<div class="requirement ${step.ok ? 'ok' : 'pending'}"><i class="icon">${step.ok ? ICONS.success : ICONS.warning}</i><span>${escapeHtml(t(step.label_key))}</span></div>`).join('')}</div>
  <p class="muted">${escapeHtml(t(req.explanation_key))}</p>`;
}

async function selectScreenDevice(id) {
  state.page = 'screen'; await safeLoad('screen', () => api(`/api/screen?device=${encodeURIComponent(id)}`));
  const data = state.data.screen;
  const el = document.querySelector('select[name="screenDevice"]'); if (el) el.value = id;
}

async function requestScreen() {
  const id = document.querySelector('select[name="screenDevice"]')?.value;
  if (!id) return;
  await safeAction(() => api('/api/action', { method: 'POST', body: JSON.stringify({ action: 'screen.request', device_id: id }) }), 'screen');
}

async function stopScreen(sessionId) {
  await safeAction(() => api('/api/action', { method: 'POST', body: JSON.stringify({ action: 'screen.stop', session_id: sessionId }) }), 'screen');
}

function renderScreen() {
  const data = state.data.screen;
  if (!data) return loadingOrError();
  if (!data.devices.length) return emptyState(t('screen.no_active_session'), t('devices.empty_body'));
  const active = data.active_sessions[0];
  return `<section class="grid cols-2"><article class="card"><h2>${escapeHtml(t('screen.title'))}</h2><label class="muted">${escapeHtml(t('navigation.devices'))}</label>
    <select name="screenDevice" style="width:100%;margin:8px 0 16px" onchange="selectScreenDevice(this.value)">${data.devices.map((d) => `<option value="${escapeHtml(d.id)}" ${d.id === data.selected_device_id ? 'selected' : ''}>${escapeHtml(d.name)}</option>`).join('')}</select>
    ${renderRequirements(data.requirements)}
    <div style="margin-top:16px;display:flex;gap:10px;flex-wrap:wrap"><button class="button primary" onclick="requestScreen()" ${data.requirements.can_request ? '' : 'disabled'}>${escapeHtml(t('screen.request'))}</button></div></article>
  <article class="card"><h2>${escapeHtml(t('screen.status'))}</h2><div class="screen-viewer">${active ? `<div class="badge success"><i>${ICONS.success}</i>${escapeHtml(t('status.protected'))}</div><p>${escapeHtml(active.id)}</p><button class="button danger" onclick="stopScreen('${escapeHtml(active.id)}')">${escapeHtml(t('screen.stop'))}</button>` : `<p>${escapeHtml(t('screen.no_active_session'))}</p><p class="muted">${escapeHtml(t(data.capability.message_key))}</p>`}</div>
  <p class="muted">${escapeHtml(t('screen.live_unavailable'))}</p></article></section>`;
}

function renderAlerts() {
  const alerts = state.data.alerts?.alerts || [];
  if (!alerts.length) return emptyState(t('alerts.empty_title'), t('alerts.empty_body'));
  return `<section class="list">${alerts.map((a) => `<article class="card alert-card"><div style="display:flex;justify-content:space-between;gap:12px"><strong>${escapeHtml(a.title)}</strong><span class="badge warning">${escapeHtml(a.relative_time)}</span></div><p class="muted">${escapeHtml(a.message)}</p><div><button class="button" onclick="alertAction('${escapeHtml(a.id)}','alerts.acknowledge')">${t('alerts.acknowledge')}</button> <button class="button" onclick="alertAction('${escapeHtml(a.id)}','alerts.dismiss')">${t('alerts.dismiss')}</button> <button class="button primary" onclick="alertAction('${escapeHtml(a.id)}','alerts.resolve')">${t('alerts.resolve')}</button></div></article>`).join('')}</section>`;
}

async function alertAction(id, action) { await safeAction(() => api('/api/action', { method: 'POST', body: JSON.stringify({ action, alert_id: id }) }), 'alerts'); }

function renderActivityList(items) {
  if (!items?.length) return emptyState(t('activity.empty_title'), t('activity.empty_body'));
  return `<div class="list">${items.map((item) => `<article class="card activity-item"><div style="display:flex;justify-content:space-between;gap:12px"><strong>${escapeHtml(item.title)}</strong><span class="muted">${escapeHtml(item.relative_time)}</span></div><p class="muted">${escapeHtml(item.description)}</p></article>`).join('')}</div>`;
}

function renderActivity() { return renderActivityList(state.data.activity?.activity || []); }

function renderSettings() {
  const settings = state.data.settings;
  if (!settings) return loadingOrError();
  const languages = [['en','English'],['hi','हिन्दी'],['hinglish','Hinglish'],['pt','Português'],['fr','Français'],['zh','中文'],['ko','한국어'],['es','Español']];
  const diagnostics = state.data.diagnostics;
  return `<section class="card"><h2>${t('settings.general')}</h2>
    <div class="setting-row"><label for="language">${t('settings.language')}</label><select id="language" onchange="setLanguage(this.value)">${languages.map(([code,label]) => `<option value="${code}" ${code===state.language?'selected':''}>${label}</option>`).join('')}</select></div>
    <div class="setting-row"><label for="theme">${t('settings.appearance')}</label><select id="theme" onchange="setTheme(this.value)"><option value="system" ${state.theme==='system'?'selected':''}>${t('settings.theme.system')}</option><option value="light" ${state.theme==='light'?'selected':''}>${t('settings.theme.light')}</option><option value="dark" ${state.theme==='dark'?'selected':''}>${t('settings.theme.dark')}</option></select></div></section>
    <section class="card"><h2>${t('settings.privacy')}</h2><p class="muted">${escapeHtml(t('about.body'))}</p><dl class="kvs"><dt>${t('settings.retention')}</dt><dd>${settings.system.retention.alerts_days} / ${settings.system.retention.telemetry_days} days</dd><dt>${t('settings.local_data')}</dt><dd>localhost only</dd></dl></section>
    <section class="card"><h2>${t('settings.security')}</h2><div class="setting-row"><span>${t('settings.device_trust')}</span><span class="badge success">${settings.system.security.trust_status}</span></div><div class="setting-row"><span>${t('settings.session_timeout')}</span><span>${settings.system.security.session_timeout_minutes} min</span></div></section>
    <section class="card"><h2>${t('settings.diagnostics')}</h2>${diagnostics ? `<table class="check-table"><thead><tr><th>${escapeHtml(t('common.diagnostics'))}</th><th>OK</th></tr></thead><tbody>${diagnostics.checks.slice(0, 12).map((check) => `<tr><td>${escapeHtml(check.name)}</td><td>${check.ok ? '✓' : '!'}</td></tr>`).join('')}</tbody></table>` : `<p class="muted">${t('common.loading')}</p>`}</section>`;
}

function renderAbout() {
  const about = state.data.about;
  if (!about) return loadingOrError();
  return `<section class="card"><h2>${escapeHtml(about.name)}</h2><p class="muted">${escapeHtml(about.phase)} · ${escapeHtml(about.version)}</p><p>${escapeHtml(t('app.tagline'))}</p><p class="muted">${escapeHtml(t('about.body'))}</p><p><strong>${t('about.license')}:</strong> ${escapeHtml(about.license)}</p></section>`;
}

function loadingOrError() {
  if (state.error) return `<div class="error-banner"><span>${escapeHtml(state.error)}</span><button class="button" onclick="loadPage(state.page.split(':')[0])">${t('common.try_again')}</button></div>`;
  return `<div class="card loading">${escapeHtml(t('common.loading'))}</div>`;
}

async function safeAction(fn, page) {
  state.loading = true; render();
  try { await fn(); state.error = ''; await loadPage(page); } catch (error) { state.error = error.message; render(); }
}

function render() {
  const app = document.getElementById('app');
  const pages = { home: renderHome, devices: renderDevices, screen: renderScreen, alerts: renderAlerts, activity: renderActivity, settings: renderSettings, about: renderAbout };
  const rootPage = state.page.split(':')[0];
  const content = rootPage === 'device' && state.page.startsWith('device:') ? renderDeviceDetail() : (pages[rootPage] ? pages[rootPage]() : renderHome());
  app.innerHTML = `
    <aside class="sidebar"><div class="brand"><div class="brand-mark">G</div><div>GuardianMesh</div></div><nav class="nav" aria-label="Primary">${navButtons()}</nav><div class="sidebar-footer">${state.bootstrap?.application?.phase || 'Atlas'} · ${state.bootstrap?.application?.version || ''}</div></aside>
    <main class="main"><div class="topbar"><div><h1>${escapeHtml(t(`navigation.${rootPage === 'device' ? 'devices' : rootPage}`))}</h1></div><div class="topbar-actions"><span class="connection-pill"><i class="icon">${ICONS.offline}</i>${escapeHtml(t('common.offline'))}</span></div></div><div class="page">${content}</div></main>
    ${bottomNav()}`;
}

function navButtons() {
  return ['home','devices','screen','alerts','activity','settings','about'].map((id) => `<button class="${state.page === id || (id === 'devices' && state.page.startsWith('device:')) ? 'active' : ''}" onclick="navigate('${id}')"><i class="icon">${ICONS[id]}</i>${escapeHtml(t(`navigation.${id}`))}</button>`).join('');
}

function bottomNav() {
  return `<nav class="bottom-nav" aria-label="Mobile">${['home','devices','screen','alerts','settings'].map((id) => `<button class="${state.page === id ? 'active' : ''}" onclick="navigate('${id}')"><i>${ICONS[id]}</i>${escapeHtml(t(`navigation.${id}`))}</button>`).join('')}</nav>`;
}

window.addEventListener('hashchange', () => { const page = location.hash.replace('#', '') || 'home'; state.page = page; loadPage(page); });

(async function init() {
  await loadTranslations('en');
  await api('/api/session').catch(() => null);
  state.bootstrap = await api('/api/bootstrap').catch(() => ({ application: { phase: 'Atlas', version: '1.1.0' } }));
  await setLanguage(state.bootstrap?.settings?.language || 'en', false);
  setTheme(state.bootstrap?.settings?.theme || 'system', false);
  loadPage(state.page);
})();
