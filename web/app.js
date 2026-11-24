/* acmesh panel — 无框架、无内联脚本（符合 CSP）的前端 */
(() => {
  'use strict';

  const state = {
    user: null,
    csrf: null,
    view: 'certs',
    certs: [],
    catalog: null,
    saved: [],
    jobs: [],
    filter: '',
    logES: null,
    notifyCatalog: null,
    notifiers: [],
    defaultEmail: '',
    certEmails: {},
  };

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));

  // ---------------- API ----------------
  async function api(path, opts = {}) {
    const { method = 'GET', body, raw = false } = opts;
    const headers = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (state.csrf) headers['X-CSRF-Token'] = state.csrf;
    let res;
    try {
      res = await fetch(path, {
        method,
        headers,
        credentials: 'same-origin',
        cache: 'no-store',
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (e) {
      throw new Error('网络请求失败');
    }
    if (res.status === 401) {
      showLogin('会话已过期，请重新登录');
      throw new Error('未登录');
    }
    if (!res.ok) {
      let msg = res.statusText;
      try { const j = await res.json(); if (j && j.error) msg = j.error; } catch (_) { /* ignore */ }
      if (res.status === 429) {
        const ra = res.headers.get('Retry-After');
        if (ra) msg = `${msg}（${ra}s）`;
      }
      throw new Error(msg || '请求失败');
    }
    if (raw) return res;
    const ct = res.headers.get('content-type') || '';
    return ct.includes('json') ? res.json() : res.text();
  }

  // ---------------- UI 基础 ----------------
  function toast(msg, type = '') {
    const div = document.createElement('div');
    div.className = 'toast ' + type;
    div.textContent = msg;
    $('#toasts').appendChild(div);
    setTimeout(() => { div.style.opacity = '0'; div.style.transition = 'opacity .3s'; }, 2600);
    setTimeout(() => div.remove(), 3000);
  }

  function openModal(title, bodyHTML, footHTML) {
    $('#modal-title').textContent = title;
    $('#modal-body').innerHTML = bodyHTML;
    $('#modal-foot').innerHTML = footHTML || '';
    $('#modal').classList.remove('hidden');
    return $('#modal-body');
  }
  function closeModal() {
    $('#modal').classList.add('hidden');
    $('#modal-body').innerHTML = '';
    $('#modal-foot').innerHTML = '';
  }
  function openDrawer(title, sub) {
    $('#drawer-title').textContent = title;
    $('#drawer-sub').textContent = sub || '';
    $('#drawer').classList.remove('hidden');
    $('#overlay').classList.remove('hidden');
  }
  function closeDrawer() {
    $('#drawer').classList.add('hidden');
    $('#overlay').classList.add('hidden');
    $('#drawer-body').innerHTML = '';
  }

  $('#modal-close').addEventListener('click', closeModal);
  $('#modal').addEventListener('click', (e) => { if (e.target.id === 'modal') closeModal(); });
  $('#drawer-close').addEventListener('click', closeDrawer);
  $('#overlay').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { closeModal(); closeDrawer(); }
  });

  async function copyText(text, label = '已复制') {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
      }
      toast(label, '');
    } catch (e) {
      toast('复制失败，请手动选择文本', 'err');
    }
  }

  function downloadText(filename, text) {
    const blob = new Blob([text], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  }

  // ---------------- 认证 ----------------
  function showLogin(msg) {
    if (state.logES) { state.logES.close(); state.logES = null; }
    state.user = null;
    state.csrf = null;
    $('#main-view').classList.add('hidden');
    $('#login-view').classList.remove('hidden');
    $('#login-error').textContent = msg || '';
    setTimeout(() => $('#login-user').focus(), 30);
  }

  function showMain() {
    $('#login-view').classList.add('hidden');
    $('#main-view').classList.remove('hidden');
    $('#sb-user').textContent = state.user;
  }

  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('#login-btn');
    const err = $('#login-error');
    err.textContent = '';
    btn.disabled = true;
    try {
      const r = await api('/api/login', {
        method: 'POST',
        body: { username: $('#login-user').value.trim(), password: $('#login-pass').value, remember: $('#login-remember').checked },
      });
      state.user = r.user;
      state.csrf = r.csrf;
      $('#login-pass').value = '';
      showMain();
      await loadAll();
      loadSysInfo();
    } catch (ex) {
      err.textContent = ex.message;
    } finally {
      btn.disabled = false;
    }
  });

  $('#logout-btn').addEventListener('click', async () => {
    try { await api('/api/logout', { method: 'POST', body: {} }); } catch (_) { /* ignore */ }
    showLogin('');
  });

  // ---------------- 启动 ----------------
  async function boot() {
    try {
      const s = await api('/api/session');
      state.user = s.user;
      state.csrf = s.csrf;
      state.defaultEmail = s.default_email || '';
      showMain();
      $('#sb-acme').textContent = s.acme_version || 'acme.sh 未就绪';
      await loadAll();
      // 刷新页面后回到上次所在页面，而不是总是证书首页
      let saved = 'certs';
      try { saved = localStorage.getItem('acmesh-view-' + state.user) || 'certs'; } catch (e) { /* ignore */ }
      if (titles[saved]) switchView(saved);
    } catch (e) {
      if (e.message !== '未登录') showLogin('');
    }
  }

  async function loadAll() {
    await Promise.all([loadCatalog(), loadNotifyCatalog(), loadCerts(), loadJobs()]);
    refreshJobsBadge();
  }

  // ---------------- 视图切换 ----------------
  const titles = {
    certs: ['证书', '来自 acme.sh 的证书，可查看、复制、续期与部署'],
    jobs: ['任务', '签发 / 续期 / 部署的执行记录与实时日志'],
    notify: ['通知', '按域名自定义 ACME 邮箱，Webhook 推送签发 / 续期 / 临期 / 安全事件'],
    creds: ['DNS 凭证', 'AES-256-GCM 加密存储，接口只返回掩码'],
    sync: ['证书同步', '签发 / 续期后自动覆盖挂载目录里的证书与私钥文件'],
    settings: ['设置', '账号安全与系统信息'],
  };

  function switchView(v) {
    state.view = v;
    try { localStorage.setItem('acmesh-view-' + state.user, v); } catch (e) { /* 隐私模式忽略 */ }
    $$('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.view === v));
    ['certs', 'jobs', 'notify', 'creds', 'sync', 'settings'].forEach((k) => {
      $('#view-' + k).classList.toggle('hidden', k !== v);
    });
    const [t, s] = titles[v];
    $('#page-title').textContent = t;
    $('#page-sub').textContent = s;
    if (v === 'notify') loadNotify();
    if (v === 'creds') loadProviders();
    if (v === 'sync') loadSync();
    if (v === 'settings') { loadSysInfo(); loadAudit(); }
    if (v === 'jobs') loadJobs();
  }
  $('#nav').addEventListener('click', (e) => {
    const b = e.target.closest('.nav-item');
    if (b) switchView(b.dataset.view);
  });

  // ---------------- 证书 ----------------
  async function loadCerts() {
    try {
      const r = await api('/api/certs');
      state.certs = r.certs || [];
      renderStats();
      renderCerts();
    } catch (e) {
      toast(e.message, 'err');
    }
  }

  function renderStats() {
    const c = state.certs;
    $('#st-total').textContent = c.length;
    $('#st-valid').textContent = c.filter((x) => x.status === 'valid').length;
    $('#st-warning').textContent = c.filter((x) => x.status === 'warning' || x.status === 'critical').length;
    $('#st-expired').textContent = c.filter((x) => x.status === 'expired').length;
  }

  const statusChip = (s, days) => {
    if (s === 'expired') return '<span class="chip red">已过期</span>';
    if (s === 'critical') return `<span class="chip red">${days} 天后到期</span>`;
    if (s === 'warning') return `<span class="chip yellow">${days} 天后到期</span>`;
    return `<span class="chip green">${days} 天后到期</span>`;
  };

  function renderCerts() {
    const q = state.filter.toLowerCase().trim();
    const list = state.certs.filter((c) => {
      if (!q) return true;
      return (c.domain + ' ' + (c.sans || []).join(' ')).toLowerCase().includes(q);
    });
    const box = $('#cert-list');
    box.innerHTML = '';
    $('#cert-empty').classList.toggle('hidden', list.length !== 0);
    for (const c of list) {
      const others = (c.sans || []).filter((d) => d !== c.domain);
      const card = document.createElement('div');
      card.className = 'cert-card';
      card.dataset.name = c.name;
      card.innerHTML = `
        <div class="cert-top">
          <span class="status-dot ${esc(c.status)}"></span>
          <div class="minw0 flex1">
            <div class="cert-name">${esc(c.domain)}</div>
            <div class="cert-meta">
              ${statusChip(c.status, c.days_left)}
              <span class="chip">${esc(c.key_type || '-')}${c.key_bits ? ' ' + c.key_bits : ''}</span>
              ${c.is_ecc ? '<span class="chip">ECC</span>' : ''}
              ${others.length ? `<span class="chip">+${others.length} SAN</span>` : ''}
            </div>
          </div>
        </div>
        <div class="cert-sans">${esc(others.length ? others.join(', ') : '签发者: ' + (c.issuer || '-'))}</div>
        <div class="cert-foot">
          <button class="btn small" data-act="detail">详情</button>
          <button class="btn small" data-act="key">私钥</button>
          <button class="btn small" data-act="renew">续期</button>
        </div>`;
      box.appendChild(card);
    }
  }

  $('#cert-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    const name = btn.closest('[data-name]').dataset.name;
    const cert = state.certs.find((c) => c.name === name);
    if (!cert) return;
    const act = btn.dataset.act;
    if (act === 'detail') openCertDrawer(cert);
    else if (act === 'key') confirmKeyView(cert);
    else if (act === 'renew') doRenew(cert);
  });

  $('#cert-filter').addEventListener('input', (e) => {
    state.filter = e.target.value;
    renderCerts();
  });
  $('#refresh-btn').addEventListener('click', async () => {
    await loadAll();
    toast('已刷新');
  });

  // ---------------- 证书详情抽屉 ----------------
  async function openCertDrawer(cert) {
    openDrawer(cert.domain, cert.name);
    const body = $('#drawer-body');
    const files = cert.files || {};
    const rows = [
      ['域名 (CN)', cert.subject || cert.domain],
      ['替代名称', (cert.sans || []).join(', ') || '-'],
      ['签发者', cert.issuer || '-'],
      ['状态', statusText(cert)],
      ['生效时间', fmtTime(cert.not_before)],
      ['到期时间', fmtTime(cert.not_after)],
      ['序列号', cert.serial || '-'],
      ['公钥', `${cert.key_type || '-'} ${cert.key_bits || ''}`],
      ['证书目录', cert.is_ecc ? 'ECC 目录 (_ecc)' : 'RSA 目录'],
      ['私钥文件', cert.has_key ? '存在' : '不存在'],
      ['ACME 邮箱', cert.email || (state.defaultEmail ? state.defaultEmail + '（默认）' : '未设置')],
    ];
    body.innerHTML = `
      <div class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</div>
      <div class="section-title">证书链</div>
      <div class="tabs" id="pem-tabs">
        ${['fullchain', 'cert', 'chain'].filter((k) => files[k]).map((k, i) =>
          `<button class="tab${i === 0 ? ' active' : ''}" data-kind="${k}">${k === 'fullchain' ? '完整链' : k === 'cert' ? '证书' : '中间链'}</button>`).join('')}
      </div>
      <textarea class="pem-box" id="pem-view" readonly spellcheck="false"></textarea>
      <div class="pem-actions">
        <button class="btn small" id="pem-copy">复制</button>
        <button class="btn small" id="pem-dl">下载</button>
      </div>
      <div class="section-title">私钥</div>
      <div class="panel panel-flat">
        <p class="tiny muted">私钥可明文查看与复制。每次查看都会记录审计日志（操作人 / 来源 IP / 时间），并需要二次确认。</p>
        <div class="pem-actions">
          <button class="btn small danger" id="drawer-key">🔑 查看私钥</button>
          <button class="btn small" id="drawer-install">部署到 /data/output</button>
        </div>
      </div>
      <div class="section-title">操作</div>
      <div class="pem-actions">
        <button class="btn small" id="drawer-renew">续期</button>
        <button class="btn small" id="drawer-email">修改邮箱</button>
        <button class="btn small" id="drawer-revoke">吊销</button>
        <button class="btn small danger" id="drawer-remove">移除证书</button>
      </div>`;

    const pemView = $('#pem-view');
    let activeKind = null;
    async function loadPem(kind) {
      activeKind = kind;
      pemView.value = '加载中…';
      try {
        pemView.value = await api(`/api/certs/${encodeURIComponent(cert.name)}/pem/${kind}`);
      } catch (e) {
        pemView.value = '加载失败: ' + e.message;
      }
      $$('#pem-tabs .tab').forEach((t) => t.classList.toggle('active', t.dataset.kind === kind));
    }
    const first = ['fullchain', 'cert', 'chain'].find((k) => files[k]);
    if (first) loadPem(first); else pemView.value = '无可读的证书文件';

    $('#pem-tabs')?.addEventListener('click', (e) => {
      const t = e.target.closest('.tab');
      if (t) loadPem(t.dataset.kind);
    });
    $('#pem-copy').addEventListener('click', () => {
      if (!pemView.value) return;
      copyText(pemView.value, '证书已复制');
    });
    $('#pem-dl').addEventListener('click', () => {
      if (!pemView.value || !activeKind) return;
      downloadText(`${cert.name}-${activeKind}.pem`, pemView.value);
    });

    $('#drawer-key').addEventListener('click', () => confirmKeyView(cert, true));
    $('#drawer-email').addEventListener('click', () => openCertEmailModal(cert));
    $('#drawer-renew').addEventListener('click', () => doRenew(cert));
    $('#drawer-install').addEventListener('click', () => doInstall(cert));
    $('#drawer-revoke').addEventListener('click', () => doRevoke(cert));
    $('#drawer-remove').addEventListener('click', () => doRemove(cert));
  }

  function openCertEmailModal(cert) {
    openModal('修改域名邮箱', `
      <p class="muted small">为 <b>${esc(cert.domain)}</b> 设置专用 ACME 邮箱；留空则恢复使用全局默认邮箱。</p>
      <div class="field mt12">
        <label for="ce-email">邮箱地址</label>
        <input id="ce-email" type="email" value="${esc(cert.email || '')}"
               placeholder="${esc(state.defaultEmail || 'you@example.com')}" spellcheck="false">
      </div>
      <p class="hint">换邮箱相当于换 ACME 账户，需重新签发才会应用到证书；续期会沿用原账户。</p>
    `, `<button class="btn ghost" id="ce-cancel">取消</button><button class="btn primary" id="ce-go">保存</button>`);
    $('#ce-cancel').addEventListener('click', closeModal);
    $('#ce-go').addEventListener('click', async () => {
      const email = $('#ce-email').value.trim();
      try {
        await api(`/api/certs/${encodeURIComponent(cert.name)}/email`, {
          method: 'POST', body: { email },
        });
        closeModal();
        cert.email = email;
        openCertDrawer(cert);
        await loadCerts();
        toast(email ? '域名邮箱已保存' : '已恢复使用默认邮箱');
      } catch (e) { toast(e.message, 'err'); }
    });
  }

  function statusText(c) {
    if (c.status === 'expired') return '已过期';
    if (c.status === 'critical') return `即将过期（${c.days_left} 天）`;
    if (c.status === 'warning') return `临期（${c.days_left} 天）`;
    return `有效（剩余 ${c.days_left} 天）`;
  }

  function fmtTime(t) {
    if (!t || t.startsWith('0001')) return '-';
    const d = new Date(t);
    if (isNaN(d.getTime())) return '-';
    return d.toLocaleString('zh-CN', { hour12: false });
  }

  // ---------------- 私钥查看（二次确认） ----------------
  function confirmKeyView(cert, fromDrawer) {
    openModal('查看私钥', `
      <div class="callout">你即将查看 <b>${esc(cert.domain)}</b> 的私钥明文。请确认：
        <ul class="callout-list">
          <li>当前屏幕与网络环境可信（无他人旁观 / 无录屏）</li>
          <li>本次操作会被记入审计日志（含来源 IP）</li>
          <li>不要将私钥粘贴到聊天工具或公共仓库</li>
        </ul>
      </div>
      <label class="check"><input type="checkbox" id="key-ack"> 我已知悉风险，确认查看私钥</label>
    `, `
      <button class="btn ghost" id="key-cancel">取消</button>
      <button class="btn danger" id="key-go" disabled>查看私钥</button>
    `);
    const ack = $('#key-ack');
    const go = $('#key-go');
    ack.addEventListener('change', () => { go.disabled = !ack.checked; });
    $('#key-cancel').addEventListener('click', closeModal);
    go.addEventListener('click', async () => {
      go.disabled = true;
      go.textContent = '读取中…';
      try {
        const r = await api(`/api/certs/${encodeURIComponent(cert.name)}/key`, {
          method: 'POST',
          body: { confirm: 'I-UNDERSTAND' },
        });
        showKeyResult(cert, r.pem);
      } catch (e) {
        closeModal();
        toast(e.message, 'err');
      }
    });
  }

  function showKeyResult(cert, pem) {
    openModal('私钥 · ' + cert.domain, `
      <div class="callout">私钥明文仅在本页内存中显示 60 秒，之后自动清除。</div>
      <textarea class="pem-box" id="key-view" readonly spellcheck="false"></textarea>
      <div class="pem-actions">
        <button class="btn small" id="key-copy">复制私钥</button>
        <button class="btn small" id="key-dl">下载 .key</button>
      </div>
    `, `<button class="btn ghost" id="key-close">关闭</button>`);
    const ta = $('#key-view');
    ta.value = pem;
    $('#key-copy').addEventListener('click', () => copyText(pem, '私钥已复制到剪贴板'));
    $('#key-dl').addEventListener('click', () => downloadText(`${cert.domain}.key`, pem));
    $('#key-close').addEventListener('click', closeModal);
    const timer = setTimeout(() => {
      if (ta) { ta.value = ''; ta.placeholder = '私钥已自动清除，请重新验证查看'; }
    }, 60000);
    $('#key-close').addEventListener('click', () => clearTimeout(timer), { once: true });
  }

  // ---------------- 签发 ----------------
  $('#issue-btn').addEventListener('click', () => openIssueModal());

  function providerOptions(selected) {
    return (state.catalog?.providers || []).map((p) =>
      `<option value="${esc(p.code)}"${p.code === selected ? ' selected' : ''}>${esc(p.name)} (${esc(p.code)})</option>`).join('');
  }

  function envFieldsHTML(code) {
    const def = (state.catalog?.providers || []).find((p) => p.code === code);
    if (!def) return '';
    return def.fields.map((f) => `
      <div class="field">
        <label for="env-${esc(f.name)}">${esc(f.label)}${f.optional ? '（可选）' : ''}</label>
        <input id="env-${esc(f.name)}" data-env="${esc(f.name)}" type="${f.secret ? 'password' : 'text'}"
               autocomplete="off" spellcheck="false" placeholder="${esc(f.hint || f.name)}">
      </div>`).join('');
  }

  function openIssueModal(preset = {}) {
    const saved = state.saved || [];
    openModal('签发证书', `
      <div class="field">
        <label for="iss-domains">域名（每行一个，首个为主域名）</label>
        <textarea id="iss-domains" placeholder="example.com&#10;*.example.com"></textarea>
        <p class="hint">支持泛域名 *.example.com（必须用 DNS API 验证）</p>
      </div>
      <div class="grid2">
        <div class="field">
          <label for="iss-cred">凭证来源</label>
          <select id="iss-cred">
            <option value="">使用新的 DNS API 凭证</option>
            ${saved.map((s) => `<option value="${esc(s.name)}">已保存：${esc(s.name)}（${esc(s.code)}）</option>`).join('')}
          </select>
        </div>
        <div class="field">
          <label for="iss-keysize">密钥类型</label>
          <select id="iss-keysize">
            ${['ec-256', 'ec-384', '2048', '4096'].map((k) => `<option value="${k}"${k === 'ec-256' ? ' selected' : ''}>${k}</option>`).join('')}
          </select>
        </div>
      </div>
      <div id="iss-manual">
        <div class="field">
          <label for="iss-code">DNS 服务商</label>
          <select id="iss-code">${providerOptions('dns_ali')}</select>
        </div>
        <div id="iss-env">${envFieldsHTML('dns_ali')}</div>
        <div class="field">
          <label for="iss-saveas">保存为凭证（可选）</label>
          <input id="iss-saveas" placeholder="例如 ali-prod" spellcheck="false">
          <p class="hint">填写后会加密保存，下次签发可直接选用</p>
        </div>
      </div>
      <div class="field">
        <label for="iss-email">ACME 通知邮箱（可选）</label>
        <input id="iss-email" type="email" placeholder="留空使用默认邮箱" spellcheck="false">
        <p class="hint" id="iss-email-hint">默认：${esc(state.defaultEmail || '未设置')} · CA 的到期提醒会发到这里</p>
      </div>
      <div class="grid2">
        <div class="field">
          <label for="iss-ca">CA</label>
          <select id="iss-ca">
            ${(state.catalog?.cas || []).map((c) => `<option value="${esc(c.code)}"${c.code === (state.catalog?.default_ca || 'letsencrypt') ? ' selected' : ''}>${esc(c.name)}</option>`).join('')}
          </select>
        </div>
        <div class="field field-end">
          <label class="check mt8"><input type="checkbox" id="iss-force"> 强制重新签发</label>
        </div>
      </div>
      <div class="callout info">签发前请确认域名的 DNS 解析已托管在你选择的服务商，且 API 凭证具备解析记录编辑权限。</div>
    `, `
      <button class="btn ghost" id="iss-cancel">取消</button>
      <button class="btn primary" id="iss-go">开始签发</button>
    `);

    $('#iss-domains').value = preset.domains || '';
    const credSel = $('#iss-cred');
    const manual = $('#iss-manual');
    const syncCred = () => { manual.classList.toggle('hidden', !!credSel.value); };
    credSel.addEventListener('change', syncCred);
    syncCred();

    $('#iss-code').addEventListener('change', (e) => {
      $('#iss-env').innerHTML = envFieldsHTML(e.target.value);
    });

    $('#iss-cancel').addEventListener('click', closeModal);
    $('#iss-go').addEventListener('click', async () => {
      const domains = $('#iss-domains').value.split(/[\s,，]+/).map((s) => s.trim()).filter(Boolean);
      if (!domains.length) { toast('请至少填写一个域名', 'err'); return; }
      const body = {
        domains,
        credential: credSel.value,
        keylength: $('#iss-keysize').value,
        ca: $('#iss-ca').value,
        force: $('#iss-force').checked,
      };
      const certEmail = $('#iss-email').value.trim();
      if (certEmail) body.email = certEmail;
      if (!credSel.value) {
        body.code = $('#iss-code').value;
        body.env = {};
        $$('#iss-env [data-env]').forEach((i) => { body.env[i.dataset.env] = i.value; });
        const saveAs = $('#iss-saveas').value.trim();
        if (saveAs) body.save_as = saveAs;
      }
      const btn = $('#iss-go');
      btn.disabled = true;
      btn.textContent = '提交中…';
      try {
        const r = await api('/api/issue', { method: 'POST', body });
        closeModal();
        toast('签发任务已创建');
        await loadJobs();
        switchView('jobs');
        openJobLog(r.job.id, r.job.title);
      } catch (e) {
        toast(e.message, 'err');
        btn.disabled = false;
        btn.textContent = '开始签发';
      }
    });
  }

  // ---------------- 证书操作 ----------------
  async function doRenew(cert) {
    openModal('续期 ' + cert.domain, `
      <p class="muted small">将对 <b>${esc(cert.domain)}</b> 执行 acme.sh --renew，沿用原证书的验证方式与 DNS 凭证。</p>
      <label class="check mt12"><input type="checkbox" id="renew-force"> 强制续期（忽略剩余有效期）</label>
    `, `<button class="btn ghost" id="rn-cancel">取消</button><button class="btn primary" id="rn-go">开始续期</button>`);
    $('#rn-cancel').addEventListener('click', closeModal);
    $('#rn-go').addEventListener('click', async () => {
      try {
        const r = await api(`/api/certs/${encodeURIComponent(cert.name)}/renew`, {
          method: 'POST',
          body: { force: $('#renew-force').checked },
        });
        closeModal();
        closeDrawer();
        await loadJobs();
        switchView('jobs');
        openJobLog(r.job.id, r.job.title);
      } catch (e) { toast(e.message, 'err'); }
    });
  }

  async function doInstall(cert) {
    try {
      const r = await api(`/api/certs/${encodeURIComponent(cert.name)}/install`, { method: 'POST', body: {} });
      toast('部署任务已创建');
      await loadJobs();
      switchView('jobs');
      openJobLog(r.job.id, r.job.title);
    } catch (e) { toast(e.message, 'err'); }
  }

  async function doRevoke(cert) {
    openModal('吊销证书', `
      <div class="callout">吊销 <b>${esc(cert.domain)}</b> 后证书将立即失效且不可恢复，确定继续？</div>
    `, `<button class="btn ghost" id="rv-cancel">取消</button><button class="btn danger" id="rv-go">确认吊销</button>`);
    $('#rv-cancel').addEventListener('click', closeModal);
    $('#rv-go').addEventListener('click', async () => {
      try {
        const r = await api(`/api/certs/${encodeURIComponent(cert.name)}/revoke`, { method: 'POST', body: {} });
        closeModal(); closeDrawer();
        await loadJobs(); switchView('jobs'); openJobLog(r.job.id, r.job.title);
      } catch (e) { toast(e.message, 'err'); }
    });
  }

  async function doRemove(cert) {
    openModal('移除证书', `
      <div class="callout">将执行 acme.sh --remove，把 <b>${esc(cert.domain)}</b> 从续期列表移除。</div>
      <label class="check"><input type="checkbox" id="rm-purge"> 同时删除磁盘上的证书目录（含私钥，不可恢复）</label>
    `, `<button class="btn ghost" id="rm-cancel">取消</button><button class="btn danger" id="rm-go">确认移除</button>`);
    $('#rm-cancel').addEventListener('click', closeModal);
    $('#rm-go').addEventListener('click', async () => {
      try {
        const r = await api(`/api/certs/${encodeURIComponent(cert.name)}/remove`, {
          method: 'POST', body: { purge: $('#rm-purge').checked },
        });
        closeModal(); closeDrawer();
        await loadJobs(); switchView('jobs'); openJobLog(r.job.id, r.job.title);
      } catch (e) { toast(e.message, 'err'); }
    });
  }

  $('#renew-all-btn').addEventListener('click', async () => {
    try {
      const r = await api('/api/renew-all', { method: 'POST', body: {} });
      toast('续期检查已开始');
      await loadJobs(); switchView('jobs'); openJobLog(r.job.id, r.job.title);
    } catch (e) { toast(e.message, 'err'); }
  });

  // ---------------- 任务 ----------------
  async function loadJobs() {
    try {
      const r = await api('/api/jobs');
      state.jobs = r.jobs || [];
      renderJobs();
      refreshJobsBadge();
    } catch (e) { /* silent */ }
  }

  function refreshJobsBadge() {
    const active = state.jobs.filter((j) => j.status === 'running' || j.status === 'queued').length;
    const b = $('#job-badge');
    b.textContent = active;
    b.classList.toggle('hidden', active === 0);
  }

  function renderJobs() {
    const box = $('#job-list');
    box.innerHTML = '';
    $('#job-empty').classList.toggle('hidden', state.jobs.length !== 0);
    for (const j of state.jobs) {
      const row = document.createElement('div');
      row.className = 'row job-item';
      row.dataset.id = j.id;
      const st = { queued: '排队', running: '执行中', success: '成功', failed: '失败', canceled: '已取消', skipped: '未到期' }[j.status] || j.status;
      row.innerHTML = `
        <div class="row-main minw0">
          <div class="row-title">${esc(j.title)}</div>
          <div class="tiny muted mt2">${esc(fmtTime(j.created))} · ${esc(j.kind)}</div>
        </div>
        <span class="job-status ${esc(j.status)}">${esc(st)}</span>
        <span class="muted">›</span>`;
      row.addEventListener('click', () => openJobLog(j.id, j.title));
      box.appendChild(row);
    }
  }

  function openJobLog(id, title) {
    openModal(title || '任务日志', `<div class="log" id="job-log"></div>`, `
      <button class="btn ghost small hidden" id="job-cancel">取消任务</button>
      <span class="grow"></span>
      <button class="btn small" id="job-reload">刷新列表</button>
      <button class="btn ghost" id="job-close">关闭</button>`);
    const logEl = $('#job-log');
    const append = (line, cls) => {
      const span = document.createElement('span');
      if (cls) span.className = cls;
      span.textContent = line + '\n';
      logEl.appendChild(span);
      logEl.scrollTop = logEl.scrollHeight;
    };
    if (state.logES) { state.logES.close(); state.logES = null; }
    const es = new EventSource(`/api/jobs/${encodeURIComponent(id)}/events`);
    state.logES = es;
    es.onmessage = (ev) => {
      const line = ev.data;
      let cls = '';
      if (line.startsWith('✗')) cls = 'l-err';
      else if (line.startsWith('ℹ')) cls = 'l-info';
      else if (line.startsWith('✓')) cls = 'l-ok';
      else if (line.startsWith('$')) cls = 'l-cmd';
      append(line, cls);
    };
    es.addEventListener('done', async (ev) => {
      append('—— 任务结束：' + ev.data + ' ——', ev.data === 'success' ? 'l-ok' : (ev.data === 'skipped' ? 'l-info' : 'l-err'));
      es.close();
      state.logES = null;
      await Promise.all([loadJobs(), loadCerts()]);
      if (ev.data === 'success') toast('任务执行成功');
      else if (ev.data === 'skipped') toast('证书未到续期时间');
      else toast('任务结束：' + ev.data, ev.data === 'canceled' ? 'warn' : 'err');
      $('#job-cancel').classList.add('hidden');
    });
    es.onerror = () => { /* 关闭或断线时浏览器会自动重连，这里不打扰用户 */ };
    $('#job-close').addEventListener('click', () => {
      if (state.logES) { state.logES.close(); state.logES = null; }
      closeModal();
    });
    $('#job-reload').addEventListener('click', async () => { await loadJobs(); closeModal(); switchView('jobs'); });
    const cancelBtn = $('#job-cancel');
    cancelBtn.classList.remove('hidden');
    cancelBtn.addEventListener('click', async () => {
      try { await api(`/api/jobs/${encodeURIComponent(id)}/cancel`, { method: 'POST', body: {} }); toast('已请求取消'); }
      catch (e) { toast(e.message, 'err'); }
    });
  }

  // 任务进行中时轮询列表，保证角标与状态新鲜
  setInterval(async () => {
    if (!state.user) return;
    if (state.jobs.some((j) => j.status === 'running' || j.status === 'queued')) {
      await loadJobs();
      if (state.view === 'certs') await loadCerts();
    }
  }, 6000);

  // ---------------- 通知渠道 ----------------
  async function loadNotifyCatalog() {
    try {
      state.notifyCatalog = await api('/api/notify/catalog');
      state.defaultEmail = state.notifyCatalog.default_email || state.defaultEmail;
    } catch (e) { /* ignore */ }
  }

  const eventLabel = (code) => {
    const e = (state.notifyCatalog?.events || []).find((x) => x.code === code);
    return e ? e.name : code;
  };
  const kindLabel = (code) => {
    const k = (state.notifyCatalog?.kinds || []).find((x) => x.code === code);
    return k ? k.name : code;
  };

  async function loadNotify() {
    try {
      // 每次打开通知页都重新拉目录，避免旧页面缓存导致新事件（如证书同步）不显示
      state.notifyCatalog = await api('/api/notify/catalog');
      const r = await api('/api/notify');
      state.notifiers = r.notifiers || [];
      state.certEmails = r.cert_emails || {};
      state.defaultEmail = r.default_email || '';
      $('#default-email').value = state.defaultEmail;
      $('#default-email-source').textContent = state.defaultEmail
        ? '签发证书留空时，将使用此邮箱作为 ACME 账户邮箱。修改后需重新签发才会应用到证书。'
        : '未设置时，签发不带 --accountemail，使用 acme.sh 安装时配置的账户。';
      renderNotifiers();
      const cat = state.notifyCatalog;
      $('#event-help').innerHTML = (cat?.events || []).map((e) =>
        `<span class="chip" title="${esc(e.code)}">${esc(e.name)}</span>`).join('');
    } catch (e) { toast(e.message, 'err'); }
  }

  function renderNotifiers() {
    const box = $('#notifier-list');
    box.innerHTML = '';
    if (!state.notifiers.length) {
      box.innerHTML = '<div class="empty"><p>还没有通知渠道</p><p class="tiny muted">添加 Gotify 或通用 Webhook 后，签发 / 续期 / 失败 / 临期都能推送到手机</p></div>';
      return;
    }
    for (const n of state.notifiers) {
      const row = document.createElement('div');
      row.className = 'row notifier-row';
      row.dataset.id = n.id;
      const evs = (n.events || []).map((e) => `<span class="chip">${esc(eventLabel(e))}</span>`).join('');
      row.innerHTML = `
        <div class="row-main">
          <div class="row-title">${esc(n.name)}
            <span class="chip">${esc(kindLabel(n.kind))}</span>
            <span class="chip ${n.enabled ? 'green' : ''}">${n.enabled ? '启用' : '停用'}</span>
          </div>
          <div class="tiny muted mono mt3">${esc(n.target_masked || '—')}${n.secret_masked ? ' · ' + esc(n.secret_masked) : ''}</div>
          <div class="cert-meta">${evs || '<span class="chip">未订阅事件</span>'}</div>
        </div>
        <button class="btn small" data-act="test" title="发送一条测试消息">测试</button>
        <button class="btn small" data-act="edit">编辑</button>
        <button class="btn small danger" data-act="del">删除</button>`;
      row.addEventListener('click', async (e) => {
        const btn = e.target.closest('[data-act]');
        if (!btn) return;
        const id = n.id;
        const act = btn.dataset.act;
        if (act === 'edit') openNotifierModal(n);
        else if (act === 'test') {
          btn.disabled = true;
          try {
            await api(`/api/notify/${encodeURIComponent(id)}/test`, { method: 'POST', body: {} });
            toast('测试消息已推送');
          } catch (ex) { toast(ex.message, 'err'); }
          finally { btn.disabled = false; }
        } else if (act === 'del') {
          if (!confirm(`确定删除通知渠道「${n.name}」？`)) return;
          try {
            await api(`/api/notify/${encodeURIComponent(id)}`, { method: 'DELETE' });
            toast('已删除');
            await loadNotify();
          } catch (ex) { toast(ex.message, 'err'); }
        }
      });
      box.appendChild(row);
    }
  }

  function openNotifierModal(existing) {
    const kinds = state.notifyCatalog?.kinds || [];
    const events = state.notifyCatalog?.events || [];
    const selected = existing?.events || ['cert_issued', 'issue_failed', 'cert_renewed', 'renew_failed'];
    openModal(existing ? '编辑通知渠道' : '添加通知渠道', `
      <div class="field">
        <label for="nt-name">名称</label>
        <input id="nt-name" value="${esc(existing?.name || '')}" placeholder="例如 Gotify 手机推送">
      </div>
      <div class="field">
        <label for="nt-kind">类型</label>
        <select id="nt-kind">
          ${kinds.map((k) => `<option value="${esc(k.code)}"${existing?.kind === k.code ? ' selected' : ''}>${esc(k.name)}</option>`).join('')}
        </select>
        <p class="hint" id="nt-hint"></p>
      </div>
      <div class="field" id="nt-target-field">
        <label for="nt-target">${existing ? '服务地址 / Webhook URL（留空保持不变）' : '服务地址 / Webhook URL'}</label>
        <input id="nt-target" value="" placeholder="https://push.example.com" spellcheck="false">
      </div>
      <div class="field" id="nt-secret-field">
        <label for="nt-secret">${existing ? 'Token / 密钥（留空保持不变）' : 'Token / 密钥'}</label>
        <input id="nt-secret" type="password" value="" autocomplete="off" spellcheck="false">
      </div>
      <div class="section-title">订阅事件</div>
      <div class="event-grid" id="nt-events">
        ${events.map((e) => `
          <label class="check ev-item">
            <input type="checkbox" data-event="${esc(e.code)}"${selected.includes(e.code) ? ' checked' : ''}>
            <span>${esc(e.name)}<br><code>${esc(e.code)}</code></span>
          </label>`).join('')}
      </div>
      <label class="check mt12"><input type="checkbox" id="nt-enabled"${existing?.enabled !== false ? ' checked' : ''}> 启用此渠道</label>
    `, `<button class="btn ghost" id="nt-cancel">取消</button><button class="btn primary" id="nt-go">保存</button>`);

    const kindSel = $('#nt-kind');
    const syncKind = () => {
      const def = kinds.find((k) => k.code === kindSel.value) || {};
      $('#nt-target-field').classList.toggle('hidden', !def.need_target);
      $('#nt-secret-field').classList.toggle('hidden', !def.need_secret);
      $('#nt-hint').textContent = def.hint || '';
      $('#nt-target').placeholder = def.target_label || '';
      $('#nt-secret').placeholder = def.secret_label || '';
    };
    kindSel.addEventListener('change', syncKind);
    syncKind();

    $('#nt-cancel').addEventListener('click', closeModal);
    $('#nt-go').addEventListener('click', async () => {
      const body = {
        id: existing?.id || '',
        name: $('#nt-name').value.trim(),
        kind: kindSel.value,
        target: $('#nt-target').value.trim(),
        secret: $('#nt-secret').value.trim(),
        events: $$('#nt-events [data-event]:checked').map((i) => i.dataset.event),
        enabled: $('#nt-enabled').checked,
        keep_target: !!existing && !body.target,
        keep_secret: !!existing && !body.secret,
      };
      if (!body.name) { toast('请填写渠道名称', 'err'); return; }
      try {
        await api('/api/notify', { method: 'POST', body });
        closeModal();
        toast('已保存');
        await loadNotify();
      } catch (e) { toast(e.message, 'err'); }
    });
  }

  // ---------------- 凭证 ----------------
  async function loadCatalog() {
    try {
      state.catalog = await api('/api/catalog');
    } catch (e) { /* ignore */ }
  }

  async function loadProviders() {
    try {
      const r = await api('/api/providers');
      state.catalog = state.catalog || { providers: r.catalog };
      state.saved = r.saved || [];
      $('#cred-path').textContent = r.output_dir ? r.output_dir.replace(/\/output$/, '') + '/secret.key 与 state.json' : '/data';
      renderCreds();
    } catch (e) { toast(e.message, 'err'); }
  }

  function renderCreds() {
    const box = $('#cred-list');
    box.innerHTML = '';
    if (!state.saved.length) {
      box.innerHTML = '<div class="empty"><p>还没有保存的凭证</p><p class="tiny muted">签发时填写的 DNS API 凭证可以选择加密保存到这里</p></div>';
      return;
    }
    for (const c of state.saved) {
      const row = document.createElement('div');
      row.className = 'row';
      const masked = Object.entries(c.masked || {}).map(([k, v]) => `${k}=${v}`).join('  ');
      row.innerHTML = `
        <div class="row-main">
          <div class="row-title">${esc(c.name)} <span class="chip">${esc(c.code)}</span></div>
          <div class="tiny muted mono mt3">${esc(masked || '（无法解密）')}</div>
        </div>
        <button class="btn small danger" data-del="${esc(c.name)}">删除</button>`;
      row.querySelector('[data-del]').addEventListener('click', async () => {
        if (!confirm(`确定删除凭证「${c.name}」？已签发的证书不受影响，但后续续期可能需要重新配置。`)) return;
        try {
          await api(`/api/providers/${encodeURIComponent(c.name)}`, { method: 'DELETE' });
          toast('已删除');
          await loadProviders();
        } catch (e) { toast(e.message, 'err'); }
      });
      box.appendChild(row);
    }
  }

  $('#add-cred-btn').addEventListener('click', () => {
    openModal('添加 DNS 凭证', `
      <div class="field">
        <label for="cred-name">凭证名称</label>
        <input id="cred-name" placeholder="例如 ali-prod" spellcheck="false">
      </div>
      <div class="field">
        <label for="cred-code">DNS 服务商</label>
        <select id="cred-code">${providerOptions('dns_ali')}</select>
      </div>
      <div id="cred-env">${envFieldsHTML('dns_ali')}</div>
      <p class="hint">保存后以 AES-256-GCM 加密写入数据卷，密钥文件为 /data/secret.key（0600）。</p>
    `, `<button class="btn ghost" id="cred-cancel">取消</button><button class="btn primary" id="cred-go">保存</button>`);
    $('#cred-code').addEventListener('change', (e) => { $('#cred-env').innerHTML = envFieldsHTML(e.target.value); });
    $('#cred-cancel').addEventListener('click', closeModal);
    $('#cred-go').addEventListener('click', async () => {
      const name = $('#cred-name').value.trim();
      if (!name) { toast('请填写凭证名称', 'err'); return; }
      const env = {};
      $$('#cred-env [data-env]').forEach((i) => { env[i.dataset.env] = i.value; });
      try {
        await api('/api/providers', { method: 'POST', body: { name, code: $('#cred-code').value, env } });
        closeModal();
        toast('凭证已加密保存');
        await loadProviders();
      } catch (e) { toast(e.message, 'err'); }
    });
  });

  // ---------------- 设置 ----------------
  async function loadSysInfo() {
    try {
      const s = await api('/api/session');
      const c = state.catalog || {};
      const rows = [
        ['登录账号', s.user],
        ['acme.sh', s.acme_version || '未检测到'],
        ['证书目录', s.acme_home],
        ['默认 CA', s.default_ca],
        ['自动续期', s.cron ? '已开启（每 12 小时检查）' : '已关闭'],
        ['Cookie Secure', s.cookie_secure ? '已开启' : '未开启'],
        ['面板版本', c.version || '-'],
      ];
      $('#sys-info').innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}${k === 'Cookie Secure' ? '<div class="tiny muted">未开启表示登录 Cookie 不带 Secure 标记，仅适合 HTTP 本地访问；配置 HTTPS 反代后设为 1，Cookie 只在 HTTPS 下发送。</div>' : ''}</dd>`).join('');
    } catch (e) { /* ignore */ }
  }

  async function loadAudit() {
    try {
      const r = await api('/api/audit');
      const tb = $('#audit-table tbody');
      tb.innerHTML = (r.entries || []).map((e) => `
        <tr>
          <td class="muted">${esc(fmtTime(e.ts))}</td>
          <td>${esc(e.user || '-')}</td>
          <td class="muted">${esc(e.ip || '-')}</td>
          <td><span class="chip">${esc(e.action)}</span></td>
          <td class="wrap muted">${esc(e.detail || '')}</td>
        </tr>`).join('') || '<tr><td colspan="5" class="muted">暂无记录</td></tr>';
    } catch (e) { /* ignore */ }
  }
  $('#audit-refresh').addEventListener('click', loadAudit);

  $('#pwd-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const oldp = $('#pwd-old').value;
    const n1 = $('#pwd-new').value;
    const n2 = $('#pwd-new2').value;
    if (n1 !== n2) { toast('两次输入的新密码不一致', 'err'); return; }
    if (n1.length < 8) { toast('新密码至少 8 位', 'err'); return; }
    try {
      const r = await api('/api/password', { method: 'POST', body: { old: oldp, new: n1 } });
      $('#pwd-old').value = ''; $('#pwd-new').value = ''; $('#pwd-new2').value = '';
      toast(`密码已更新${r.sessions_revoked ? `，已注销 ${r.sessions_revoked} 个其它会话` : ''}`);
      await loadAudit();
    } catch (ex) { toast(ex.message, 'err'); }
  });

  // 赞赏码点击放大
  $('.support-qr').addEventListener('click', (e) => {
    const img = e.target.closest('.qr-zoom');
    if (!img) return;
    openModal(img.dataset.title || '收款码',
      `<div class="qr-large"><img src="${esc(img.dataset.src)}" alt="${esc(img.dataset.title || '收款码')}"></div>`);
  });

  $('#add-notifier').addEventListener('click', () => openNotifierModal());

  $('#save-default-email').addEventListener('click', async () => {
    const email = $('#default-email').value.trim();
    try {
      await api('/api/notify/default-email', { method: 'POST', body: { email } });
      state.defaultEmail = email;
      toast('默认邮箱已保存');
      await loadNotify();
    } catch (e) { toast(e.message, 'err'); }
  });

  // ---------------- 证书同步 ----------------
  let syncCatalog = null;
  let syncRules = [];
  let syncEvents = [];

  async function loadSync() {
    try {
      const [cat, r] = await Promise.all([
        api('/api/sync/catalog'), api('/api/sync/rules')]);
      syncCatalog = cat;
      syncRules = r.rules || [];
      syncEvents = r.events || [];
      const dirs = cat.dirs || (cat.dir ? [cat.dir] : []);
      $('#sync-dir-info').textContent = cat.enabled
        ? `挂载目录（${dirs.length} 个）：${dirs.join('  ·  ')} · 签发/续期成功后自动覆盖匹配文件`
        : '未配置挂载目录。请设置环境变量 ACME_PANEL_SYNC_DIR 并重启面板后使用。';
      $('#sync-dir-warn').classList.toggle('hidden', cat.enabled);
      $('#sync-dir-warn').textContent = cat.enabled ? '' : '同步功能当前不可用（需重启并配置 ACME_PANEL_SYNC_DIR）。';
      renderSyncFiles(cat.files || []);
      const presets = $('#sync-presets');
      presets.innerHTML = (cat.presets || []).map((p, i) =>
        `<button class="chip" data-preset="${i}" title="${esc(p.mode)}" type="button">＋ ${esc(p.name)}</button>`).join('');
      renderSyncRules();
      renderSyncEvents();
    } catch (e) { toast(e.message, 'err'); }
  }

  const syncModeLabel = (code) => (syncCatalog?.modes || []).find((m) => m.code === code)?.name || code;
  const syncModeHint = (code) => (syncCatalog?.modes || []).find((m) => m.code === code)?.hint || '';

  function renderSyncFiles(files) {
    const box = $('#sync-file-list');
    if (!files.length) {
      box.innerHTML = '<div class="empty"><p>目录里还没有证书文件</p><p class="tiny muted">把证书和私钥放进挂载目录后，这里会列出它们</p></div>';
      return;
    }
    box.innerHTML = files.map((f) => {
      const cert = f.has_cert
        ? `<span class="chip green">证书${f.cn ? ' · CN=' + esc(f.cn) : ''}</span>`
        : '<span class="chip yellow">未识别为证书</span>';
      const kindLabel = { key: '私钥', chain: '证书链', cert: '证书' }[f.kind] || f.kind;
      return `<div class="row">
        <span class="grow minw0 tiny">${esc(f.name)} <span class="muted">(${fmtSize(f.size)})</span></span>
        <span class="chip">${esc(kindLabel)}</span>
        <span class="tiny muted">域名 ${esc(f.domain || '—')}</span>
      </div>`;
    }).join('');
  }

  function fmtSize(n) {
    if (!n && n !== 0) return '—';
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(1) + ' MB';
  }

  function renderSyncRules() {
    const box = $('#sync-rule-list');
    if (!syncRules.length) {
      box.innerHTML = '<div class="empty"><p>还没有同步规则</p><p class="tiny muted">点击上方预设快速创建，或点「新建规则」自定义匹配方式</p></div>';
      return;
    }
    box.innerHTML = syncRules.map((r) => {
      const status = r.enabled ? '<span class="chip green">已启用</span>' : '<span class="chip">已停用</span>';
      const last = r.last_sync ? `<span class="tiny muted">上次同步 ${esc(r.last_sync)}${r.last_info ? ' · ' + esc(r.last_info) : ''}</span>` : '';
      return `<div class="row notifier-row">
        <div class="grow minw0">
          <div class="row"><strong>${esc(r.name)}</strong>${status}</div>
          <div class="tiny muted" title="${esc(syncModeHint(r.mode))}">匹配：${esc(syncModeLabel(r.mode))}${r.pattern ? ` · ${esc(r.pattern)}` : ''} · 来源：${esc(r.source || '*')}</div>
          <div class="tiny muted">写入：按文件名自动判断（key→私钥，cert→证书，chain→证书链）</div>
          ${last}
        </div>
        <button class="btn small" data-sync-edit="${esc(r.id)}" type="button">编辑</button>
        <button class="btn small danger" data-sync-del="${esc(r.id)}" type="button">删除</button>
      </div>`;
    }).join('');
  }

  function renderSyncEvents() {
    const box = $('#sync-event-list');
    if (!syncEvents.length) {
      box.innerHTML = '<div class="empty"><p>暂无同步记录</p></div>';
      return;
    }
    const cls = { ok: 'green', fail: 'red', skip: 'yellow' };
    box.innerHTML = syncEvents.map((e) => `<div class="row">
      <span class="chip ${cls[e.result] || ''}">${esc(e.result)}</span>
      <span class="tiny muted">${esc(e.time)}</span>
      <span class="grow minw0 tiny">${esc(e.rule)} · ${esc(e.source)} → ${esc(e.target)} · ${esc(e.detail)}</span>
    </div>`).join('');
  }

  function openSyncModal(rule, preset) {
    const r = rule || {};
    const p = preset || {};
    const modes = (syncCatalog?.modes || []).map((m) =>
      `<option value="${esc(m.code)}" ${m.code === (r.mode || p.mode) ? 'selected' : ''}>${esc(m.name)}</option>`).join('');
    const sources = ['*', ...state.certs.map((c) => c.name)];
    const srcOpts = sources.map((s) =>
      `<option value="${esc(s)}" ${s === (r.source || '*') ? 'selected' : ''}>${esc(s)}</option>`).join('');
    const body = `
      <div class="field"><label>规则名称（自己起个好记的）</label><input id="sy-name" value="${esc(r.name || p.name || '')}"></div>
      <div class="field"><label>怎么找到要覆盖的文件</label><select id="sy-mode">${modes}</select><p class="hint" id="sy-mode-hint"></p></div>
      <div class="field"><label>文件名匹配写法（仅「按文件名通配匹配」需要填）</label><input id="sy-pattern" value="${esc(r.pattern || p.pattern || '')}" placeholder="*_cert.pem"></div>
      <div class="field"><label>用哪张面板证书的内容写入</label><select id="sy-source">${srcOpts}</select><p class="hint">选 * 表示所有证书，会逐张尝试匹配。</p></div>
      <p class="hint">匹配到文件后自动按文件名判断写入内容：名字含 key 写新私钥，含 cert/fullchain 写新证书，含 chain/ca 写新证书链。无需配置目标文件名。</p>
      <label class="row"><input id="sy-enabled" type="checkbox" ${r.enabled !== false ? 'checked' : ''}> 启用此规则</label>
      <div class="mt8"><button class="btn small" id="sy-preview" type="button">🔍 预览匹配</button></div>
      <div id="sy-preview-result" class="mt8"></div>`;
    const foot = `<button class="btn ghost" id="sy-cancel" type="button">取消</button><button class="btn primary" id="sy-save" type="button">保存</button>`;
    const box = openModal(rule ? '编辑同步规则' : '新建同步规则', body, foot);
    const syncHint = () => { $('#sy-mode-hint').textContent = syncModeHint($('#sy-mode').value); };
    $('#sy-mode').addEventListener('change', syncHint);
    syncHint();
    const readPayload = () => ({
      id: r.id || '', name: $('#sy-name').value.trim(), enabled: $('#sy-enabled').checked,
      mode: $('#sy-mode').value, pattern: $('#sy-pattern').value.trim(),
      source: $('#sy-source').value, cert_tmpl: '', key_tmpl: '',
    });
    $('#sy-preview').addEventListener('click', async () => {
      const out = $('#sy-preview-result');
      out.textContent = '正在计算…';
      try {
        const res = await api('/api/sync/preview', { method: 'POST', body: readPayload() });
        const items = res.matched || [];
        if (!items.length) {
          out.innerHTML = '<p class="hint">没有匹配到任何文件。换个匹配方式，或检查目录里是否有对应证书。</p>';
          return;
        }
        out.innerHTML = `<p class="tiny">会覆盖 <strong>${items.length}</strong> 个文件：</p>` +
          items.map((m) => `<div class="row tiny"><span class="grow minw0">${esc(m.dir)} · ${esc(m.file)} <span class="muted">← ${esc(m.source)}</span></span><span class="chip">写入${esc(m.content)}</span></div>`).join('');
      } catch (e) { out.innerHTML = `<p class="form-error">${esc(e.message)}</p>`; }
    });
    $('#sy-cancel').addEventListener('click', closeModal);
    $('#sy-save').addEventListener('click', async () => {
      try {
        await api('/api/sync/rules', { method: 'POST', body: readPayload() });
        closeModal();
        toast('同步规则已保存');
        await loadSync();
      } catch (e) { toast(e.message, 'err'); }
    });
    return box;
  }

  $('#sync-add').addEventListener('click', () => openSyncModal());
  $('#sync-presets').addEventListener('click', (e) => {
    const b = e.target.closest('[data-preset]');
    if (!b) return;
    const p = syncCatalog.presets[Number(b.dataset.preset)];
    if (p) openSyncModal(null, p);
  });
  $('#sync-rule-list').addEventListener('click', async (e) => {
    const edit = e.target.closest('[data-sync-edit]');
    const del = e.target.closest('[data-sync-del]');
    if (edit) {
      const r = syncRules.find((x) => x.id === edit.dataset.syncEdit);
      if (r) openSyncModal(r);
    } else if (del) {
      try {
        await api('/api/sync/rules/' + encodeURIComponent(del.dataset.syncDel), { method: 'DELETE' });
        toast('规则已删除');
        await loadSync();
      } catch (ex) { toast(ex.message, 'err'); }
    }
  });
  $('#sync-run').addEventListener('click', async () => {
    try {
      const r = await api('/api/sync/run', { method: 'POST', body: {} });
      const ok = (r.events || []).filter((x) => x.result === 'ok').length;
      toast(`同步完成：${ok} 个文件已更新`);
      await loadSync();
    } catch (e) { toast(e.message, 'err'); }
  });

  // 未登录时按 Enter 直接提交
  $('#login-pass').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') $('#login-form').requestSubmit();
  });

  boot();
})();
