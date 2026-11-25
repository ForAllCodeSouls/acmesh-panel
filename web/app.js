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
    modalReturnFocus: null,
    drawerReturnFocus: null,
    combinedKeyTimer: null,
    auditPage: 0,
    auditTotal: 0,
    auditTimer: null,
    syncPage: 0,
    syncTotal: 0,
    syncTimer: null,
    auditSeq: 0,
    syncSeq: 0,
    keyViewTimer: null,
  };

  const AUDIT_PAGE_SIZE = 50;

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));

  // 一次性按钮：提交期间禁用并改文案，防止双击重复创建任务（吊销/移除不可逆）。
  // 调用方在成功分支会 closeModal，届时按钮随弹窗销毁；失败分支恢复可点。
  function busyButton(btn, text) {
    if (!btn || btn.disabled) return false;
    const old = btn.textContent;
    btn.disabled = true;
    btn.textContent = text || '处理中…';
    return () => { btn.disabled = false; btn.textContent = old; };
  }

  // ---------------- API ----------------
  async function api(path, opts = {}) {
    const { method = 'GET', body, raw = false } = opts;
    const headers = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (state.csrf) headers['X-CSRF-Token'] = state.csrf;
    let res;
    const ctrl = new AbortController();
    const timeout = setTimeout(() => ctrl.abort(), 30000);
    try {
      res = await fetch(path, {
        method,
        headers,
        credentials: 'same-origin',
        cache: 'no-store',
        signal: ctrl.signal,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (e) {
      throw new Error('网络请求失败或超时');
    } finally {
      clearTimeout(timeout);
    }
    if (res.status === 401) {
      // 401 有多种原因，先读出后端真实 error，再决定怎么呈现。
      let reason = '';
      try { const j = await res.json(); reason = (j && j.error) || ''; } catch (_) { /* ignore */ }
      // 首屏探测「未登录」或会话失效：静默回登录页，不显示吓人的红字。
      // 真正的登录失败（密码错误等）由调用方在表单里显示后端返回的具体原因。
      if (path === '/api/login') {
        throw new Error(reason || '登录失败');
      }
      showLogin('');
      throw new Error('未登录');
    }
    if (!res.ok) {
      let msg = res.statusText;
      try { const j = await res.json(); if (j && j.error) msg = j.error; } catch (_) { /* ignore */ }
      if (res.status === 429) {
        const ra = res.headers.get('Retry-After');
        if (ra) msg = `${msg}（${ra}s）`;
        const err = new Error(msg || '请求失败');
        err.retryAfter = parseInt(ra, 10) || 0;
        throw err;
      }
      throw new Error(msg || '请求失败');
    }
    if (raw) return res;
    const text = await res.text();
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch (_) {
      return text;
    }
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
    state.modalReturnFocus = document.activeElement;
    $('#modal-title').textContent = title;
    $('#modal-body').innerHTML = bodyHTML;
    $('#modal-foot').innerHTML = footHTML || '';
    $('#modal').classList.remove('hidden');
    const first = $('#modal-body').querySelector('input:not([type=checkbox]):not([type=hidden]), textarea, select');
    if (first) setTimeout(() => first.focus(), 30);
    return $('#modal-body');
  }
  function closeModal() {
    if ($('#modal').classList.contains('hidden')) return;
    if (state.keyViewTimer) { clearTimeout(state.keyViewTimer); state.keyViewTimer = null; }
    if (typeof state.closeJobLog === 'function') state.closeJobLog();
    $('#modal').classList.add('hidden');
    $('#modal-body').innerHTML = '';
    $('#modal-foot').innerHTML = '';
    if (state.modalReturnFocus && state.modalReturnFocus.isConnected) {
      state.modalReturnFocus.focus();
    }
    state.modalReturnFocus = null;
  }
  function openDrawer(title, sub) {
    state.drawerReturnFocus = document.activeElement;
    $('#drawer-title').textContent = title;
    $('#drawer-sub').textContent = sub || '';
    $('#drawer').classList.remove('hidden');
    $('#overlay').classList.remove('hidden');
    setTimeout(() => $('#drawer-close').focus(), 30);
  }
  function closeDrawer() {
    if ($('#drawer').classList.contains('hidden')) return;
    if (state.combinedKeyTimer) { clearTimeout(state.combinedKeyTimer); state.combinedKeyTimer = null; }
    $('#drawer').classList.add('hidden');
    $('#overlay').classList.add('hidden');
    $('#drawer-body').innerHTML = '';
    if (state.drawerReturnFocus && state.drawerReturnFocus.isConnected) {
      state.drawerReturnFocus.focus();
    }
    state.drawerReturnFocus = null;
  }

  $('#modal-close').addEventListener('click', closeModal);
  // 点击遮罩可关闭弹窗与抽屉，避免请求卡在 loading 时无法退出
  $('#modal').addEventListener('click', (e) => { if (e.target.id === 'modal') closeModal(); });
  $('#drawer-close').addEventListener('click', closeDrawer);
  $('#overlay').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    // 只关最上层：从抽屉里打开子弹窗时，按一次 Escape 先回到抽屉
    if (!$('#modal').classList.contains('hidden')) closeModal();
    else if (!$('#drawer').classList.contains('hidden')) closeDrawer();
  });
  // Tab 焦点陷阱：键盘用户不会跑到被弹窗遮住的背景上
  const trapTab = (sel) => {
    $(sel).addEventListener('keydown', (e) => {
      if (e.key !== 'Tab') return;
      const items = $$('button:not([disabled]), input:not([disabled]), select, textarea, a[href]', $(sel));
      if (!items.length) return;
      const first = items[0], last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
  };
  trapTab('#modal');
  trapTab('#drawer');

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
    if (btn.disabled) return; // 表单天然支持 Enter，避免隐式提交与重复点击双发
    const err = $('#login-error');
    err.textContent = '';
    btn.disabled = true;
    let countdown = false; // 429 倒计时接管按钮状态后，finally 不再立即恢复
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
      // 429 限流：按 Retry-After 倒计时禁用登录按钮，避免持续撞锁定窗口。
      const wait = ex.retryAfter || 0;
      if (wait > 0) {
        countdown = true;
        let left = Math.min(wait, 3600);
        const tick = () => {
          btn.disabled = true;
          btn.textContent = `请等待 ${left}s`;
          if (left <= 0) { btn.disabled = false; btn.textContent = '登录'; return; }
          left--;
          setTimeout(tick, 1000);
        };
        tick();
        return; // 倒计时接管了按钮状态，跳过 finally 的立即恢复
      }
    } finally {
      if (!countdown) btn.disabled = false;
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
    certs: ['证书', 'acme.sh 证书总览：查看、复制、续期与部署'],
    jobs: ['任务', '签发 / 续期 / 部署的执行记录与实时日志'],
    notify: ['通知', '默认邮箱、域名专属邮箱与 Webhook 同步'],
    creds: ['DNS 凭证', 'AES-256-GCM 加密存储，接口只返回掩码'],
    sync: ['证书同步', '本地覆盖 / 远程同步 / 合并后的同步记录'],
    settings: ['设置', '账号安全、系统运行、审计、备份恢复与支持'],
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
    // 签发只在证书页有意义；其它页隐藏，避免误点后跳回证书页
    $('#issue-btn').classList.toggle('hidden', v !== 'certs');
    window.scrollTo({ top: 0, behavior: 'auto' });
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

  // 页内分区：把长页面拆成少量明确分区，避免反复上下滚动。
  // 补齐 tab/tabpanel 语义，屏幕阅读器能读出当前分区，键盘可用左右方向键切换。
  function bindSubTabs(tabsSel, viewSel) {
    const tabs = $$(tabsSel + ' [data-subtab]');
    const panels = $$(viewSel + ' [data-subpanel]');
    const viewId = viewSel.replace('#', '');
    tabs.forEach((b) => {
      const panelId = `panel-${viewId}-${b.dataset.subtab}`;
      b.setAttribute('role', 'tab');
      b.setAttribute('aria-controls', panelId);
      const panel = panels.find((p) => p.dataset.subpanel === b.dataset.subtab);
      if (panel) {
        panel.id = panelId;
        panel.setAttribute('role', 'tabpanel');
      }
    });
    const activate = (btn) => {
      const key = btn.dataset.subtab;
      tabs.forEach((b) => {
        const on = b === btn;
        b.classList.toggle('active', on);
        b.setAttribute('aria-selected', on ? 'true' : 'false');
        b.tabIndex = on ? 0 : -1;
      });
      panels.forEach((p) => p.classList.toggle('hidden', p.dataset.subpanel !== key));
      window.scrollTo({ top: 0, behavior: 'auto' });
    };
    const current = tabs.find((b) => b.classList.contains('active')) || tabs[0];
    if (current) activate(current);
    $(tabsSel).addEventListener('click', (e) => {
      const btn = e.target.closest('[data-subtab]');
      if (btn) activate(btn);
    });
    $(tabsSel).addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
      const i = tabs.indexOf(document.activeElement);
      if (i < 0) return;
      e.preventDefault();
      const next = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
      activate(next);
      next.focus();
    });
  }
  bindSubTabs('#sync-tabs', '#view-sync');
  bindSubTabs('#settings-tabs', '#view-settings');

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
          <button class="btn small" data-act="copy">证书/私钥</button>
          <button class="btn small" data-act="renew">续期</button>
          <button class="btn small ghost" data-act="detail">详情</button>
        </div>`;
      box.appendChild(card);
    }
  }

  $('#cert-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-act]');
    const card = e.target.closest('[data-name]');
    if (!btn && !card) return;
    const name = (btn || card).closest('[data-name]').dataset.name;
    const cert = state.certs.find((c) => c.name === name);
    if (!cert) return;
    const act = btn ? btn.dataset.act : 'detail';
    if (act === 'copy') confirmKeyView(cert, showCombinedView);
    else if (act === 'detail') openCertDrawer(cert);
    else if (act === 'renew') doRenew(cert);
  });

  $('#cert-filter').addEventListener('input', (e) => {
    state.filter = e.target.value;
    renderCerts();
  });
  $('#refresh-btn').addEventListener('click', async () => {
    const btn = $('#refresh-btn');
    btn.disabled = true;
    const old = btn.textContent;
    btn.textContent = '刷新中…';
    try {
      await loadAll();
      if (state.view === 'notify') await loadNotify();
      else if (state.view === 'sync') await loadSync();
      else if (state.view === 'settings') { await loadSysInfo(); await loadAudit(); }
      toast('已刷新');
    }
    finally { btn.disabled = false; btn.textContent = old; }
  });

  // ---------------- 证书详情抽屉 ----------------
  async function openCertDrawer(cert, focus) {
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
    let pemSeq = 0; // 请求序号：快速切换 tab 时丢弃旧请求的迟到响应
    async function loadPem(kind) {
      const seq = ++pemSeq;
      activeKind = kind;
      pemView.value = '加载中…';
      try {
        const text = await api(`/api/certs/${encodeURIComponent(cert.name)}/pem/${kind}`);
        if (seq !== pemSeq || !pemView.isConnected) return;
        pemView.value = text;
      } catch (e) {
        if (seq !== pemSeq || !pemView.isConnected) return;
        pemView.value = '加载失败: ' + e.message;
      }
      $$('#pem-tabs .tab').forEach((t) => t.classList.toggle('active', t.dataset.kind === kind));
    }
    const first = ['fullchain', 'cert', 'chain'].find((k) => files[k]);
    // 卡片上的「证书」按钮直接显示叶证书（cert.pem），「详情」才默认完整链
    const initial = focus === 'cert' && files.cert ? 'cert' : first;
    if (initial) loadPem(initial); else pemView.value = '无可读的证书文件';
    if (focus === 'cert') {
      const chainTitle = [...body.querySelectorAll('.section-title')].find((n) => n.textContent === '证书链');
      chainTitle?.scrollIntoView({ block: 'start' });
    }

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

    $('#drawer-key').addEventListener('click', () => confirmKeyView(cert));
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
    if (!t || String(t).startsWith('0001')) return '-';
    const d = new Date(t);
    if (isNaN(d.getTime())) return '-';
    return d.toLocaleString('zh-CN', { hour12: false });
  }

  // ---------------- 私钥查看（二次确认） ----------------
  function confirmKeyView(cert, onSuccess) {
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
        // 先关闭确认弹窗，再打开结果，避免 z-index 更高的弹窗遮住抽屉
        closeModal();
        if (typeof onSuccess === 'function') onSuccess(cert, r.pem);
        else showKeyResult(cert, r.pem);
      } catch (e) {
        closeModal();
        toast(e.message, 'err');
      }
    });
  }

  // 证书与私钥同屏显示，方便左右同时复制；私钥仍需上面的二次确认才会到这里
  function showCombinedView(cert, keyPem) {
    closeModal();
    openDrawer(cert.domain + ' · 证书与私钥', cert.name);
    const body = $('#drawer-body');
    const files = cert.files || {};
    const kind = files.cert ? 'cert' : (files.fullchain ? 'fullchain' : 'chain');
    body.innerHTML = `
      <div class="callout info">证书与私钥已同屏展开，可分别复制。私钥明文仅在本次会话中显示 60 秒，之后自动清除。</div>
      <div class="combine-grid">
        <div>
          <div class="section-title">证书${kind === 'cert' ? '（叶证书）' : kind === 'chain' ? '（中间链）' : '（完整链）'}</div>
          <textarea class="pem-box" id="comb-cert" readonly spellcheck="false">加载中…</textarea>
          <div class="pem-actions">
            <button class="btn small" id="comb-cert-copy" type="button">复制证书</button>
            <button class="btn small" id="comb-cert-dl" type="button">下载证书</button>
          </div>
        </div>
        <div>
          <div class="section-title">私钥</div>
          <textarea class="pem-box" id="comb-key" readonly spellcheck="false"></textarea>
          <div class="pem-actions">
            <button class="btn small" id="comb-key-copy" type="button">复制私钥</button>
            <button class="btn small" id="comb-key-dl" type="button">下载私钥</button>
          </div>
        </div>
      </div>`;
    $('#comb-key').value = keyPem;
    // 捕获当前抽屉的文本框：异步返回时若抽屉已关闭/换了证书，不能写进新打开的文本框。
    const combCertEl = $('#comb-cert');
    api(`/api/certs/${encodeURIComponent(cert.name)}/pem/${kind}`).then((v) => {
      if (combCertEl && combCertEl.isConnected) combCertEl.value = v;
    }).catch((e) => {
      if (combCertEl && combCertEl.isConnected) combCertEl.value = '加载失败: ' + e.message;
    });
    $('#comb-cert-copy').addEventListener('click', () => copyText($('#comb-cert').value, '证书已复制'));
    // 只从当前 DOM 取值：60 秒后文本框清空，复制/下载也必须同时失效。
    $('#comb-key-copy').addEventListener('click', () => {
      const v = $('#comb-key').value;
      if (v) copyText(v, '私钥已复制');
      else toast('私钥已自动清除，请重新验证查看', 'err');
    });
    $('#comb-cert-dl').addEventListener('click', () => downloadText(`${cert.name}-${kind}.pem`, $('#comb-cert').value));
    $('#comb-key-dl').addEventListener('click', () => {
      const v = $('#comb-key').value;
      if (v) downloadText(`${cert.domain}.key`, v);
      else toast('私钥已自动清除，请重新验证查看', 'err');
    });
    const keyBox = $('#comb-key');
    state.combinedKeyTimer = setTimeout(() => {
      if (keyBox) { keyBox.value = ''; keyBox.placeholder = '私钥已自动清除，请重新验证查看'; }
      $('#comb-key-copy').disabled = true;
      $('#comb-key-dl').disabled = true;
      state.combinedKeyTimer = null;
    }, 60000);
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
    $('#key-copy').addEventListener('click', () => {
      const v = ta.value;
      if (v) copyText(v, '私钥已复制到剪贴板');
      else toast('私钥已自动清除，请重新验证查看', 'err');
    });
    $('#key-dl').addEventListener('click', () => {
      const v = ta.value;
      if (v) downloadText(`${cert.domain}.key`, v);
      else toast('私钥已自动清除，请重新验证查看', 'err');
    });
    $('#key-close').addEventListener('click', closeModal);
    state.keyViewTimer = setTimeout(() => {
      if (ta) { ta.value = ''; ta.placeholder = '私钥已自动清除，请重新验证查看'; }
      $('#key-copy').disabled = true;
      $('#key-dl').disabled = true;
      state.keyViewTimer = null;
    }, 60000);
  }

  // ---------------- 签发 ----------------
  $('#issue-btn').addEventListener('click', () => openIssueModal());

  function providerOptions(selected) {
    // 按 acme.sh code 字母序展示；后端目录已排序，这里再兜一层底。
    return (state.catalog?.providers || []).slice()
      .sort((a, b) => String(a.code).localeCompare(String(b.code)))
      .map((p) =>
        `<option value="${esc(p.code)}"${p.code === selected ? ' selected' : ''}>${esc(p.name)} (${esc(p.code)})</option>`).join('');
  }

  function websiteHTML(code) {
    const def = (state.catalog?.providers || []).find((p) => p.code === code);
    if (!def?.website) return '';
    // 官网地址来自后端固定目录，仍限制为 https 并转义，杜绝脚本协议注入。
    if (!/^https:\/\//i.test(def.website)) return '';
    return `<div class="field provider-site"><a href="${esc(def.website)}" target="_blank" rel="noopener noreferrer">打开 ${esc(def.name)} 官网获取凭证 ↗</a></div>`;
  }

  function envFieldsHTML(code) {
    const def = (state.catalog?.providers || []).find((p) => p.code === code);
    if (!def) return '';
    return websiteHTML(code) + def.fields.map((f) => `
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
        <p class="hint" id="iss-email-hint">${state.defaultEmail ? '默认：' + esc(state.defaultEmail) + ' · CA 的到期提醒会发到这里' : '未设置默认邮箱：将使用 acme.sh 安装时配置的账户'}</p>
      </div>
      <div class="field">
        <label for="iss-dnssleep">DNS 生效等待（秒）</label>
        <input id="iss-dnssleep" type="number" min="0" max="600" value="30">
        <p class="hint">默认 30 秒：跳过 acme.sh 的公共 DNS 轮询，避免动态 DNS（如 DuckDNS）一直卡在「Not valid yet」检查。填 0 则沿用 acme.sh 默认行为。</p>
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
        dns_sleep: parseInt($('#iss-dnssleep').value, 10) || 0,
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
      const restore = busyButton($('#iss-go'), '提交中…');
      if (!restore) return;
      try {
        const r = await api('/api/issue', { method: 'POST', body });
        closeModal();
        toast('签发任务已创建');
        await loadJobs();
        switchView('jobs');
        openJobLog(r.job.id, r.job.title);
      } catch (e) {
        restore();
        toast(e.message, 'err');
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
      const restore = busyButton($('#rn-go'), '提交中…');
      if (!restore) return;
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
      } catch (e) { restore(); toast(e.message, 'err'); }
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
      const restore = busyButton($('#rv-go'), '吊销中…');
      if (!restore) return;
      try {
        const r = await api(`/api/certs/${encodeURIComponent(cert.name)}/revoke`, { method: 'POST', body: {} });
        closeModal(); closeDrawer();
        await loadJobs(); switchView('jobs'); openJobLog(r.job.id, r.job.title);
      } catch (e) { restore(); toast(e.message, 'err'); }
    });
  }

  async function doRemove(cert) {
    openModal('移除证书', `
      <div class="callout">将执行 acme.sh --remove，把 <b>${esc(cert.domain)}</b> 从续期列表移除。</div>
      <label class="check"><input type="checkbox" id="rm-purge"> 同时删除磁盘上的证书目录（含私钥，不可恢复）</label>
    `, `<button class="btn ghost" id="rm-cancel">取消</button><button class="btn danger" id="rm-go">确认移除</button>`);
    $('#rm-cancel').addEventListener('click', closeModal);
    $('#rm-go').addEventListener('click', async () => {
      const restore = busyButton($('#rm-go'), '移除中…');
      if (!restore) return;
      try {
        const r = await api(`/api/certs/${encodeURIComponent(cert.name)}/remove`, {
          method: 'POST', body: { purge: $('#rm-purge').checked },
        });
        closeModal(); closeDrawer();
        await loadJobs(); switchView('jobs'); openJobLog(r.job.id, r.job.title);
      } catch (e) { restore(); toast(e.message, 'err'); }
    });
  }

  $('#renew-all-btn').addEventListener('click', async () => {
    const restore = busyButton($('#renew-all-btn'), '提交中…');
    if (!restore) return;
    try {
      const r = await api('/api/renew-all', { method: 'POST', body: {} });
      toast('续期检查已开始');
      await loadJobs(); switchView('jobs'); openJobLog(r.job.id, r.job.title);
    } catch (e) { restore(); toast(e.message, 'err'); }
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

  async function retryJob(id, title) {
    try {
      const r = await api(`/api/jobs/${encodeURIComponent(id)}/retry`, { method: 'POST', body: {} });
      toast('重试任务已创建');
      state.closeJobLog?.();
      await loadJobs();
      if (r.job) openJobLog(r.job.id, r.job.title);
      else switchView('jobs');
    } catch (e) { toast(e.message, 'err'); }
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
      const retryable = ['failed', 'canceled', 'skipped'].includes(j.status);
      row.innerHTML = `
        <div class="row-main minw0">
          <div class="row-title">${esc(j.title)}</div>
          <div class="tiny muted mt2">${esc(fmtTime(j.created))} · ${esc(j.kind)}</div>
        </div>
        ${retryable ? '<button class="btn small job-retry-btn" type="button" title="用原参数重新执行">重试</button>' : ''}
        <span class="job-status ${esc(j.status)}">${esc(st)}</span>
        <span class="muted">›</span>`;
      const retryBtn = row.querySelector('.job-retry-btn');
      if (retryBtn) {
        retryBtn.addEventListener('click', (e) => { e.stopPropagation(); retryJob(j.id, j.title); });
      }
      row.addEventListener('click', () => openJobLog(j.id, j.title));
      box.appendChild(row);
    }
  }

  function openJobLog(id, title) {
    const cur = state.jobs.find((j) => j.id === id);
    const canRetryLog = cur && ['failed', 'canceled', 'skipped'].includes(cur.status);
    openModal(title || '任务日志', `<div class="log" id="job-log"></div>`, `
      <button class="btn ghost small hidden" id="job-cancel">取消任务</button>
      <button class="btn small hidden" id="job-retry">重试任务</button>
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
    // 服务端对每条新连接都会回放全部历史日志；EventSource 自动重连后会重复追加，
    // 因此在每次连接建立时清空，保证日志只显示一遍。
    es.onopen = () => { logEl.textContent = ''; };
    es.onmessage = (ev) => {
      const line = ev.data;
      let cls = '';
      if (line.startsWith('✗')) cls = 'l-err';
      else if (line.startsWith('ℹ')) cls = 'l-info';
      else if (line.startsWith('✓')) cls = 'l-ok';
      else if (line.startsWith('$')) cls = 'l-cmd';
      append(line, cls);
    };
    // 打开时任务已结束：回放的 done 事件只渲染终态，不再弹「执行成功」这类实时提示。
    const wasFinished = !!(cur && ['success', 'failed', 'canceled', 'skipped'].includes(cur.status));
    es.addEventListener('done', async (ev) => {
      append('—— 任务结束：' + ev.data + ' ——', ev.data === 'success' ? 'l-ok' : (ev.data === 'skipped' ? 'l-info' : 'l-err'));
      es.close();
      state.logES = null;
      if (!wasFinished) await Promise.all([loadJobs(), loadCerts()]);
      const stillOpen = !$('#modal').classList.contains('hidden');
      if (!stillOpen || wasFinished) return;
      if (ev.data === 'success') toast('任务执行成功');
      else if (ev.data === 'skipped') toast('证书未到续期时间');
      else toast('任务结束：' + ev.data, ev.data === 'canceled' ? 'warn' : 'err');
      $('#job-cancel')?.classList.add('hidden');
      if (ev.data === 'failed' || ev.data === 'canceled' || ev.data === 'skipped') {
        $('#job-retry')?.classList.remove('hidden');
      }
    });
    es.onerror = () => { /* 关闭或断线时浏览器会自动重连，这里不打扰用户 */ };
    // 统一关闭入口：✕ / 遮罩 / Escape / 关闭按钮都会走到这里，避免 SSE 泄漏
    state.closeJobLog = () => {
      if (state.logES) { state.logES.close(); state.logES = null; }
      state.closeJobLog = null;
    };
    $('#job-close').addEventListener('click', closeModal);
    $('#job-reload').addEventListener('click', async () => { await loadJobs(); closeModal(); switchView('jobs'); });
    const cancelBtn = $('#job-cancel');
    const job = state.jobs.find((j) => j.id === id);
    if (!job || job.status === 'running' || job.status === 'queued') {
      cancelBtn.classList.remove('hidden');
    }
    cancelBtn.addEventListener('click', async () => {
      try { await api(`/api/jobs/${encodeURIComponent(id)}/cancel`, { method: 'POST', body: {} }); toast('已请求取消'); }
      catch (e) { toast(e.message, 'err'); }
    });
    const retryBtn = $('#job-retry');
    if (canRetryLog) retryBtn.classList.remove('hidden');
    retryBtn.addEventListener('click', () => retryJob(id, title));
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
      box.innerHTML = '<div class="empty"><p>还没有通知渠道</p><p class="tiny muted">添加 Gotify 或通用 Webhook 后，签发 / 续期 / 失败 / 临期都能同步到手机</p></div>';
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
            toast('测试消息已同步');
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
        <input id="nt-name" value="${esc(existing?.name || '')}" placeholder="例如 Gotify 手机同步">
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
      const targetVal = $('#nt-target').value.trim();
      const secretVal = $('#nt-secret').value.trim();
      const body = {
        id: existing?.id || '',
        name: $('#nt-name').value.trim(),
        kind: kindSel.value,
        target: targetVal,
        secret: secretVal,
        events: $$('#nt-events [data-event]:checked').map((i) => i.dataset.event),
        enabled: $('#nt-enabled').checked,
        keep_target: !!existing && !targetVal,
        keep_secret: !!existing && !secretVal,
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
      $('#cred-path').textContent = r.output_dir ? r.output_dir.replace(/\/output$/, '') + '/secret.key 与 panel.db' : '/data';
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
  function credSourceLabel(src, kind) {
    if (src === 'web') return 'Web 设置页修改（持久生效，重启不回退）';
    if (src === 'generated') return kind === 'pass'
      ? '首次启动自动生成（随机，仅日志显示一次）'
      : '首次启动默认账号 admin';
    if (src === 'env') return kind === 'pass'
      ? '环境变量 ACME_PANEL_PASSWORD（仅首次初始化）'
      : '环境变量 ACME_PANEL_USER（仅首次初始化，默认 admin）';
    return '未知';
  }

  async function loadSysInfo() {
    try {
      const s = await api('/api/session');
      const c = state.catalog || {};
      const rows = [
        ['登录账号', s.user],
        ['账号来源', credSourceLabel(s.cred_source || s.username_source, 'user')],
        ['密码来源', credSourceLabel(s.cred_source || s.password_source, 'pass')],
        ['acme.sh', s.acme_version || '未检测到'],
        ['acme.sh 目录', (s.acme_home || '-') + '（容器内路径，数据卷 acme_home）'],
        ['数据存储', 'SQLite · panel.db'],
        ['默认 CA', s.default_ca],
        ['自动续期', s.cron ? `已开启（每天 ${String(s.cron_hour ?? 3).padStart(2, '0')}:00 检查一次）` : '已关闭'],
        ['服务模式', 'HTTP（HTTPS 由 nginx/Caddy 反代终结）'],
        ['面板版本', c.version || '-'],
      ];
      const hourSel = $('#cron-hour');
      if (hourSel && !hourSel.options.length) {
        for (let h = 0; h < 24; h++) {
          const o = document.createElement('option');
          o.value = String(h);
          o.textContent = String(h).padStart(2, '0') + ':00';
          hourSel.appendChild(o);
        }
      }
      if (hourSel) hourSel.value = String(s.cron_hour ?? 3);
      const rd = $('#retention-days');
      if (rd) rd.value = String(s.retention_days ?? 30);
      const fh = $('#force-https');
      if (fh) { fh.checked = !!s.force_https; fh.disabled = !!s.force_https_pinned; }
      const fhSave = $('#force-https-save');
      if (fhSave) fhSave.disabled = !!s.force_https_pinned;
      const fhHint = $('#force-https-hint');
      if (fhHint) {
        if (s.force_https_pinned) {
          fhHint.textContent = `已由环境变量 ACME_PANEL_FORCE_HTTPS=${s.force_https ? '1' : '0'} 锁定，界面不可修改；改 .env 后须 docker compose up -d 重建容器才生效（restart 不刷新 env）。`;
        } else if (s.force_https) {
          fhHint.textContent = s.https_now
            ? '当前生效中：HTTP 直连已被静默断连（同空端口），仅 HTTPS 反代可访问；健康检查 /api/health 不受限制。'
            : '当前生效中，但本次请求不是 HTTPS——反代需传递 X-Forwarded-Proto: https；若已无法访问，设 ACME_PANEL_FORCE_HTTPS=0 并 docker compose up -d 恢复。';
        } else {
          fhHint.textContent = '当前未开启。开启后，通过 IP / 端口的 HTTP 直连会被静默断连（等同访问空端口），只能经 HTTPS 反代访问；反代需传递 X-Forwarded-Proto: https。若 HTTPS 也打不开，设 ACME_PANEL_FORCE_HTTPS=0 并 docker compose up -d 即可临时关闭。';
        }
      }
      $('#cron-hour-hint').textContent = s.cron_last_day
        ? `今天（${s.cron_last_day}）已执行过自动检测；每天 ${String(s.cron_hour ?? 3).padStart(2, '0')}:00 检查一次，重启不会重复。`
        : `每天 ${String(s.cron_hour ?? 3).padStart(2, '0')}:00 自动检查续期与临期；同一天只执行一次，重启不会重复检测。`;
      $('#sys-info').innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}${k === '密码来源' ? '<div class="tiny muted">环境变量只在首次启动（数据库里还没有密码时）写入账号密码；之后以数据库为准，Web 上「修改账号 / 修改密码」会持久保存，重启不会被 env 覆盖。忘记密码可用 ACME_PANEL_RESET_CREDENTIALS=1 配合 env 显式重置一次。数据库只存 PBKDF2 哈希，不存明文。任何方式都无法防止主机本身被入侵。</div>' : ''}${k === '面板版本' ? '<span id="update-slot"></span>' : ''}${k === '数据存储' ? '<span id="storage-slot" class="tiny muted"></span>' : ''}</dd>`).join('');
      checkUpdate();
      checkStorage();
    } catch (e) { /* ignore */ }
  }

  // 版本检测：默认走后端缓存（后台按频次自动刷新），force=1 时立即请求 GitHub。
  // 同一份状态同时渲染设置页徽标、更新配置卡与顶部全局横幅。
  async function checkUpdate(force = false) {
    const slot = $('#update-slot');
    const status = $('#update-status');
    const btn = $('#update-check-now');
    if (btn) btn.disabled = true;
    if (slot && !force) { slot.className = 'tiny muted'; slot.textContent = ' · 检测中…'; }
    try {
      // 强制检测用 POST（有副作用且受 CSRF 保护），GET 只返回缓存状态。
      const forceCheck = () => api('/api/update/check', { method: 'POST', body: {} });
      let r = force ? await forceCheck() : await api('/api/update/check');
      // 从未检测过（首次启动）：缓存为空，自动补一次实时检测，避免误显示"已是最新"。
      if (!force && (!r.last_check || String(r.last_check).startsWith('0001'))) {
        r = await forceCheck();
      }
      renderUpdate(r);
      if (force) toast(r.ok ? (r.need_update ? '发现新版本 ' + (r.latest || '') : '已是最新版本') : (r.error || '检测失败'), r.ok ? '' : 'warn');
      return r;
    } catch (e) {
      if (slot) slot.textContent = ' · 检测失败';
      if (status) status.textContent = '检测失败';
      if (force) toast('检测失败，请稍后重试', 'warn');
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function renderUpdate(r) {
    const slot = $('#update-slot');
    const status = $('#update-status');
    const banner = $('#update-banner');
    const latest = r.latest || '';
    const url = r.url || 'https://github.com/ForAllCodeSouls/acmesh-panel';
    const need = !!r.need_update;

    if (slot) {
      slot.textContent = '';
      if (!r.ok) {
        slot.className = 'tiny muted';
        slot.textContent = ' · ' + (r.error || '检测失败');
      } else if (need) {
        const a = document.createElement('a');
        a.className = 'update-badge';
        a.href = url; a.target = '_blank'; a.rel = 'noopener noreferrer';
        a.textContent = '可更新 ' + latest + ' →';
        slot.appendChild(a);
      } else {
        slot.className = 'tiny muted';
        slot.textContent = ' · 已是最新';
      }
    }
    if (banner) {
      if (need) {
        banner.href = url;
        banner.textContent = '↑ 有新版本 ' + latest;
        banner.classList.remove('hidden');
      } else {
        banner.classList.add('hidden');
      }
    }
    if (status) {
      status.textContent = !r.ok ? (r.error || '检测失败')
        : need ? '发现新版本 ' + latest
        : '已是最新（' + fmtTime(r.last_check) + ' 检测）';
    }
    const auto = $('#update-auto');
    const interval = $('#update-interval');
    if (auto && r.auto_check !== undefined) auto.checked = !!r.auto_check;
    if (interval && r.interval) interval.value = r.interval;
  }

  async function checkStorage() {
    const slot = $('#storage-slot');
    if (!slot) return;
    try {
      const r = await api('/api/storage');
      slot.textContent = ` · ${r.path || 'panel.db'} · ${fmtSize(r.size)} · 任务 ${r.jobs} / 审计 ${r.audit} / 同步 ${r.sync_events} / 指纹 ${r.sync_seen} 条`;
    } catch (e) {
      slot.textContent = ' · 读取失败';
    }
  }

  function auditFilters() {
    return {
      q: $('#audit-q')?.value.trim() || '',
      action: $('#audit-action')?.value || '',
      user: $('#audit-user')?.value || '',
      from: $('#audit-from')?.value || '',
      to: $('#audit-to')?.value || '',
    };
  }

  function auditHasFilter() {
    const f = auditFilters();
    return !!(f.q || f.action || f.user || f.from || f.to);
  }

  async function loadAudit(resetPage = false) {
    if (resetPage) state.auditPage = 0;
    const seq = state.auditSeq = (state.auditSeq || 0) + 1;
    const f = auditFilters();
    const p = new URLSearchParams();
    Object.entries(f).forEach(([k, v]) => { if (v) p.set(k, v); });
    p.set('limit', String(AUDIT_PAGE_SIZE));
    p.set('offset', String(state.auditPage * AUDIT_PAGE_SIZE));
    try {
      const r = await api('/api/audit?' + p.toString());
      if (seq !== state.auditSeq) return; // 旧筛选条件的响应不得覆盖新结果
      state.auditTotal = r.total || 0;
      const tb = $('#audit-table tbody');
      tb.innerHTML = (r.entries || []).map((e) => `
        <tr>
          <td class="muted">${esc(fmtTime(e.ts))}</td>
          <td>${esc(e.user || '-')}</td>
          <td class="muted">${esc(e.ip || '-')}</td>
          <td><span class="chip">${esc(e.action)}</span></td>
          <td class="wrap muted">${esc(e.detail || '')}</td>
        </tr>`).join('') || `<tr><td colspan="5" class="muted">${auditHasFilter() ? '没有符合筛选条件的记录' : '暂无记录'}</td></tr>`;

      // 填充动作 / 用户下拉（保留当前选择）
      const fill = (sel, list, allLabel) => {
        const el = $(sel);
        if (!el) return;
        const cur = el.value;
        el.innerHTML = `<option value="">${allLabel}</option>` +
          (list || []).map((v) => `<option value="${esc(v)}">${esc(v)}</option>`).join('');
        el.value = cur;
      };
      fill('#audit-action', r.actions, '全部动作');
      fill('#audit-user', r.users, '全部用户');

      const shown = (r.entries || []).length;
      const from = state.auditTotal ? state.auditPage * AUDIT_PAGE_SIZE + 1 : 0;
      const to = state.auditPage * AUDIT_PAGE_SIZE + shown;
      const cnt = $('#audit-count');
      if (cnt) cnt.textContent = `共 ${state.auditTotal} 条` + (state.auditTotal ? `，显示 ${from}-${to}` : '');
      const pageEl = $('#audit-page');
      if (pageEl) pageEl.textContent = `第 ${state.auditPage + 1} 页 / 共 ${Math.max(1, Math.ceil(state.auditTotal / AUDIT_PAGE_SIZE))} 页`;
      const prev = $('#audit-prev'), next = $('#audit-next');
      if (prev) prev.disabled = state.auditPage <= 0;
      if (next) next.disabled = to >= state.auditTotal;
    } catch (e) { /* ignore */ }
  }

  function scheduleAuditSearch() {
    clearTimeout(state.auditTimer);
    state.auditTimer = setTimeout(() => loadAudit(true), 300);
  }

  $('#audit-refresh').addEventListener('click', () => loadAudit(true));
  $('#audit-q').addEventListener('input', scheduleAuditSearch);
  ['#audit-action', '#audit-user', '#audit-from', '#audit-to'].forEach((sel) => {
    $(sel)?.addEventListener('change', () => loadAudit(true));
  });
  $('#audit-reset').addEventListener('click', () => {
    ['#audit-q', '#audit-action', '#audit-user', '#audit-from', '#audit-to'].forEach((sel) => {
      const el = $(sel); if (el) el.value = '';
    });
    state.auditPage = 0;
    loadAudit(true);
  });
  $('#audit-prev').addEventListener('click', () => {
    if (state.auditPage > 0) { state.auditPage--; loadAudit(); }
  });
  $('#audit-next').addEventListener('click', () => {
    if ((state.auditPage + 1) * AUDIT_PAGE_SIZE < state.auditTotal) { state.auditPage++; loadAudit(); }
  });

  $('#user-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('#user-form button[type="submit"]');
    const pass = $('#user-pass').value;
    const name = $('#user-new').value.trim();
    if (!/^[A-Za-z][A-Za-z0-9_-]{2,31}$/.test(name)) { toast('账号需 3-32 位、字母开头，只能用字母/数字/下划线/短横线', 'err'); return; }
    btn.disabled = true;
    try {
      const r = await api('/api/username', { method: 'POST', body: { password: pass, username: name } });
      $('#user-pass').value = ''; $('#user-new').value = '';
      toast(`账号已改为 ${name}，请用新账号重新登录`);
      showLogin(`账号已改为 ${name}，请用新账号登录`);
    } catch (ex) { toast(ex.message, 'err'); }
    finally { btn.disabled = false; }
  });

  $('#pwd-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const oldp = $('#pwd-old').value;
    const n1 = $('#pwd-new').value;
    const n2 = $('#pwd-new2').value;
    if (n1 !== n2) { toast('两次输入的新密码不一致', 'err'); return; }
    if (n1.length < 12 || !/[A-Z]/.test(n1) || !/[a-z]/.test(n1) || !/[0-9]/.test(n1)) {
      toast('新密码至少 12 位，且须同时包含大写、小写和数字', 'err'); return;
    }
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

  $('#cron-hour-save').addEventListener('click', async () => {
    try {
      await api('/api/cron/schedule', { method: 'POST', body: { hour: Number($('#cron-hour').value) } });
      toast('每日检测时间已保存');
      await loadSysInfo();
    } catch (e) { toast(e.message, 'err'); }
  });

  $('#retention-save').addEventListener('click', async () => {
    const days = Number($('#retention-days').value);
    if (!Number.isInteger(days) || days < 0 || days > 3650) { toast('保留天数需为 0-3650 的整数', 'err'); return; }
    try {
      await api('/api/retention', { method: 'POST', body: { days } });
      toast(days === 0 ? '已设为永不清理' : `保留天数已设为 ${days} 天`);
      await loadSysInfo();
    } catch (e) { toast(e.message, 'err'); }
  });

  $('#force-https-save').addEventListener('click', async () => {
    const box = $('#force-https');
    if (!box || box.disabled) return;
    const on = box.checked;
    if (on && !confirm('开启后，直接通过 IP / 端口访问面板（包括当前页面）会立即被拒绝，只能通过 HTTPS 反代地址访问。请确认反代已传递 X-Forwarded-Proto: https。确定开启？')) {
      box.checked = false;
      return;
    }
    const done = busyButton($('#force-https-save'), '保存中…');
    try {
      const r = await api('/api/https/settings', { method: 'POST', body: { force_https: on } });
      toast(on ? '已开启：仅允许 HTTPS 访问' : '已关闭：HTTP 与 HTTPS 均可访问');
      await loadSysInfo();
      if (on && r && r.https_now === false) toast('本次请求不是 HTTPS，反代可能未传递 X-Forwarded-Proto', 'err');
    } catch (e) {
      box.checked = !on;
      toast(e.message, 'err');
    } finally { done(); }
  });

  $('#update-save').addEventListener('click', async () => {
    const auto = $('#update-auto').checked;
    const interval = $('#update-interval').value;
    try {
      const r = await api('/api/update/settings', { method: 'POST', body: { auto_check: auto, interval } });
      renderUpdate(r);
      toast('更新检测设置已保存');
    } catch (e) { toast(e.message, 'err'); }
  });

  $('#update-check-now').addEventListener('click', () => checkUpdate(true));

  $('#cleanup-now').addEventListener('click', async () => {
    if (!confirm('立即清理会按当前保留天数永久删除旧任务、审计与同步记录，不可撤销。确定继续？')) return;
    const btn = $('#cleanup-now');
    btn.disabled = true;
    try {
      const r = await api('/api/cleanup', { method: 'POST', body: {} });
      const parts = Object.entries(r.removed || {}).filter(([, n]) => n > 0)
        .map(([k, n]) => `${k} ${n} 条`);
      toast(parts.length ? `已清理：${parts.join('、')}` : '没有需要清理的旧数据');
    } catch (e) { toast(e.message, 'err'); }
    finally { btn.disabled = false; }
  });

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
  let syncSeenCount = 0;
  let remoteHosts = [];
  const SYNC_PAGE_SIZE = 50;

  async function loadSync() {
    try {
      const [cat, r, rh] = await Promise.all([
        api('/api/sync/catalog'), api('/api/sync/rules'), api('/api/remote/hosts')]);
      syncCatalog = cat;
      syncRules = r.rules || [];
      syncSeenCount = r.seen_count || 0;
      remoteHosts = rh.hosts || [];
      const dirs = cat.dirs || (cat.dir ? [cat.dir] : []);
      $('#sync-dir-info').textContent = cat.enabled
        ? `挂载目录（${dirs.length} 个）：${dirs.join('  ·  ')} · 签发/续期成功后自动覆盖匹配文件`
        : '未配置挂载目录。请设置环境变量 ACME_PANEL_SYNC_DIR 并重启面板后使用。';
      $('#sync-dir-warn').classList.toggle('hidden', cat.enabled);
      $('#sync-dir-warn').textContent = cat.enabled ? '' : '同步功能当前不可用（需重启并配置 ACME_PANEL_SYNC_DIR）。';
      $('#sync-dedupe-info').textContent = syncSeenCount
        ? `已记录 ${syncSeenCount} 个目标文件的证书指纹：证书未续签时自动跳过，不重复覆盖。需要重写全部文件时勾选「强制同步」。`
        : '默认只在证书续签或文件首次匹配时同步一次；内容未变化的文件会自动跳过，不重复覆盖。需要重写全部文件时，勾选「强制同步」再点「立即同步」。';
      const remoteSeen = Number(r.remote_seen_count || 0);
      $('#remote-sync-info').textContent = remoteSeen
        ? `已记录 ${remoteSeen} 个文件的远程同步摘要：只同步内容与面板已签名证书对得上的文件，内容未变化时按主机分别跳过；需要全部重同步时勾选「强制同步」。`
        : '远程同步按「证书内容」对比：只有目标机器上确实是面板签发证书的文件才会覆盖，与规则、文件名无关。';
      renderSyncFiles(cat.files || []);
      renderRemoteFileHosts();
      const presets = $('#sync-presets');
      presets.innerHTML = (cat.presets || []).map((p, i) =>
        `<button class="chip" data-preset="${i}" title="${esc(p.mode)}" type="button">＋ ${esc(p.name)}</button>`).join('');
      renderSyncRules();
      await loadSyncEvents();
      renderRemoteHosts();
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
    const KIND = {
      key:   { label: '🔑 私钥',   cls: 'red' },
      cert:  { label: '📜 证书',   cls: 'green' },
      chain: { label: '⛓ 证书链', cls: 'blue' },
    };
    box.innerHTML = files.map((f) => {
      const k = KIND[f.kind] || { label: f.kind, cls: '' };
      return `<div class="row">
        <span class="grow minw0 tiny">${esc(f.name)} <span class="muted">(${fmtSize(f.size)})</span></span>
        <span class="chip ${k.cls}">${k.label}</span>
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
      const targets = (r.remote_hosts || []).map((id) => (remoteHosts.find((h) => h.id === id) || {}).name || id);
      // 生效范围标签：本地始终生效；远程按规则选中的主机逐个标注
      const scopeChips = ['<span class="chip" title="规则始终写入本地挂载目录' + (targets.length ? '' : '；未选远程主机，不做远程同步') + '">本地</span>']
        .concat(targets.map((n) => `<span class="chip blue" title="命中文件同步到该主机的远程证书目录">${esc(n)}</span>`));
      return `<div class="row notifier-row">
        <div class="grow minw0">
          <div class="row"><strong>${esc(r.name)}</strong>${status}<span class="chip-wrap mt4">${scopeChips.join('')}</span></div>
          <div class="tiny muted" title="${esc(syncModeHint(r.mode))}">匹配：${esc(syncModeLabel(r.mode))}${r.pattern ? ` · ${esc(r.pattern)}` : ''} · 来源：${esc(r.source || '*')}</div>
          <div class="tiny muted">写入：按文件名自动判断（key→私钥，cert→证书，chain→证书链）</div>
          ${last}
        </div>
        <button class="btn small" data-sync-edit="${esc(r.id)}" type="button">编辑</button>
        <button class="btn small danger" data-sync-del="${esc(r.id)}" type="button">删除</button>
      </div>`;
    }).join('');
  }

  function syncFilters() {
    return {
      q: $('#sync-q')?.value.trim() || '',
      result: $('#sync-result')?.value || '',
      scope: $('#sync-scope')?.value || '',
      from: $('#sync-from')?.value || '',
      to: $('#sync-to')?.value || '',
    };
  }

  function syncHasFilter() {
    const f = syncFilters();
    return !!(f.q || f.result || f.scope || f.from || f.to);
  }

  async function loadSyncEvents(resetPage = false) {
    if (resetPage) state.syncPage = 0;
    const seq = state.syncSeq = (state.syncSeq || 0) + 1;
    const f = syncFilters();
    const p = new URLSearchParams();
    Object.entries(f).forEach(([k, v]) => { if (v) p.set(k, v); });
    p.set('limit', String(SYNC_PAGE_SIZE));
    p.set('offset', String(state.syncPage * SYNC_PAGE_SIZE));
    try {
      const r = await api('/api/sync/events?' + p.toString());
      if (seq !== state.syncSeq) return; // 旧筛选条件的响应不得覆盖新结果
      state.syncTotal = r.total || 0;
      const entries = r.entries || [];
      renderSyncEvents(entries);
      const from = state.syncTotal ? state.syncPage * SYNC_PAGE_SIZE + 1 : 0;
      const to = state.syncPage * SYNC_PAGE_SIZE + entries.length;
      const cnt = $('#sync-count');
      if (cnt) {
        const ok = entries.filter((e) => e.result === 'ok').length;
        const fail = entries.filter((e) => e.result === 'fail').length;
        const skip = entries.filter((e) => e.result === 'skip').length;
        cnt.textContent = `共 ${state.syncTotal} 批` + (state.syncTotal ? `，显示 ${from}-${to}` : '')
          + ` · 本页 ✓${ok} !${fail} ·${skip}`;
      }
      const pageEl = $('#sync-page');
      if (pageEl) pageEl.textContent = `第 ${state.syncPage + 1} 页 / 共 ${Math.max(1, Math.ceil(state.syncTotal / SYNC_PAGE_SIZE))} 页`;
      const prev = $('#sync-prev'), next = $('#sync-next');
      if (prev) prev.disabled = state.syncPage <= 0;
      if (next) next.disabled = to >= state.syncTotal;
    } catch (e) { /* 静默：同步页数据加载失败时保留上次的记录 */ }
  }

  // 本地写入与远程同步的结果合并展示；后端已把同批次事件合并，这里负责分层呈现。
  function eventDayLabel(iso) {
    const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso || '');
    if (!m) return '';
    const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
    return `${Number(m[2])}月${Number(m[3])}日 · 周${'日一二三四五六'[d.getDay()]}`;
  }

  function eventClock(iso) {
    const m = /T(\d{2}:\d{2}(?::\d{2})?)/.exec(iso || '');
    return m ? m[1] : '';
  }

  function fileKind(name) {
    if (/_key|_priv|\.key/i.test(name)) return 'key';
    if (/_cert|\.cer|\.crt/i.test(name)) return 'cert';
    return 'file';
  }

  function renderSyncEvents(list) {
    const box = $('#sync-event-list');
    if (!box) return;
    if (!list.length) {
      box.innerHTML = `<div class="empty"><p>${syncHasFilter() ? '没有符合筛选条件的记录' : '暂无同步记录'}</p></div>`;
      return;
    }
    const cls = { ok: 'green', fail: 'red', skip: 'yellow' };
    const icon = { ok: '✓', fail: '!', skip: '·' };
    const label = { ok: '成功', fail: '失败', skip: '跳过' };
    let lastDay = '';
    box.innerHTML = list.map((e) => {
      const day = eventDayLabel(e.time);
      const divider = day && day !== lastDay ? `<div class="event-day"><span>${esc(day)}</span></div>` : '';
      lastDay = day;
      const files = (e.files || []).map((name) => {
        const kind = fileKind(name);
        const mark = kind === 'key' ? '钥' : kind === 'cert' ? '证' : '档';
        return `<span class="file-chip ${kind}"><span class="file-ico">${mark}</span>${esc(name)}</span>`;
      }).join('');
      const merged = e.merged > 1 ? `<span class="chip merged">合并 ${e.merged} 条</span>` : '';
      const count = e.count || (e.files || []).length;
      const countChip = count > 1 ? `<span class="chip">${count} 个文件</span>` : '';
      let detail = '';
      if (e.result === 'fail') {
        detail = `<div class="event-detail is-error">${esc(e.detail || '同步失败')}</div>`;
      } else if (e.detail && e.detail.includes('跳过')) {
        detail = `<div class="event-note">${esc(e.detail)}</div>`;
      } else if (!files && e.detail) {
        detail = `<div class="event-detail">${esc(e.detail)}</div>`;
      }
      const scopeText = e.scope === 'remote' ? '远程同步' : '本地同步';
      return `${divider}<div class="sync-event-item result-${esc(e.result || 'skip')}">
        <div class="event-head">
          <span class="result-pill ${cls[e.result] || ''}"><span class="result-ico">${icon[e.result] || '·'}</span>${esc(label[e.result] || '跳过')}</span>
          <span class="chip">${scopeText}</span>${merged}${countChip}
          <span class="event-time">${esc(eventClock(e.time) || e.time || '')}</span>
        </div>
        <div class="event-route"><span class="route-from">${esc(e.rule)}</span><span class="arrow">→</span><span class="route-to">${esc(e.target)}</span></div>
        <div class="event-meta"><span class="meta-label">来源</span><span class="meta-value">${esc(e.source || '—')}</span></div>
        ${files ? `<div class="file-list">${files}</div>` : ''}
        ${detail}
      </div>`;
    }).join('');
  }

  function scheduleSyncSearch() {
    clearTimeout(state.syncTimer);
    state.syncTimer = setTimeout(() => loadSyncEvents(true), 300);
  }

  $('#sync-events-refresh').addEventListener('click', () => loadSyncEvents(true));
  $('#sync-q').addEventListener('input', scheduleSyncSearch);
  ['#sync-result', '#sync-scope', '#sync-from', '#sync-to'].forEach((sel) => {
    $(sel)?.addEventListener('change', () => loadSyncEvents(true));
  });
  $('#sync-reset').addEventListener('click', () => {
    ['#sync-q', '#sync-result', '#sync-scope', '#sync-from', '#sync-to'].forEach((sel) => {
      const el = $(sel); if (el) el.value = '';
    });
    state.syncPage = 0;
    loadSyncEvents(true);
  });
  $('#sync-prev').addEventListener('click', () => {
    if (state.syncPage > 0) { state.syncPage--; loadSyncEvents(); }
  });
  $('#sync-next').addEventListener('click', () => {
    if ((state.syncPage + 1) * SYNC_PAGE_SIZE < state.syncTotal) { state.syncPage++; loadSyncEvents(); }
  });

  // ---------------- 远程主机同步 ----------------
  function renderRemoteFileHosts() {
    const sel = $('#remote-file-host');
    if (!sel) return;
    const prev = sel.value;
    const hosts = remoteHosts.filter((h) => h.enabled);
    sel.innerHTML = hosts.length
      ? hosts.map((h) => `<option value="${esc(h.id)}">${esc(h.name)}</option>`).join('')
      : '<option value="">没有启用的主机</option>';
    if (hosts.some((h) => h.id === prev)) sel.value = prev;
  }

  // 类型标注只看文件自身内容（后端 matched_kinds）：证书/私钥都能识别，
  // 不靠同步规则、不靠文件名、也不要求面板签发过同域证书。
  // 是否会被同步由 contentMatches 决定，两者分开显示，避免「识别了却不同步」被误读成漏识别。
  function renderRemoteFiles(files, dir, matchedKinds, fileDomains, contentMatches) {
    const box = $('#remote-file-list');
    const info = $('#remote-file-info');
    const identified = Object.keys(matchedKinds || {}).length;
    const hits = Object.keys(contentMatches || {}).length;
    info.textContent = `${dir || '—'} · ${files.length} 个条目 · 识别 ${identified} 个证书文件 · 证书内容匹配 ${hits} 个`;
    if (!files.length) {
      box.innerHTML = '<div class="empty"><p>远程目录里没有文件</p><p class="tiny muted">目录取自主机配置，请确认路径正确且已有同步好的证书</p></div>';
      return;
    }
    const KIND = { key: { cls: 'red', label: '🔑 私钥' }, cert: { cls: 'green', label: '📜 证书' }, chain: { cls: 'blue', label: '⛓ 证书链' } };
    box.innerHTML = files.map((f) => {
      const k = KIND[(matchedKinds || {})[f.name]];
      const tag = k ? `<span class="chip ${k.cls}">${k.label}</span>`
                    : `<span class="chip">${f.is_dir ? '目录' : '文件'}</span>`;
      const domains = (fileDomains || {})[f.name] || [];
      const dom = domains.length
        ? `<div class="tiny muted mt4">签发域名 ${esc(domains.slice(0, 4).join('、'))}${domains.length > 4 ? ' 等' : ''}</div>`
        : '';
      const matched = !!(contentMatches || {})[f.name];
      const syncTag = k
        ? (matched ? '<span class="chip green">可同步</span>' : '<span class="chip">面板未签发此域名</span>')
        : '';
      return `<div class="row">
        <span class="grow minw0 tiny">${esc(f.name)} <span class="muted">(${fmtSize(f.size)})</span>${dom}</span>
        ${tag}${syncTag}
        <span class="tiny muted">${esc((f.mod_time || '').slice(0, 16).replace('T', ' '))}</span>
      </div>`;
    }).join('');
  }

  function renderRemoteHosts() {
    const box = $('#remote-list');
    if (!remoteHosts.length) {
      box.innerHTML = '<div class="empty"><p>还没有添加远程主机</p><p class="tiny muted">添加后可点「立即同步」手动同步；开启「自动同步」后本地同步成功会自动同步</p></div>';
      return;
    }
    box.innerHTML = remoteHosts.map((h) => `
      <div class="row">
        <span class="chip ${h.enabled ? 'green' : ''}">${h.enabled ? '● 已启用' : '○ 已暂停'}</span>
        <span class="grow minw0">
          <div class="tiny">${esc(h.name)} · <span class="muted">${esc(h.user)}@${esc(h.host)}:${h.port}</span></div>
          <div class="tiny muted mt4">远程目录 ${esc(h.remote_dir)} · 认证 ${h.auth_mode === 'password' ? '账号密码' : 'SSH 私钥'} ${esc(h.auth_mode === 'password' ? h.password_masked : h.key_masked || '未配置')}</div>
          <div class="tiny muted mt4">${h.domains && h.domains.length ? '负责域名 ' + esc(h.domains.join('、')) + '（只同步这些域名的证书）' : '未设负责域名（内容匹配的证书全部同步）'}</div>
          <div class="tiny muted mt4">自动同步 ${h.auto_push ? '开启（本地同步成功后立即同步规则选中的文件）' : '关闭（仅在证书同步页手动同步）'}</div>
        </span>
        <button class="btn ghost small" data-remote-edit="${esc(h.id)}" type="button">编辑</button>
        <button class="btn ghost small" data-remote-test="${esc(h.id)}" type="button">测试</button>
        <button class="btn ghost small danger" data-remote-del="${esc(h.id)}" type="button">删除</button>
      </div>`).join('');
  }

  function openRemoteModal(host) {
    const h = host || {};
    const editing = !!h.id;
    const body = `
      <div class="field"><label>名称（自己起个好记的）</label><input id="rm-name" value="${esc(h.name || '')}" placeholder="例如 家里的 NAS"></div>
      <div class="field"><label>主机地址（IP 或域名）</label><input id="rm-host" value="${esc(h.host || '')}" placeholder="192.168.1.10 或 nas.example.com"></div>
      <div class="grid2">
        <div class="field"><label>SSH 端口</label><input id="rm-port" type="number" min="1" max="65535" value="${h.port || 22}"></div>
        <div class="field"><label>SSH 用户名</label><input id="rm-user" value="${esc(h.user || '')}" placeholder="root"></div>
      </div>
      <div class="field"><label>远程证书目录（绝对路径，需提前建好）</label><input id="rm-dir" value="${esc(h.remote_dir || '')}" placeholder="/etc/ssl/certs"></div>
      <div class="field"><label>负责的域名（可选，逗号分隔）</label><input id="rm-domains" value="${esc((h.domains || []).join(', '))}" placeholder="例如 pyworker.example.com, *.pyworker.example.com"></div>
      <p class="hint">这里的「名称」只是给自己看的备注，不参与域名匹配。填写「负责的域名」后，只有证书内容（CN/SAN）属于这些域名的文件才会同步到这台主机；留空表示内容匹配的证书全部同步。填写时通配符 * 可以省略。</p>
      <div class="field"><label>认证方式</label><select id="rm-auth">
        <option value="key" ${h.auth_mode !== 'password' ? 'selected' : ''}>SSH 私钥（推荐）</option>
        <option value="password" ${h.auth_mode === 'password' ? 'selected' : ''}>账号密码</option>
      </select></div>
      <div class="field" id="rm-key-field"><label>SSH 私钥（${editing ? '留空表示不修改' : '粘贴私钥内容'}）</label><textarea id="rm-key" rows="5" placeholder="${editing ? esc(h.key_masked || '') : '-----BEGIN OPENSSH PRIVATE KEY-----'}"></textarea></div>
      <div class="field hidden" id="rm-pass-field"><label>SSH 登录密码（${editing ? '留空表示不修改' : '填写账号对应的密码'}）</label><input id="rm-pass" type="password" autocomplete="new-password" placeholder="${editing ? esc(h.password_masked || '') : ''}"></div>
      <p class="hint" id="rm-auth-hint">凭证加密保存在面板数据目录，不写入命令行、不落到网页。首次连接会记录主机密钥指纹，之后密钥变化会拒绝连接。</p>
      <label class="check card"><input id="rm-enabled" type="checkbox" ${h.enabled !== false ? 'checked' : ''}> 启用这台主机</label>
      <label class="check card"><input id="rm-autopush" type="checkbox" ${h.auto_push ? 'checked' : ''}> 本地同步成功后自动同步到此主机（还需同步规则选择这台主机）</label>
      <div class="mt8"><button class="btn small" id="rm-test" type="button">🔌 测试连接</button></div>`;
    const foot = `<button class="btn ghost" id="rm-cancel" type="button">取消</button><button class="btn primary" id="rm-save" type="button">保存</button>`;
    openModal(editing ? '编辑远程主机' : '添加远程主机', body, foot);
    const syncAuthFields = () => {
      const isPass = $('#rm-auth').value === 'password';
      $('#rm-key-field').classList.toggle('hidden', isPass);
      $('#rm-pass-field').classList.toggle('hidden', !isPass);
      $('#rm-auth-hint').textContent = isPass
        ? '密码只在内存中用于登录，加密后存入数据库，网页只显示掩码，不会写入命令行或日志。首次连接记录主机密钥，之后变化会拒绝。'
        : '私钥加密保存在面板数据目录，不写入命令行、不落到网页。首次连接会记录主机密钥指纹，之后密钥变化会拒绝连接。';
    };
    $('#rm-auth').addEventListener('change', syncAuthFields);
    syncAuthFields();
    const checkCred = () => {
      if ($('#rm-auth').value === 'password' && !editing && !$('#rm-pass').value.trim()) {
        toast('请填写 SSH 登录密码', 'err');
        return false;
      }
      if ($('#rm-auth').value === 'key' && !editing && !$('#rm-key').value.trim()) {
        toast('请粘贴 SSH 私钥', 'err');
        return false;
      }
      return true;
    };
    const readPayload = () => {
      const usePass = $('#rm-auth').value === 'password';
      return {
        host: {
          id: h.id || '', name: $('#rm-name').value.trim(), host: $('#rm-host').value.trim(),
          port: Number($('#rm-port').value) || 22, user: $('#rm-user').value.trim(),
          remote_dir: $('#rm-dir').value.trim(),
          domains: $('#rm-domains').value.split(/[,，;；\n]/).map((s) => s.trim()).filter(Boolean),
          key: usePass ? '' : $('#rm-key').value.trim(),
          password: usePass ? $('#rm-pass').value : '',
          auto_push: $('#rm-autopush').checked,
          enabled: $('#rm-enabled').checked,
        },
        keep_key: editing && !usePass && !$('#rm-key').value.trim(),
        keep_password: editing && usePass && !$('#rm-pass').value.trim(),
      };
    };
    $('#rm-test').addEventListener('click', async () => {
      if (!checkCred()) return;
      const btn = $('#rm-test');
      btn.disabled = true; btn.textContent = '测试中…';
      try {
        const res = await api('/api/remote/test', { method: 'POST', body: readPayload() });
        toast(res.msg || '连接成功');
      } catch (e) { toast(e.message, 'err'); }
      finally { btn.disabled = false; btn.textContent = '🔌 测试连接'; }
    });
    $('#rm-cancel').addEventListener('click', closeModal);
    $('#rm-save').addEventListener('click', async () => {
      if (!checkCred()) return;
      try {
        await api('/api/remote/hosts', { method: 'POST', body: readPayload() });
        closeModal(); toast('远程主机已保存'); await loadSync();
      } catch (e) { toast(e.message, 'err'); }
    });
  }

  $('#remote-file-host').addEventListener('change', () => {
    const h = remoteHosts.find((x) => x.id === $('#remote-file-host').value);
    $('#remote-file-info').textContent = h
      ? `将读取主机「${h.name}」配置的远程目录：${h.remote_dir || '（未设置）'}，点「查看文件」加载。`
      : '先选择主机，再点「查看文件」。';
  });
  $('#remote-file-load').addEventListener('click', async () => {
    const hostID = $('#remote-file-host').value;
    if (!hostID) { toast('请先添加并启用远程主机', 'err'); return; }
    const btn = $('#remote-file-load');
    btn.disabled = true; btn.textContent = '读取中…';
    try {
      // 目录固定取主机配置，前端不再传自定义目录。
      const r = await api('/api/remote/files', { method: 'POST', body: { host_id: hostID } });
      renderRemoteFiles(r.files || [], r.dir || '', r.matched_kinds || {}, r.file_domains || {}, r.content_matches || {});
      toast(`已读取 ${(r.files || []).length} 个远程条目`);
    } catch (e) {
      $('#remote-file-info').textContent = e.message;
      $('#remote-file-list').innerHTML = `<div class="empty"><p>读取失败</p><p class="tiny muted">${esc(e.message)}</p></div>`;
      toast(e.message, 'err');
    } finally { btn.disabled = false; btn.textContent = '查看文件'; }
  });
  $('#remote-add').addEventListener('click', () => openRemoteModal());
  $('#remote-push').addEventListener('click', async () => {
    const force = $('#remote-force').checked;
    const tip = force
      ? '强制同步会读取目标机器上的证书文件，与面板已签名证书对比，命中的文件全部用最新证书/私钥覆盖，继续？'
      : '将读取目标机器上的证书文件，与面板已签名证书对比，只覆盖内容变化过的文件，继续？';
    if (!confirm(tip)) return;
    const btn = $('#remote-push');
    btn.disabled = true;
    btn.textContent = '同步中…';
    try {
      const r = await api('/api/remote/push', { method: 'POST', body: { force, by_content: true } });
      const events = (r.remote_events || r.events || []).filter((x) => x.scope !== 'local');
      const ok = events.filter((x) => x.result === 'ok').length;
      const fail = events.filter((x) => x.result === 'fail').length;
      const skipped = Number(r.skipped || 0);
      toast(!events.length
        ? (r.message || (skipped ? `${skipped} 个文件未变化，已跳过；需要全部重推请勾选「强制同步」`
                                 : '没有可同步的文件：请检查目标机器上是否有面板签发的证书、主机是否启用'))
        : `远程同步完成：${ok} 个文件成功${fail ? `，${fail} 个失败（详见同步记录）` : ''}${skipped ? `，跳过 ${skipped} 个未变化文件` : ''}`,
        fail ? 'err' : '');
      await loadSync();
    } catch (e) { toast(e.message, 'err'); }
    finally { btn.disabled = false; btn.textContent = '立即同步'; }
  });
  $('#remote-list').addEventListener('click', async (e) => {
    const edit = e.target.closest('[data-remote-edit]');
    const test = e.target.closest('[data-remote-test]');
    const del = e.target.closest('[data-remote-del]');
    if (edit) {
      const h = remoteHosts.find((x) => x.id === edit.dataset.remoteEdit);
      if (h) openRemoteModal(h);
    } else if (test) {
      const h = remoteHosts.find((x) => x.id === test.dataset.remoteTest);
      if (!h) return;
      const btn = test; btn.disabled = true;
      try {
        await api('/api/remote/test', { method: 'POST', body: { host: { ...h, key: '', password: '' }, keep_key: true, keep_password: true } });
        toast('连接成功');
      } catch (ex) { toast(ex.message, 'err'); }
      finally { btn.disabled = false; }
    } else if (del) {
      if (!confirm('确定删除这台远程主机？')) return;
      try {
        await api('/api/remote/hosts/' + encodeURIComponent(del.dataset.remoteDel), { method: 'DELETE' });
        toast('已删除'); await loadSync();
      } catch (ex) { toast(ex.message, 'err'); }
    }
  });

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
      <div class="field"><label>远程主机（本规则命中的文件才同步到选中的主机）</label>
        <div id="sy-remote-hosts">${remoteHosts.length
          ? remoteHosts.map((h) => `<label class="check"><input type="checkbox" value="${esc(h.id)}" ${(r.remote_hosts || []).includes(h.id) ? 'checked' : ''}> ${esc(h.name)} · ${esc(h.user)}@${esc(h.host)}</label>`).join('')
          : '<p class="hint">还没有远程主机，请先在「远程同步」分区添加。</p>'}</div>
        <p class="hint">不选主机表示这条规则只做本地覆盖、不参与自动远程同步。规则用于本地挂载目录的自动覆盖；远程同步的「立即同步」按目标机器证书内容与面板证书对比，不依赖这里的规则。主机配置了「负责域名」时，只会覆盖属于它的文件。</p>
      </div>
      <p class="hint">匹配到文件后按文件名结尾的标记判断写入内容：_key / .key 写新私钥，_cert / _fullchain 写新证书，_chain / ca. 写证书链。域名里出现 key 等字样不会误判。</p>
      <label class="check card"><input id="sy-enabled" type="checkbox" ${r.enabled !== false ? 'checked' : ''}> 启用此规则</label>
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
      remote_hosts: $$('#sy-remote-hosts input:checked').map((i) => i.value),
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
        const K = { key: 'red', cert: 'green', chain: 'blue' };
        out.innerHTML = `<p class="tiny">会覆盖 <strong>${items.length}</strong> 个文件：</p>` +
          items.map((m) => `<div class="row tiny"><span class="grow minw0">${esc(m.dir)} · ${esc(m.file)} <span class="muted">← ${esc(m.source)}</span></span><span class="chip ${K[m.kind] || ''}">写入${esc(m.content)}</span></div>`).join('');
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
    const force = $('#sync-force').checked;
    if (force && !confirm('强制同步会重新覆盖所有匹配到的证书和私钥，确定继续？')) return;
    const btn = $('#sync-run');
    btn.disabled = true;
    btn.textContent = '同步中…';
    try {
      const r = await api('/api/sync/run', { method: 'POST', body: { force } });
      const events = r.events || [];
      const ok = events.filter((x) => x.result === 'ok').length;
      const fail = events.filter((x) => x.result === 'fail').length;
      const skipped = r.skipped || 0;
      toast(`同步完成：${ok} 个文件已更新${skipped ? `，${skipped} 个未变化已跳过` : ''}${fail ? `，${fail} 个失败` : ''}`);
      await loadSync();
    } catch (e) { toast(e.message, 'err'); }
    finally { btn.disabled = false; btn.textContent = '立即同步'; }
  });
  $('#sync-clear-events').addEventListener('click', async () => {
    if (!confirm('确定清空全部同步记录？此操作不可撤销。')) return;
    try {
      await api('/api/sync/events', { method: 'DELETE' });
      toast('同步记录已清空');
      await loadSync();
    } catch (e) { toast(e.message, 'err'); }
  });

  // ---------------- 备份与恢复 ----------------
  let backupPayload = null;

  $('#backup-export').addEventListener('click', async () => {
    const btn = $('#backup-export');
    btn.disabled = true; btn.textContent = '导出中…';
    try {
      const res = await api('/api/backup', { raw: true });
      const blob = await res.blob();
      const cd = res.headers.get('Content-Disposition') || '';
      const m = /filename="([^"]+)"/.exec(cd);
      const name = m ? m[1] : 'acmesh-panel-backup.json';
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = name;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast('备份文件已开始下载');
    } catch (e) { toast(e.message, 'err'); }
    finally { btn.disabled = false; btn.textContent = '⭳ 导出备份'; }
  });

  $('#backup-file').addEventListener('change', async () => {
    const f = $('#backup-file').files[0];
    const box = $('#backup-preview');
    const btn = $('#backup-import');
    backupPayload = null; btn.disabled = true;
    if (!f) { box.textContent = '尚未选择文件。'; return; }
    if (f.size > 8 * 1024 * 1024) { box.textContent = '文件超过 8 MiB，不是有效的备份文件。'; return; }
    try {
      const j = JSON.parse(await f.text());
      if (j.format !== 'acmesh-panel-backup' || j.version !== 1 || !j.state || !j.exported_at) {
        box.textContent = '不是有效的 acmesh-panel 备份文件（格式 / 版本不匹配）。';
        return;
      }
      const st = j.state;
      const count = (v) => (v && typeof v === 'object') ? Object.keys(v).length : (Array.isArray(v) ? v.length : 0);
      const items = [
        ['DNS 凭证', count(st.providers)], ['通知渠道', count(st.notifiers)],
        ['远程主机', count(st.remote_hosts)], ['同步规则', count(st.sync_rules)],
        ['同步记录', count(st.sync_events)], ['证书邮箱', count(st.cert_emails)],
      ];
      box.innerHTML = `<div class="backup-summary">
        <div><strong>${esc(f.name)}</strong> · ${fmtSize(f.size)}</div>
        <div class="mt4">面板版本 ${esc(j.app_version || '未知')} · 导出于 ${esc(String(j.exported_at).slice(0, 19).replace('T', ' '))}</div>
        <div class="chip-wrap mt4">${items.map(([k, v]) => `<span class="chip">${esc(k)} ${v}</span>`).join('')}</div>
        <div class="mt4">确认无误后点「恢复这份备份」；登录凭据不会被覆盖。</div>
      </div>`;
      backupPayload = j;
      btn.disabled = false;
    } catch (e) { box.textContent = '无法解析该 JSON 文件：' + e.message; }
  });

  $('#backup-import').addEventListener('click', async () => {
    if (!backupPayload) return;
    if (!confirm('恢复会覆盖当前全部配置与同步记录，且不可撤销。确定继续？')) return;
    const btn = $('#backup-import');
    btn.disabled = true; btn.textContent = '恢复中…';
    try {
      const r = await api('/api/backup', { method: 'POST', body: backupPayload });
      toast(r.message || '配置已恢复，正在刷新页面');
      setTimeout(() => location.reload(), 600);
    } catch (e) { toast(e.message, 'err'); btn.disabled = false; btn.textContent = '恢复这份备份'; }
  });

  boot();
})();
