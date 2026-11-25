// 无浏览器环境下验证合并同步记录渲染 / 筛选 / 失败提示（node tests/web_ui_check.js）
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.join(__dirname, '..');
const src = fs.readFileSync(path.join(root, 'web', 'app.js'), 'utf8');
const start = src.indexOf('  function syncFilters()');
const end = src.indexOf('  function scheduleSyncSearch()', start);
if (start < 0 || end < 0) throw new Error('未找到同步记录渲染函数片段');
const snippet = src.slice(start, end);

const boxes = { '#sync-event-list': { innerHTML: '' } };
const inputs = {
  '#sync-q': { value: '' }, '#sync-result': { value: '' }, '#sync-scope': { value: '' },
  '#sync-from': { value: '' }, '#sync-to': { value: '' },
};
const sandbox = {
  $: (sel) => boxes[sel] || inputs[sel] || { value: '', textContent: '', disabled: false },
  esc: (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])),
  state: { syncPage: 0, syncTotal: 0, syncTimer: null },
  api: async () => ({}),
  SYNC_PAGE_SIZE: 50,
};
vm.createContext(sandbox);
vm.runInContext(snippet + '\nthis.renderSyncEvents = renderSyncEvents; this.syncHasFilter = syncHasFilter;', sandbox);

let passed = 0;
function check(name, ok, extra) {
  if (!ok) throw new Error(`FAIL ${name}: ${JSON.stringify(extra)}`);
  passed++;
  console.log(`  ok - ${name}`);
}

const failDetail = '读取本地文件失败: demo1.example.net_cert.pem（路径 /certs/demo1.example.net_cert.pem 不存在）。请检查面板容器内 ACME_PANEL_SYNC_DIR 的挂载路径，不要填写宿主机路径';
const list = [
  { time: '2026-11-25T08:12:16+08:00', scope: 'local', rule: '本地覆盖', source: 'example.com', target: '/certs/x.pem', result: 'ok', detail: '写入成功', files: ['example.com_cert.pem'] },
  { time: '2026-11-25T08:12:16+08:00', scope: 'remote', rule: '远程同步 · remote1.example.net', source: '/certs', target: 'deploy@203.0.113.10:/home/web/certs', result: 'fail', detail: failDetail },
  { time: '2026-11-25T08:13:00+08:00', scope: 'remote', rule: '远程同步 · NAS', source: '/certs', target: 'deploy@nas:/srv/certs', result: 'ok', detail: '同步 2 个文件到远程主机', count: 2, files: ['a_cert.pem', 'a_key.pem'] },
];
sandbox.renderSyncEvents(list);
const merged = boxes['#sync-event-list'].innerHTML;
check('合并列表同时含本地与远程结果', merged.includes('本地覆盖') && merged.includes('remote1.example.net') && merged.includes('NAS'), merged.slice(0, 160));
check('每条标注本地/远程范围', merged.includes('<span class="chip">本地同步</span>') && merged.includes('<span class="chip">远程同步</span>'));
check('失败原因完整展示', merged.includes(failDetail));
check('失败样式标记', merged.includes('event-detail is-error'));
check('路由清晰展示', merged.includes('deploy@203.0.113.10:/home/web/certs'));
check('不再拼接 /certs/certs 路径', !merged.includes('/certs/certs/'));
check('日期分隔按天分组', merged.includes('event-day') && merged.includes('11月25日'));
check('私钥与证书文件用不同标识', merged.includes('file-chip key') && merged.includes('file-chip cert'));
check('结果用直观图标', merged.includes('result-pill green') && merged.includes('result-pill red'));
check('时间只显示时分秒', merged.includes('08:12:16') && !merged.includes('2026-11-25T08:12:16'));

// 同批次多条事件应合并为一张卡片：后端字段 merged/count 驱动前端聚合展示。
sandbox.renderSyncEvents([{
  time: '2026-11-26T00:00:25+08:00', scope: 'remote', rule: '按证书内容同步 · 服务器1',
  source: 'pythonscript.duckdns.org_ecc', target: 'root@203.0.113.10:/home/web/certs',
  result: 'ok', merged: 6, count: 6,
  files: ['panel_key.pem', 'news_key.pem', 'panel_cert.pem', 'news_cert.pem'],
}]);
const batch = boxes['#sync-event-list'].innerHTML;
check('批次合并徽标', batch.includes('class="chip merged"'));
check('批次条数可辨识', batch.includes('合并 6 条') && batch.includes('6 个文件'));
check('批次内文件全部列出', ['panel_key.pem', 'news_key.pem', 'panel_cert.pem', 'news_cert.pem'].every((f) => batch.includes(f)));

sandbox.renderSyncEvents([]);
check('无筛选空状态文案', boxes['#sync-event-list'].innerHTML.includes('暂无同步记录'));
inputs['#sync-q'].value = 'abc';
sandbox.renderSyncEvents([]);
check('有筛选空状态文案', boxes['#sync-event-list'].innerHTML.includes('没有符合筛选条件的记录'));
inputs['#sync-q'].value = '';

// 结构 / 交互回归：防止改写后出现死标签、弹窗遮挡、SSE 泄漏
const html = fs.readFileSync(path.join(root, 'web', 'index.html'), 'utf8');
const css = fs.readFileSync(path.join(root, 'web', 'style.css'), 'utf8');
const app = fs.readFileSync(path.join(root, 'web', 'app.js'), 'utf8');
const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
const goBackup = fs.readFileSync(path.join(root, 'backup.go'), 'utf8');
const goApi = fs.readFileSync(path.join(root, 'api.go'), 'utf8');
const goAcme = fs.readFileSync(path.join(root, 'acme.go'), 'utf8');

function tabsMatch(tabsRe, panelsRe, label) {
  const tabs = [...html.matchAll(tabsRe)].map((m) => m[1]);
  const panels = [...html.matchAll(panelsRe)].map((m) => m[1]);
  check(label + ' 标签与分区一一对应',
    tabs.length > 0 && tabs.length === panels.length && tabs.every((t) => panels.includes(t)),
    { tabs, panels });
}
tabsMatch(/data-subtab="([^"]+)"/g, /data-subpanel="([^"]+)"/g, '页内分区');
check('证书同步四个分区且顺序正确', ['local', 'rules', 'remote', 'records']
  .map((k) => html.includes(`data-subtab="${k}"`)).join('') === 'truetruetruetrue');
check('同步规则独立页签且本地/远程分工明确', html.indexOf('data-subtab="local"') < html.indexOf('data-subtab="rules"')
  && html.indexOf('data-subtab="rules"') < html.indexOf('data-subtab="remote"')
  && html.includes('data-subpanel="rules"') && html.includes('这套规则用于本地挂载目录的自动覆盖')
  && html.includes('手动远程同步则在「远程同步」页签按目标机器上的证书内容对比进行'));
check('精确归属优先说明存在', html.includes('精确归属优先') && html.includes('泛域名/子域匹配不会抢写已有独立证书的子域文件'));
check('规则行显示生效范围标签', app.includes("scopeChips") && app.includes('>本地</span>')
  && app.includes('chip blue" title="命中文件同步到该主机的远程证书目录'));
check('设置五个分区', ['security', 'system', 'audit', 'backup', 'support'].every((k) => html.includes(`data-subtab="${k}"`)));
check('确认弹窗先关闭再展示结果', /closeModal\(\);\s*\n\s*if \(typeof onSuccess/.test(app));
check('SSE 统一关闭钩子挂到 closeModal', app.includes('state.closeJobLog') && app.includes("if (typeof state.closeJobLog === 'function') state.closeJobLog()"));
check('任务取消按钮空值保护', app.includes("$('#job-cancel')?.classList.add('hidden')"));
check('私钥清除定时器捕获节点', app.includes("const keyBox = $('#comb-key')"));
check('刷新按当前页加载', /state\.view === 'notify'[\s\S]*state\.view === 'sync'[\s\S]*state\.view === 'settings'/.test(app));
check('切换视图复位滚动', app.includes("window.scrollTo({ top: 0, behavior: 'auto' })"));
check('签发按钮只在证书页显示', app.includes("$('#issue-btn').classList.toggle('hidden', v !== 'certs')"));
check('远程主机空状态文案已修正', app.includes('可点「立即同步」手动同步'));
check('远程同步新增默认关闭的强制勾选', html.includes('id="remote-force"') && html.includes('id="remote-push" type="button">立即同步')
  && app.includes("const force = $('#remote-force').checked") && app.includes('by_content: true'));
check('远程同步提示文案改为按证书内容对比', html.includes('面板读取目标机器上证书文件里的 CN/SAN')
  && app.includes('by_content: true') && app.includes('remote_seen_count'));
check('页签改名为远程同步', html.includes('>远程同步</button>') && !html.includes('>远程推送</button>'));
check('远程目录输入框已删除', !html.includes('id="remote-file-dir"') && !app.includes('remote-file-dir'));
check('远程目录直接读主机配置', html.includes('目录直接读取主机配置')
  && app.includes("body: { host_id: hostID }") && goApi.includes('listRemoteFiles(s.store, h, h.RemoteDir)'));
check('远程文件只按证书内容标注类型', app.includes('matched_kinds') && app.includes('KIND[(matchedKinds')
  && app.includes('证书内容匹配') && !goApi.includes('remoteMatchedKinds')
  && goApi.includes('contentMatches = matchRemoteCerts(names, contents, all)'));
check('主机名称明确标注为备注不参与匹配', html.includes('主机名称都不参与匹配')
  && app.includes('不参与域名匹配'));
check('同步记录合并为单一列表', !html.includes('id="remote-event-list"')
  && html.includes('id="sync-event-list"') && html.includes('本地写入与远程同步合并展示')
  && html.includes('归为一批'));
check('同步记录筛选栏齐备', ['sync-q', 'sync-result', 'sync-scope', 'sync-from', 'sync-to', 'sync-reset']
  .every((id) => html.includes(`id="${id}"`)) && html.includes('id="sync-filters"'));
check('同步记录分页控件存在', ['sync-count', 'sync-prev', 'sync-page', 'sync-next']
  .every((id) => html.includes(`id="${id}"`)));
check('同步记录走服务端筛选与分页', app.includes("'/api/sync/events?' + p.toString()")
  && app.includes("p.set('limit'") && app.includes("p.set('offset'"));
check('同步记录关键词防抖', app.includes('scheduleSyncSearch') && app.includes('setTimeout(() => loadSyncEvents(true), 300)'));
check('同步记录重置清空全部条件', /#sync-reset'\)[\s\S]*el\.value = ''[\s\S]*loadSyncEvents\(true\)/.test(app));
check('备份恢复分区与控件存在', html.includes('data-subtab="backup"')
  && ['backup-export', 'backup-file', 'backup-preview', 'backup-import'].every((id) => html.includes(`id="${id}"`)));
check('备份导出走下载、导入走预览确认', app.includes("api('/api/backup', { raw: true })")
  && app.includes("api('/api/backup', { method: 'POST', body: backupPayload })")
  && app.includes("j.format !== 'acmesh-panel-backup'"));
check('备份不含登录凭据哈希', goBackup.includes('st.Hash = ""') && goBackup.includes('st.Salt = ""')
  && goBackup.includes('st.Iter = 0') && html.includes('登录账号与密码哈希'));
check('部署文档废话已删除', !readme.includes('不管用哪种系统，都需要两个文件'));
check('密码策略统一为 12 位', html.includes('至少 12 位，含大写 / 小写 / 数字') && html.includes('minlength="12"')
  && app.includes('n1.length < 12') && app.includes('/[A-Z]/.test(n1)') && app.includes('/[a-z]/.test(n1)') && app.includes('/[0-9]/.test(n1)'));
check('危险按钮防重复提交', app.includes('function busyButton') && app.includes("busyButton($('#rn-go')")
  && app.includes("busyButton($('#rv-go')") && app.includes("busyButton($('#rm-go')")
  && app.includes("busyButton($('#renew-all-btn')"));
check('SSE 重连清空日志避免重复', app.includes('es.onopen = () => { logEl.textContent = \'\'; };'));
check('PEM 异步竞态加序号与 DOM 校验', app.includes('let pemSeq = 0') && app.includes('seq !== pemSeq')
  && app.includes('combCertEl.isConnected'));
check('不可逆操作二次确认', app.includes("confirm('确定清空全部同步记录") && app.includes("confirm('立即清理会按当前保留天数"));
check('429 登录倒计时禁用按钮', app.includes('err.retryAfter') && app.includes('countdown = true'));
check('SSH 端口/用户名使用已定义栅格类', app.includes('<div class="grid2">') && !app.includes('field-row'));
check('CSS 只有一套设计令牌', (css.match(/:root\s*\{/g) || []).length === 1);
check('CSS 无旧版畸形 font 简写残留', !css.includes('font: 500 11.5px/1.4 inherit') && !css.includes('.filter-tab'));
check('弹窗底部固定可见', css.includes('.modal-foot') && css.includes('flex: none; background: #101820'));
check('设置页含自动更新配置卡', html.includes('id="update-auto"') && html.includes('id="update-interval"')
  && html.includes('id="update-save"') && html.includes('id="update-check-now"'));
check('检测频次五档齐全', ['off', 'startup', '6h', 'daily', 'weekly']
  .every((v) => html.includes(`value="${v}"`)) && html.includes('每天一次'));
check('顶部全局更新横幅存在', html.includes('id="update-banner"') && css.includes('.update-banner'));
check('前端立即检测强制刷新走 POST', app.includes("api('/api/update/check', { method: 'POST', body: {} })")
  && !app.includes("api('/api/update/check?force=1')")
  && app.includes("$('#update-check-now').addEventListener('click', () => checkUpdate(true))"));
check('前端保存更新设置', app.includes("api('/api/update/settings'")
  && app.includes('auto_check: auto, interval'));
check('首次启动自动补检测', app.includes("String(r.last_check).startsWith('0001')"));
check('审计筛选栏存在', html.includes('id="audit-q"') && html.includes('id="audit-action"')
  && html.includes('id="audit-user"') && html.includes('id="audit-from"')
  && html.includes('id="audit-to"') && html.includes('id="audit-reset"'));
check('审计分页控件存在', html.includes('id="audit-prev"') && html.includes('id="audit-next"')
  && html.includes('id="audit-page"') && html.includes('id="audit-count"'));
check('审计关键词防抖搜索', app.includes('scheduleAuditSearch')
  && app.includes('setTimeout(() => loadAudit(true), 300)')
  && app.includes("$('#audit-q').addEventListener('input', scheduleAuditSearch)"));
check('审计筛选走服务端分页参数', app.includes("p.set('limit'")
  && app.includes("p.set('offset'") && app.includes("'/api/audit?' + p.toString()"));
check('审计重置清空全部条件', /#audit-reset'\)[\s\S]*el\.value = ''[\s\S]*loadAudit\(true\)/.test(app));
check('注册表单与入口已移除', !html.includes('id="setup-form"') && !html.includes('id="setup-btn"')
  && !app.includes('/api/setup') && !app.includes('checkSetup'));
check('改账号表单存在', html.includes('id="user-form"') && html.includes('id="user-pass"')
  && html.includes('id="user-new"'));
check('改账号走新接口并重新登录', app.includes("api('/api/username'")
  && (app.includes('showLogin(`账号已改为') || app.includes('showLogin(')));
check('登录页说明 env 仅首次初始化', html.includes('首次启动用环境变量')
  && html.includes('ACME_PANEL_USER / ACME_PANEL_PASSWORD')
  && html.includes('之后在设置页修改会持久保存'));
check('账号安全表单说明修改持久生效', (html.match(/修改会持久保存，重启后仍生效/g) || []).length === 2
  && !html.includes('重启后会恢复为'));
check('运行信息按凭据来源显示三态', app.includes('function credSourceLabel')
  && app.includes("src === 'web'") && app.includes("src === 'generated'")
  && app.includes("src === 'env'") && app.includes('仅首次初始化'));
check('运行信息说明 env 不再强制覆盖', app.includes('重启不会被 env 覆盖')
  && app.includes('ACME_PANEL_RESET_CREDENTIALS=1'));
check('会话凭据来源优先取 cred_source', app.includes("s.cred_source || s.username_source")
  && app.includes("s.cred_source || s.password_source"));
check('DNS 凭证展示服务商官网链接', app.includes('function websiteHTML')
  && app.includes('provider-site') && app.includes('target="_blank" rel="noopener noreferrer"')
  && app.includes('websiteHTML(code) + def.fields'));
check('官网链接仅允许 https', app.includes('/^https:\\/\\//i.test(def.website)'));
check('CSS 有官网链接样式', css.includes('.provider-site a'));
check('provider 目录带 website 字段', goAcme.includes('Website string') && goAcme.includes('json:"website"')
  && goAcme.includes('"dns_duckdns"'));
check('provider 目录已补齐 43 家', (goAcme.match(/\{"dns_/g) || []).length >= 43
  && goAcme.includes('"dns_dgon"') && goAcme.includes('"dns_gandi_livedns"')
  && goAcme.includes('"dns_linode_v4"'));
check('失效 code 只保留兼容映射', !goAcme.includes('{"dns_do"')
  && !goAcme.includes('{"dns_gandi"') && !goAcme.includes('{"dns_linode"')
  && goAcme.includes('"dns_do":     "dns_dgon"'));
check('DNS 凭证下拉按 code 字母序', app.includes('.sort((a, b) => String(a.code).localeCompare(String(b.code)))'));
check('服务商目录源码按 code 排序', (() => {
  const codes = [...goAcme.matchAll(/^\t\{"(dns_[a-z0-9_]+)"/gm)].map((m) => m[1]);
  return codes.length >= 43 && codes.join() === [...codes].sort().join();
})());
check('签发弹窗有 DNS 等待秒数并默认 30', app.includes('id="iss-dnssleep"')
  && app.includes('type="number" min="0" max="600" value="30"')
  && app.includes('dns_sleep: parseInt($(\'#iss-dnssleep\').value, 10) || 0'));
check('失败任务显示重试按钮', app.includes("['failed', 'canceled', 'skipped'].includes(j.status)")
  && app.includes("class=\"btn small job-retry-btn\""));
check('重试调用 retry 接口并跳转新任务', app.includes("/retry`, { method: 'POST', body: {} }")
  && app.includes('openJobLog(r.job.id, r.job.title)'));
check('日志弹窗有重试按钮', app.includes('id="job-retry"')
  && app.includes("retryBtn.addEventListener('click', () => retryJob(id, title))"));
check('后端有重试路由与处理函数', fs.readFileSync(path.join(root, 'main.go'), 'utf8').includes('/api/jobs/{id}/retry')
  && goApi.includes('func (s *Server) handleRetryJob')
  && goAcme.includes('func (m *JobManager) Retry'));
check('重试凭证密文落盘', goAcme.includes('EnvBlob') && goAcme.includes('SealForRetry')
  && fs.readFileSync(path.join(root, 'store.go'), 'utf8').includes('func (s *Store) SealForRetry'));
check('README 引用全部四张示意图', readme.includes('docs/01-overview.svg')
  && readme.includes('docs/02-dns-credential.svg')
  && readme.includes('docs/03-domain-matching.svg')
  && readme.includes('docs/04-remote-sync.svg'));

// 401 文案：首屏/会话失效静默回登录页，登录失败显示后端真实原因
check('401 不再无条件显示会话已过期', !app.includes("showLogin('会话已过期，请重新登录')"));
check('登录失败抛出后端真实原因', app.includes("if (path === '/api/login')") && app.includes('throw new Error(reason')
  && app.includes('j && j.error'));
check('非登录 401 静默回登录页', app.includes("showLogin('')"));
const goMain = fs.readFileSync(path.join(root, 'main.go'), 'utf8');
const goAuth = fs.readFileSync(path.join(root, 'auth.go'), 'utf8');
check('面板不再有 HSTS 开关', !goMain.includes('ACME_PANEL_HSTS') && !goMain.includes('HSTS:'));
check('HSTS 仅在确认 HTTPS 时下发', goMain.includes('if requestIsHTTPS(r)')
  && goMain.includes('Strict-Transport-Security'));
check('面板固定纯 HTTP', goMain.includes('httpSrv.ListenAndServe()')
  && !goMain.includes('ListenAndServeTLS'));
check('JS/CSS 不缓存（避免旧前端文案）', goMain.includes('strings.HasSuffix(r.URL.Path, ".js")')
  && goMain.includes('strings.HasSuffix(r.URL.Path, ".css")') && goMain.includes('"no-store"'));
check('首页资源带版本号，绕开反代旧缓存', goMain.includes('__VER__')
  && fs.readFileSync(path.join(root, 'web', 'index.html'), 'utf8').includes('/app.js?v=__VER__'));
check('Cookie 智能加固（HTTPS 才 Secure+Lax）', goApi.includes('if requestIsHTTPS(r)')
  && goApi.includes('c.Secure = true') && goApi.includes('c.SameSite = http.SameSiteLaxMode'));
check('同源校验智能恢复（按主机名兼容反代）', goAuth.includes('func sameOrigin(r *http.Request) bool {')
  && goAuth.includes('isInternalHost') && goAuth.includes('X-Forwarded-Host'));
const goNotify = fs.readFileSync(path.join(root, 'notify.go'), 'utf8');
const goRemote = fs.readFileSync(path.join(root, 'remote.go'), 'utf8');
check('Webhook 禁止跟随重定向 + 钉住已校验 IP', goNotify.includes('http.ErrUseLastResponse')
  && goNotify.includes('dialIPKey') && goNotify.includes('safeResolvedIP'));
check('远程替换不再先删目标文件', goRemote.includes('func safeRemoteReplace')
  && goRemote.includes('HasExtension("posix-rename@openssh.com")')
  && !goRemote.includes('_ = sftpClient.Remove(remotePath)'));
check('redactArgs 实现 KEY=value 打码', goAcme.includes('k+"=••••"')
  && goAcme.includes('// KEY=value 形式的参数只保留键名'));
check('删目录改为完成钩子（无 60s 轮询）', goAcme.includes('purgeHooks') && !goApi.includes('i < 300'));
check('随机密码拒绝采样', goMain.includes('limit := 256 - (256 % len(alphabet))'));
check('密码策略 store 层统一 12 位', fs.readFileSync(path.join(root, 'store.go'), 'utf8').includes('!strongPassword(password)'));
const goCompose = fs.readFileSync(path.join(root, 'docker-compose.yml'), 'utf8');
check('Docker 透传重置/并发/代理层数变量', goCompose.includes('ACME_PANEL_RESET_CREDENTIALS: "${ACME_PANEL_RESET_CREDENTIALS:-0}"')
  && goCompose.includes('ACME_PANEL_PARALLEL: "${ACME_PANEL_PARALLEL:-2}"')
  && goCompose.includes('ACME_PANEL_TRUST_PROXY_HOPS: "${ACME_PANEL_TRUST_PROXY_HOPS:-1}"'));

// 本轮全盘优化的结构性回归
check('私钥 60 秒清除后复制/下载同步失效', app.includes("const v = $('#comb-key').value")
  && app.includes("const v = ta.value") && app.includes("$('#comb-key-copy').disabled = true")
  && app.includes("$('#key-dl').disabled = true"));
check('筛选加载有请求序号防旧响应覆盖', app.includes("state.auditSeq = (state.auditSeq || 0) + 1")
  && app.includes("state.syncSeq = (state.syncSeq || 0) + 1")
  && (app.match(/seq !== state\.(audit|sync)Seq/g) || []).length >= 2);
check('页内分区补齐 tab/tabpanel 语义与方向键', app.includes("setAttribute('role', 'tab')")
  && app.includes("setAttribute('role', 'tabpanel')") && app.includes("setAttribute('aria-selected'")
  && app.includes("e.key !== 'ArrowLeft'"));
check('抽屉与弹窗共用 Tab 焦点陷阱', app.includes('const trapTab = (sel) =>')
  && app.includes("trapTab('#modal')") && app.includes("trapTab('#drawer')"));
check('登录 Enter 不再双提交', !app.includes('requestSubmit()')
  && app.includes('if (btn.disabled) return; // 表单天然支持 Enter'));
check('死代码已清理', !css.includes('#remote-event-list') && !app.includes("k === 'Cookie Secure'"));
const goSync = fs.readFileSync(path.join(root, 'sync.go'), 'utf8');
check('强制同步把 force 透传到远程', goSync.includes('pushAllRemotes(e.store, key.dir, files, force'));
check('远程凭证切换只认 keep 标志', goApi.includes('if req.KeepPassword {')
  && !goApi.includes('req.KeepPassword || h.Password == ""'));
check('跨实例恢复先校验存储密钥', goBackup.includes('func (s *Store) ValidateRestore')
  && goBackup.includes('s.store.ValidateRestore(st)'));
check('强制检测只走 POST', goMain.includes('POST /api/update/check')
  && !goApi.includes('r.URL.Query().Get("force")'));
check('远程临时/备份文件名唯一', goRemote.includes('func remoteTempPath')
  && goRemote.includes('".acmesh-bak-" + randToken(8)'));
const appVer = (fs.readFileSync(path.join(root, 'version.go'), 'utf8').match(/[0-9]+\.[0-9]+\.[0-9]+/) || [''])[0];
const installSh = fs.readFileSync(path.join(root, 'install.sh'), 'utf8');
const releaseYml = fs.readFileSync(path.join(root, '.github/workflows/release.yml'), 'utf8');
const mk = fs.readFileSync(path.join(root, 'Makefile'), 'utf8');
const bugTpl = fs.readFileSync(path.join(root, '.github/ISSUE_TEMPLATE/bug_report.yml'), 'utf8');
check('安装脚本默认版本与发布一致', installSh.includes('VERSION="${VERSION:-' + appVer + '}"')
  && installSh.includes('SHA256SUMS') && installSh.includes('sha256sum "$TMP"'));
check('Release 镜像 tag 与实际推送一致', releaseYml.includes('RELEASE_TAG_PLAIN')
  && releaseYml.includes('plain=${V#v}') && !releaseYml.includes('acmesh-panel:${{ env.RELEASE_VERSION }}')
  && releaseYml.includes('acmesh-panel-darwin-arm64'));
check('Makefile 版本从 version.go 派生', mk.includes("grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+' version.go"));
check('issue 模板版本占位符同步', bugTpl.includes(`placeholder: "${appVer}"`));

// ---- 仅允许 HTTPS 开关 ----
check('设置页有 HTTPS 开关与状态提示', html.includes('id="force-https"')
  && html.includes('id="force-https-save"') && html.includes('id="force-https-hint"'));
check('前端读取会话状态并二次确认', app.includes('s.force_https_pinned')
  && app.includes('s.https_now') && app.includes("api('/api/https/settings'")
  && app.includes('确定开启？'));
check('后端有开关接口与审计', goApi.includes('handleHTTPSSettings')
  && goApi.includes('"https_settings"') && goMain.includes('POST /api/https/settings'));
check('强制 HTTPS 静默断连且放行健康检查', goMain.includes('srv.requireHTTPS(mux)')
  && goMain.includes('r.URL.Path == "/api/health"') && goMain.includes('dropConnection(w)')
  && goMain.includes('http.Hijacker') && !goMain.includes('httpsOnlyPage'));
check('环境变量覆盖与恢复说明已文档化',
  fs.readFileSync(path.join(root, '.env.example'), 'utf8').includes('ACME_PANEL_FORCE_HTTPS=1')
  && fs.readFileSync(path.join(root, 'README.md'), 'utf8').includes('ACME_PANEL_FORCE_HTTPS=0')
  && fs.readFileSync(path.join(root, 'README.md'), 'utf8').includes('docker compose up -d'));
check('compose 注释列出全部环境变量并强调 up -d', (() => {
  const c = fs.readFileSync(path.join(root, 'docker-compose.yml'), 'utf8');
  return ['ACME_PANEL_FORCE_HTTPS', 'ACME_PANEL_RESET_CREDENTIALS', 'ACME_PANEL_TRUST_PROXY_HOPS',
    'ACME_PANEL_SYNC_DIR', 'ACME_PANEL_PARALLEL', 'ACME_PANEL_LISTEN', 'ACME_HOME', 'ACME_BIN',
    'ACME_PANEL_DATA', 'ACME_PANEL_ALLOW_LOCAL_WEBHOOK'].every((k) => c.includes(k))
    && c.includes('docker compose up -d') && c.includes('restart') && c.includes('等号');
})());

// ---- 免责声明 ----
check('登录页提示仅限授权与违法禁用', html.includes('已获明确授权的域名与主机')
  && html.includes('禁止用于任何违法用途') && html.includes('使用者自负合规责任'));
check('设置页有独立免责声明分区', html.includes('data-subtab="legal"')
  && html.includes('data-subpanel="legal"') && html.includes('使用条款与免责声明'));
const disclaimerMd = fs.readFileSync(path.join(root, 'DISCLAIMER.md'), 'utf8');
check('独立声明含三语与责任边界', disclaimerMd.includes('合法使用')
  && disclaimerMd.includes('Lawful use') && disclaimerMd.includes('適法な利用')
  && disclaimerMd.includes('不构成法律意见') && disclaimerMd.includes('No legal advice'));
for (const f of ['README.md', 'README.en.md', 'README.ja.md', 'SECURITY.md']) {
  check(`${f} 链接独立声明`, fs.readFileSync(path.join(root, f), 'utf8').includes('DISCLAIMER.md'));
}

console.log(`web UI checks: ${passed} passed`);
