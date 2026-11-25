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
check('同步规则独立页签且同时用于本地与远程', html.indexOf('data-subtab="local"') < html.indexOf('data-subtab="rules"')
  && html.indexOf('data-subtab="rules"') < html.indexOf('data-subtab="remote"')
  && html.includes('data-subpanel="rules"') && html.includes('这套规则同时用于「本地同步」和「远程同步」'));
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
  && app.includes("const force = $('#remote-force').checked") && app.includes('body: { force }'));
check('远程同步提示文案改为同步', html.includes('只有规则命中的文件才会同步')
  && app.includes('只同步规则命中的文件') && app.includes('remote_seen_count'));
check('页签改名为远程同步', html.includes('>远程同步</button>') && !html.includes('>远程推送</button>'));
check('远程目录输入框已删除', !html.includes('id="remote-file-dir"') && !app.includes('remote-file-dir'));
check('远程目录直接读主机配置', html.includes('目录直接读取主机配置')
  && app.includes("body: { host_id: hostID }") && goApi.includes('listRemoteFiles(s.store, h, h.RemoteDir)'));
check('远程文件按规则命中标注类型', app.includes('matched_kinds') && app.includes('KIND[(matchedKinds')
  && goApi.includes('func (s *Server) remoteMatchedKinds()') && goApi.includes('s.sync.Preview(rule)'));
check('同步记录合并为单一列表', !html.includes('id="remote-event-list"')
  && html.includes('id="sync-event-list"') && html.includes('本地写入与远程同步的结果合并展示'));
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
check('密码策略统一为 12 位', html.includes('至少 12 位，含大写 / 小写 / 数字') && html.includes('minlength="12"'));
check('SSH 端口/用户名使用已定义栅格类', app.includes('<div class="grid2">') && !app.includes('field-row'));
check('CSS 只有一套设计令牌', (css.match(/:root\s*\{/g) || []).length === 1);
check('CSS 无旧版畸形 font 简写残留', !css.includes('font: 500 11.5px/1.4 inherit') && !css.includes('.filter-tab'));
check('弹窗底部固定可见', css.includes('.modal-foot') && css.includes('flex: none; background: #101820'));
check('设置页含自动更新配置卡', html.includes('id="update-auto"') && html.includes('id="update-interval"')
  && html.includes('id="update-save"') && html.includes('id="update-check-now"'));
check('检测频次五档齐全', ['off', 'startup', '6h', 'daily', 'weekly']
  .every((v) => html.includes(`value="${v}"`)) && html.includes('每天一次'));
check('顶部全局更新横幅存在', html.includes('id="update-banner"') && css.includes('.update-banner'));
check('前端立即检测强制刷新', app.includes("api('/api/update/check?force=1')")
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

console.log(`web UI checks: ${passed} passed`);
