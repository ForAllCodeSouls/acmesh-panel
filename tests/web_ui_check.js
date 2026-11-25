// 无浏览器环境下验证同步记录渲染 / 结果筛选 / 失败提示（node tests/web_ui_check.js）
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const src = fs.readFileSync(path.join(__dirname, '..', 'web', 'app.js'), 'utf8');
const start = src.indexOf('  function renderSyncEvents()');
const end = src.indexOf("  $('#remote-event-filter').addEventListener", start);
if (start < 0 || end < 0) throw new Error('未找到渲染函数片段');
const snippet = src.slice(start, end);

const boxes = { '#sync-event-list': { innerHTML: '' }, '#remote-event-list': { innerHTML: '' } };
const sandbox = {
  $: (sel) => boxes[sel],
  esc: (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])),
  syncEvents: [], remoteEvents: [], localEventFilter: 'all', remoteEventFilter: 'all',
};
vm.createContext(sandbox);
vm.runInContext(snippet + '\nthis.renderSyncEvents = renderSyncEvents; this.renderEventList = renderEventList;', sandbox);

let passed = 0;
function check(name, ok, extra) {
  if (!ok) throw new Error(`FAIL ${name}: ${JSON.stringify(extra)}`);
  passed++;
  console.log(`  ok - ${name}`);
}

const failDetail = '读取本地文件失败: baihu.loveli.de5.net_cert.pem（路径 /certs/baihu.loveli.de5.net_cert.pem 不存在）。请检查面板容器内 ACME_PANEL_SYNC_DIR 的挂载路径，不要填写宿主机路径';
sandbox.syncEvents = [{ time: '2026-11-25T08:12:16+08:00', rule: '本地覆盖', source: 'example.com', target: '/certs/x.pem', result: 'ok', detail: '写入成功', files: ['example.com_cert.pem'] }];
sandbox.remoteEvents = [
  { time: '2026-11-25T08:12:16+08:00', rule: '远程同步 · pyworker.de5.net', source: '/certs', target: 'root@156.233.226.94:/home/web/certs', result: 'fail', detail: failDetail },
  { time: '2026-11-25T08:13:00+08:00', rule: '远程同步 · NAS', source: '/certs', target: 'deploy@nas:/srv/certs', result: 'ok', detail: '推送 2 个文件到远程主机', count: 2, files: ['a_cert.pem', 'a_key.pem'] },
];
sandbox.renderSyncEvents();
check('远程记录只渲染远程结果', !boxes['#remote-event-list'].innerHTML.includes('本地覆盖'), boxes['#remote-event-list'].innerHTML.slice(0, 120));
check('本地记录不含远程主机', !boxes['#sync-event-list'].innerHTML.includes('pyworker.de5.net'));
check('失败原因完整展示', boxes['#remote-event-list'].innerHTML.includes(failDetail));
check('失败样式标记', boxes['#remote-event-list'].innerHTML.includes('event-detail is-error'));
check('路由清晰展示', boxes['#remote-event-list'].innerHTML.includes('root@156.233.226.94:/home/web/certs'));
check('不再拼接 /certs/certs 路径', !boxes['#remote-event-list'].innerHTML.includes('/certs/certs/'));

sandbox.remoteEventFilter = 'fail';
sandbox.renderSyncEvents();
check('筛选失败只显示失败', boxes['#remote-event-list'].innerHTML.includes('pyworker.de5.net') && !boxes['#remote-event-list'].innerHTML.includes('NAS'));
sandbox.remoteEventFilter = 'ok';
sandbox.renderSyncEvents();
check('筛选成功只显示成功', boxes['#remote-event-list'].innerHTML.includes('NAS') && !boxes['#remote-event-list'].innerHTML.includes('pyworker.de5.net'));
sandbox.remoteEvents = [];
sandbox.renderSyncEvents();
check('空状态文案', boxes['#remote-event-list'].innerHTML.includes('没有成功记录'));

// 结构 / 交互回归：防止改写后出现死标签、弹窗遮挡、SSE 泄漏
const html = fs.readFileSync(path.join(__dirname, '..', 'web', 'index.html'), 'utf8');
const css = fs.readFileSync(path.join(__dirname, '..', 'web', 'style.css'), 'utf8');
const app = fs.readFileSync(path.join(__dirname, '..', 'web', 'app.js'), 'utf8');

function tabsMatch(tabsRe, panelsRe, label) {
  const tabs = [...html.matchAll(tabsRe)].map((m) => m[1]);
  const panels = [...html.matchAll(panelsRe)].map((m) => m[1]);
  check(label + ' 标签与分区一一对应',
    tabs.length > 0 && tabs.length === panels.length && tabs.every((t) => panels.includes(t)),
    { tabs, panels });
}
tabsMatch(/data-subtab="([^"]+)"/g, /data-subpanel="([^"]+)"/g, '页内分区');
check('证书同步三个分区', ['local', 'remote', 'records'].every((k) => html.includes(`data-subtab="${k}"`)));
check('设置四个分区', ['security', 'system', 'audit', 'support'].every((k) => html.includes(`data-subtab="${k}"`)));
check('确认弹窗先关闭再展示结果', /closeModal\(\);\s*\n\s*if \(typeof onSuccess/.test(app));
check('SSE 统一关闭钩子挂到 closeModal', app.includes('state.closeJobLog') && app.includes("if (typeof state.closeJobLog === 'function') state.closeJobLog()"));
check('任务取消按钮空值保护', app.includes("$('#job-cancel')?.classList.add('hidden')"));
check('私钥清除定时器捕获节点', app.includes('const keyBox = $(\'#comb-key\')'));
check('刷新按当前页加载', /state\.view === 'notify'[\s\S]*state\.view === 'sync'[\s\S]*state\.view === 'settings'/.test(app));
check('切换视图复位滚动', app.includes("window.scrollTo({ top: 0, behavior: 'auto' })"));
check('签发按钮只在证书页显示', app.includes("$('#issue-btn').classList.toggle('hidden', v !== 'certs')"));
check('远程主机空状态文案已修正', app.includes('可点「立即同步」手动推送'));
check('远程同步新增默认关闭的强制勾选', html.includes('id="remote-force"') && html.includes('id="remote-push" type="button">立即同步')
  && app.includes("const force = $('#remote-force').checked") && app.includes('body: { force }'));
check('远程普通同步提示文案存在', html.includes('只有规则命中的文件才会推送')
  && app.includes('只推规则命中的文件') && app.includes('remote_seen_count'));
check('远程目录文件面板存在', html.includes('id="remote-file-host"') && html.includes('id="remote-file-dir"')
  && html.includes('id="remote-file-load"') && html.includes('id="remote-file-list"')
  && app.includes("api('/api/remote/files'"));
check('同步规则新增远程主机栏', app.includes('id="sy-remote-hosts"') && app.includes('remote_hosts: $$(')
  && app.includes('远程主机：${remoteText}'));
check('密码策略统一为 12 位', html.includes('至少 12 位，含大写 / 小写 / 数字') && html.includes('minlength="12"'));
check('SSH 端口/用户名使用已定义栅格类', app.includes('<div class="grid2">') && !app.includes('field-row'));
check('CSS 只有一套设计令牌', (css.match(/:root\s*\{/g) || []).length === 1);
check('筛选标签字号声明有效', /font-family: inherit; font-size: 11\.5px; font-weight: 500/.test(css) && !css.includes('font: 500 11.5px/1.4 inherit'));
check('弹窗底部固定可见', css.includes('.modal-foot') && css.includes('flex: none; background: #101820'));

console.log(`web UI checks: ${passed} passed`);
