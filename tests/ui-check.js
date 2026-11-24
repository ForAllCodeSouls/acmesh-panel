#!/usr/bin/env node
/* 静态一致性检查：app.js 里引用的 #id 必须存在于 index.html 或 JS 动态模板里。
   没有浏览器环境时，这是发现「选择器拼错 → 运行时 null 报错」最有效的手段。 */
const fs = require('fs');
const path = require('path');

const root = path.dirname(__dirname);
const html = fs.readFileSync(path.join(root, 'web/index.html'), 'utf8');
const js = fs.readFileSync(path.join(root, 'web/app.js'), 'utf8');

const ids = new Set();
for (const m of (html + js).matchAll(/\bid="([A-Za-z0-9_-]+)"/g)) ids.add(m[1]);

const refs = new Set();
for (const m of js.matchAll(/\$\('#([A-Za-z0-9_-]+)'/g)) {
  if (m[1].endsWith('-')) continue; // 动态拼接的前缀，例如 '#view-' + k
  refs.add(m[1]);
}

const missing = [...refs].filter((r) => !ids.has(r));
const unused = [...ids].filter((i) => !refs.has(i) && !js.includes(`#${i}`));

console.log(`id 定义: ${ids.size}, 引用: ${refs.size}`);
if (missing.length) {
  console.error('❌ 引用了不存在的 id:', missing.join(', '));
  process.exit(1);
}
console.log('✅ 所有选择器都能命中元素');
if (unused.length) console.log('（提示）HTML 中未被 JS 直接引用的 id:', unused.join(', '));
