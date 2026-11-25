#!/usr/bin/env node
/* 静态一致性检查：app.js 里引用的 #id 必须存在于 index.html 或 JS 动态模板里。
   没有浏览器环境时，这是发现「选择器拼错 → 运行时 null 报错」最有效的手段。 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.dirname(__dirname);
const html = fs.readFileSync(path.join(root, 'web/index.html'), 'utf8');
const js = fs.readFileSync(path.join(root, 'web/app.js'), 'utf8');

// 1) 语法检查：把整个 IIFE 交给 JS 引擎编译，语法错误直接失败
try {
  new vm.Script(js, { filename: 'app.js' });
  console.log('✅ app.js 语法正确');
} catch (e) {
  console.error('❌ app.js 语法错误:', e.message);
  process.exit(1);
}

// 2) 检查对象字面量初始化时引用自身（TDZ 会导致运行时静默报错，例如保存按钮无反应）
//    模式：const X = { ... X. ... };  —— 只扫描到第一个 "};" 为止
const lines = js.split('\n');
for (let i = 0; i < lines.length; i++) {
  const m = lines[i].match(/\b(?:const|let)\s+(\w+)\s*=\s*\{/);
  if (!m) continue;
  const name = m[1];
  let depth = 0;
  for (let j = i; j < Math.min(i + 60, lines.length); j++) {
    depth += (lines[j].match(/\{/g) || []).length - (lines[j].match(/\}/g) || []).length;
    if (j > i && new RegExp(`\\b${name}\\.`).test(lines[j])) {
      console.error(`❌ 第 ${j + 1} 行：变量 ${name} 在自身对象初始化中引用（暂时性死区）`);
      process.exit(1);
    }
    if (depth <= 0 && j > i) break;
  }
}
console.log('✅ 无变量自引用初始化');

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
