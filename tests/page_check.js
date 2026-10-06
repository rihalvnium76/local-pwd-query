'use strict';

// 用桩 DOM 执行 index.html 的内联脚本，检查 pytest 看不到的交互：
// 输入框的提交时机、分页与密码生成的联动。用法：node tests/page_check.js

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const failures = [];
function check(label, actual, expected) {
  const ok = actual === expected;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}：实际 ${actual}，期望 ${expected}`);
  if (!ok) failures.push(label);
}

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const script = /<script>([\s\S]*?)<\/script>/.exec(html);
if (script === null) throw new Error('index.html 里没有内联脚本');

// 页面脚本加载时就会绑定全部事件并调用 boot()，桩元素用来承接这些调用。
const elements = new Map();
function makeElement(id) {
  const listeners = new Map();
  return {
    id,
    value: '',
    textContent: '',
    className: '',
    hidden: false,
    disabled: false,
    dataset: {},
    children: [],
    clicks: 0,
    listeners,
    classList: { add() {} },
    addEventListener(type, handler) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(handler);
    },
    fire(type, event) {
      for (const handler of listeners.get(type) ?? []) handler(event);
    },
    append() {},
    replaceChildren(...children) {
      this.children = children;
    },
    showModal() {},
    close() {},
    click() {
      this.clicks += 1;
      this.fire('click', {});
    },
  };
}
function element(id) {
  if (!elements.has(id)) elements.set(id, makeElement(id));
  return elements.get(id);
}

const context = {
  console,
  document: {
    getElementById: element,
    createElement: () => makeElement('created'),
    head: { append() {} },
    createRange: () => ({ selectNodeContents() {} }),
  },
  localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
  // boot() 会去请求 version，这里让它失败：交互检查不依赖服务器，失败路径由 pytest 之外的人工确认覆盖。
  fetch: async () => ({
    ok: false,
    status: 500,
    text: async () => '',
    arrayBuffer: async () => new ArrayBuffer(0),
  }),
  navigator: { clipboard: { writeText: async () => {} } },
  Date,
  setTimeout,
  btoa: value => Buffer.from(value, 'binary').toString('base64'),
  getSelection: () => ({ removeAllRanges() {}, addRange() {} }),
  crypto: { getRandomValues: array => array, subtle: {} },
  TextEncoder,
  MessagePack: { decode: () => [] },
};
context.globalThis = context;
vm.createContext(context);
vm.runInContext(script[1], context, { filename: 'index.html' });
const read = expression => vm.runInContext(expression, context);

// 一个含 250 个文件的根目录，按每页 100 条算正好 3 页。
const files = new Map();
for (let index = 0; index < 250; index += 1) {
  files.set(`f${index}`, { name: `f${index}`, path: `/f${index}` });
}
context.nodeStub = { name: '/', path: '/', dirs: new Map(), files };
read(
  'state.dirIndex = new Map([["/", nodeStub]]); state.allRows = collectRows(nodeStub, []);' +
    ' state.size = 100; state.page = 1; render();'
);

check('初始页码', read('state.page'), 1);
check('总页数提示', element('page-total').textContent, '共 250 项，3 页');

element('page-now').value = '9';
element('page-jump').click();
check('跳转按钮把越界页码收回末页', read('state.page'), 3);

element('page-now').value = '2';
element('page-now').fire('keydown', { key: 'Enter' });
check('页码输入框回车跳转', read('state.page'), 2);

element('page-now').value = '1';
element('page-now').fire('keydown', { key: 'a' });
check('页码输入框其他按键不跳转', read('state.page'), 2);

element('search-target').value = 'all';
element('search-scope').value = 'all';
element('search-type').value = 'all';
element('search-text').value = 'f1';
element('search-text').fire('keydown', { key: 'Enter' });
check('搜索框回车执行搜索', read('state.results.length') > 0, true);

element('pwdgen-bytes').value = '16';
element('pwdgen-count').value = '3';
element('pwdgen-bytes').fire('keydown', { key: 'Enter' });
check('字节数输入框回车生成', element('pwdgen-rows').children.length, 3);

element('pwdgen-count').value = '2';
element('pwdgen-count').fire('keydown', { key: 'Enter' });
check('生成数量输入框回车生成', element('pwdgen-rows').children.length, 2);

element('pwdgen-count').value = '0';
element('pwdgen-count').fire('keydown', { key: 'Enter' });
check('非法数量由回车给出提示', element('pwdgen-msg').textContent !== '', true);

let clicks = element('login').clicks;
element('token').value = 'token-for-check';
element('token').fire('keydown', { key: 'Enter' });
check('未登录时 Token 输入框回车触发登录按钮', element('login').clicks - clicks, 1);

read('state.user = { name: "alice" }');
clicks = element('login').clicks;
element('token').fire('keydown', { key: 'Enter' });
check('已登录时 Token 输入框回车不触发按钮', element('login').clicks - clicks, 0);

element('page-size').value = '50';
element('page-size').fire('change', {});
check('每页条数输入框在 change 时生效', read('state.size'), 50);

// 输入过程中不触发：确认没有任何输入框挂逐字监听。
const watched = ['input', 'keyup', 'keypress'];
const live = ['token', 'search-text', 'page-now', 'page-size', 'pwdgen-bytes', 'pwdgen-count'];
check(
  '输入框没有逐字触发的监听',
  live.filter(id => watched.some(type => element(id).listeners.has(type))).length,
  0
);

console.log(failures.length === 0 ? '全部通过' : `失败 ${failures.length} 项：${failures.join('、')}`);
process.exitCode = failures.length === 0 ? 0 : 1;
