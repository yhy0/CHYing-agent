"""
Web Terminal 自动注入模块
========================

提供 Web Terminal（xterm.js / ttyd / wetty / gotty）的初始化脚本和
PostToolUse hook 注入逻辑。

- WT_INIT_SCRIPT: 完整可执行的 JS 初始化脚本
- build_wt_additional_context(): 构建 navigate_page 成功后的 additionalContext

从 base.py 拆分而来，被 create_post_tool_use_hook 引用。
"""


# Web Terminal 初始化脚本（完整可执行 JS）
# PostToolUse hook 在 navigate_page 成功后通过 additionalContext 注入给 LLM
WT_INIT_SCRIPT = """\
async () => {
  if (window.__wt) return JSON.stringify({status:'ready', proto: window.__wt.proto, termType: window.__wt.termType});

  // --- Terminal instance discovery ---
  const findTerminal = () => {
    const xtermEl = document.querySelector('.xterm');
    if (!xtermEl) return null;
    for (const key of Object.getOwnPropertyNames(window)) {
      try {
        const obj = window[key];
        if (obj && typeof obj === 'object' && typeof obj.onData === 'function'
            && typeof obj.write === 'function') return obj;
      } catch(e) {}
    }
    return null;
  };

  const term = findTerminal();
  if (!term && !document.querySelector('.xterm'))
    return JSON.stringify({error: 'NO_TERMINAL'});

  // --- WebSocket discovery ---
  const findWS = () => {
    for (const key of Object.getOwnPropertyNames(window)) {
      try {
        if (window[key] instanceof WebSocket && window[key].readyState === 1)
          return window[key];
      } catch(e) {}
    }
    return null;
  };

  // --- Protocol detection ---
  const ws = findWS();
  const url = ws?.url || '';
  const proto = typeof sendInput === 'function' ? 'ttyd'
    : url.includes('/wetty') ? 'wetty'
    : url.includes('/gotty') ? 'gotty'
    : (url.includes('/api/v1/') && url.includes('exec')) ? 'k8s'
    : 'generic';

  // --- Build send function ---
  const sender =
    (term && typeof term.input === 'function')
      ? (t) => term.input(t)
    : (typeof sendInput === 'function')
      ? (t) => sendInput(t)
    : ws ? ((proto === 'ttyd') ? (t) => {
          const e = new TextEncoder(), d = e.encode(t);
          const m = new Uint8Array(d.length + 1); m[0] = 0; m.set(d, 1);
          ws.send(m);
        }
        : (proto === 'gotty') ? (t) => ws.send('1' + t)
        : (proto === 'k8s') ? (t) => {
            const e = new TextEncoder(), d = e.encode(t);
            const m = new Uint8Array(d.length + 1); m[0] = 0; m.set(d, 1);
            ws.send(m);
          }
        : (t) => ws.send(t))
    : null;

  if (!sender) return JSON.stringify({error: 'NO_SENDER'});

  // --- Build reader ---
  const rows = document.querySelector('.xterm-rows');
  const reader = rows ? () => rows.innerText : () => document.body.innerText;

  // --- Register global helper ---
  window.__wt = {
    proto, termType: term ? 'xterm' : 'unknown', send: sender, read: reader,
    exec: (cmd, timeout=10000) => new Promise(resolve => {
      const tag = '__D_' + Math.random().toString(36).slice(2,7) + '__';
      sender(cmd + ' > /tmp/_o 2>&1; cat /tmp/_o; echo ' + tag + '\\n');
      const t0 = Date.now();
      const iv = setInterval(() => {
        const txt = reader();
        const idx = txt.lastIndexOf(tag);
        if (idx !== -1) {
          clearInterval(iv);
          const lines = txt.substring(0, idx).split('\\n');
          let s = lines.length - 1;
          for (let i = lines.length-1; i >= 0; i--) {
            if (lines[i].includes('cat /tmp/_o')) { s = i+1; break; }
          }
          resolve({ok:true, out: lines.slice(s).join('\\n').trim()});
        } else if (Date.now()-t0 > timeout) {
          clearInterval(iv);
          resolve({ok:false, out: '[TIMEOUT] ' + reader().split('\\n').slice(-15).join('\\n')});
        }
      }, 250);
    }),
    raw: (cmd, delay=1000) => new Promise(r => {
      sender(cmd + '\\n');
      setTimeout(() => r({ok:true, out: reader().split('\\n').slice(-8).join('\\n')}), delay);
    }),
    batch: async (cmds, timeout=8000) => {
      const r = {};
      for (const c of cmds) r[c] = await window.__wt.exec(c, timeout);
      return r;
    }
  };
  return JSON.stringify({status:'ready', proto: window.__wt.proto, termType: window.__wt.termType});
}"""


def build_wt_additional_context() -> str:
    """构建 navigate_page 成功后注入给 LLM 的 additionalContext。

    包含完整的 WT_INIT_SCRIPT 和使用说明。

    Returns:
        additionalContext 字符串
    """
    return (
        "页面已加载。请先用 take_snapshot 检查页面是否包含 web terminal"
        "（查找 xterm / terminal / console 相关元素）。\n"
        "如果发现 web terminal 元素，用下面的脚本初始化 `window.__wt`——"
        "将整段代码作为 evaluate_script 的 function 参数执行：\n\n"
        "```javascript\n"
        f"{WT_INIT_SCRIPT}\n"
        "```\n\n"
        "**返回值处理**：\n"
        '- `{"status":"ready", ...}` → 初始化成功，可用 `window.__wt.exec(cmd)` 执行命令\n'
        '- `{"error":"NO_TERMINAL"}` → 页面无 xterm 终端，等 2 秒后重试一次（xterm 可能还在渲染）\n'
        '- `{"error":"NO_SENDER"}` → 重试一次；仍失败则回退到 fill + press_key\n\n'
        "**初始化成功后执行命令**：\n"
        "```javascript\n"
        "async () => JSON.stringify(await window.__wt.exec('cmd'))\n"
        "```\n"
        "**批量执行**：\n"
        "```javascript\n"
        "async () => JSON.stringify(await window.__wt.batch(['id','uname -a','whoami']))\n"
        "```\n"
        "**Shell 状态（cd/export）**：\n"
        "```javascript\n"
        "async () => { await window.__wt.raw('cd /tmp'); return JSON.stringify(await window.__wt.exec('pwd')); }\n"
        "```"
    )


__all__ = [
    "WT_INIT_SCRIPT",
    "build_wt_additional_context",
]
