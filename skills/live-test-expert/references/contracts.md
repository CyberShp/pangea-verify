# `live-test-expert` 契约速查

## 1. CLI 常用子命令（`node <skill_dir>/bin/cli.mjs <cmd>`）

| 分类 | 命令 | 作用 |
| :--- | :--- | :--- |
| 拓扑管理 | `topo-list --store <file>` | 列出已保存脱敏多节点拓扑 |
| | `topo-save --store <file> --topo-file <json>` | 加密保存新拓扑（校验管理口与稳定盘路径） |
| | `topo-adapt --store <file> --adapter <mjs> --raw-file <raw> [--save true]` | 用确定性适配器转换原始 Topo 文件 |
| 守护网关 | `session-start --store <file> --topo-id <id> --data-root <dir>` | 启动后台受控网关（初始 `probe_readonly`，默认 30min 空闲自动清理退出） |
| | `status / exec / bg-start / bg-read / bg-stop / interactive / http --config <.gateway.json>` | 在多节点靶场执行受控 SSH/PTY/HTTP 操作并签发 `command_id` |
| | `register-cleanup --config <.gateway.json> --target <node> [--cmd <c> \| --kind http --method DELETE --path <p>]` | 登记对偶清理并解锁 `armed` 阶段 |
| | `run-cleanups / session-close --config <.gateway.json>` | 逆序执行清理并关闭守护会话 |
| 知识进化 | `kp-catalog --pack <dir> [--domain d] [--module m] [--role r] [--q kw] [--include-drafts true]` | 二级目录检索原子能力卡 |
| | `kp-card --pack <dir> --id <id> [--allow-draft true]` | 读取单张完整能力卡 |
| | `kp-draft --pack <dir> --card-file <json> [--topo-file <json>]` | 保存参数化草稿（过闸门 1 去敏 + 闸门 2 清理绑定） |
| | `kp-promote --pack <dir> --id <id> --transcript <jsonl> --command-ids <c1,c2>` | 校验真实 `transcript.jsonl` 证据盖戳转正 `verified`（过闸门 3） |
| | `kp-attest --pack <dir> --id <id> --by <name> --reason <why>` | 测试专家人工签字背书 `human_attested` |
| | `kp-save-adapter --pack <dir> --id <name> --code-file <mjs>` | 语法校验并写入 `topo-adapters/<name>.mjs` |
| | `kp-feedback --pack <dir> --id <id> --summary <msg>` | 跑批只读模式记录版本失配反馈（过闸门 4） |
| | `kp-lint --pack <dir>` | 校验知识包白名单目录洁净度与正式卡防伪印章 |
| 静态蒸馏 | `index-py --root <dir> [--query kw] [--topo-only true]` | 零 `import` AST 索引遗留 Python 自动化框架 |
| | `index-cli --root <dir> [--pack <dir> --name <map>]` | 扫描被测源码 CLI 注册宏与打桩点 |

## 2. 原子能力卡 JSON 契约（`CapabilityCard`）

```json
{
  "id": "mp.port.flap",
  "title": "多路径业务口闪断",
  "domain": "multipath",
  "intent": "拉低主机业务数据口触发路径切换并恢复",
  "source_modules": ["src/multipath"],
  "required_roles": ["host"],
  "side_effect": "mutating",
  "precheck": "ip -br link show ${node.host.data_nics[0]}",
  "execute": "ip link set ${node.host.data_nics[0]} down",
  "verify_effect": "ip -br link show ${node.host.data_nics[0]}",
  "cleanup": "ip link set ${node.host.data_nics[0]} up"
}
```

## 3. Knowledge Pack 白名单目录规范（`kp-lint` 强检）

- 允许根目录文件：`catalog.json`、`README.md`、`.gitignore`
- 允许子目录：`.git/`、`cards/{drafts,attested,verified}/`、`topo-adapters/`、`code-maps/`、`feedback/`
- 任何超出上述白名单的野文件/野目录，或 `verified/` 中缺失 64 位 `proof.transcript_sha256` 的卡片均会被 `kp-lint` 判错拦截。
