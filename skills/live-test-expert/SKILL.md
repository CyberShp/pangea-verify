---
name: live-test-expert
description: 双态真机测试专家 Skill（驯化沉淀 + 受控真机核验）：支持零 import 静态蒸馏遗留 Python 自动化框架、确定性转换异构 Topo、经受控多节点 SSH/PTY/REST 网关（带物理只读锁、管理面保护与对偶清理）实测盖戳沉淀原子能力卡，以及跨环境无人值守真机核验。
---

# Live Test Expert（双态真机测试专家 Skill）

本 Skill 自包含受控多节点执行网关与四闸门知识进化引擎，**无需手工配置 MCP 服务器**，任意 Coding Agent 客户端加载本目录后直接调用内置 CLI（`node "<skill_dir>/bin/cli.mjs"`）即可运行。

## 核心铁律（违者底座直接拒收）

1. **绝不 `import` 或执行遗留 Python 自动化框架**：只用 `index-py` 做纯只读 AST 静态蒸馏，扒出底层 SSH/REST 裸命令、类继承链与 Topo 解析逻辑，学完即脱钩。
2. **绝不直接篡改 `knowledge-pack/`**：所有向知识包写入的卡片、适配器与代码索引必须走 `kp-draft` / `kp-promote` / `kp-attest` / `kp-save-adapter` / `index-cli` 正式命令，禁止绕过闸门手写文件；变更后用 `kp-lint` 校验洁癖与印章。
3. **不实测不转正**：口述命令、文档合集或代码扒出的模板先存草稿（`kp-draft`），必须经受控网关在靶场真机跑通执行与清理，凭 `transcript.jsonl` 真实 `command_ids` 调 `kp-promote` 转正为 `verified`。
4. **物理只读锁与对偶清理**：任何真机网关会话默认锁在 `probe_readonly` 阶段；执行任何状态变更、发包、挂桩或白名单网口/块设备操作前，必须先调用 `register-cleanup` 登记对偶恢复命令解锁 `armed`。

---

## 模式一：专家驯化流（Trainer —— 喂 Topo / 啃代码 / 聊天攒能力）

当测试工程师提供自动化 Topo、遗留 Python 自动化仓、命令合集或口述操作套路时执行：

1. **接入异构自动化 Topo（一次编写，后续 0 Token）**：
   - 先用 `index-py --root <legacy_py_dir> --topo-only true` 定位原框架的 Topo 解析文件；
   - 与测试员明确区分 `protected`（管理网口、系统盘）与 `test_resources`（业务数据口、`/dev/disk/by-id/...` 稳定盘路径、允许重启的进程）；
   - 编写标准 `adaptTopology(rawInput)` 转换器源码到临时文件，通过 `kp-save-adapter --pack <pack> --id <name> --code-file <tmp.mjs>` 过语法校验入库；
   - 用 `topo-adapt --store <store> --adapter <pack>/topo-adapters/<name>.mjs --raw-file <topo_file> --save true` 校验并加密入库。
2. **蒸馏原子能力卡（过闸门 1 去敏 + 闸门 2 对偶清理）**：
   - 先查 `kp-catalog --pack <pack> --include-drafts true` 避免重复建卡；
   - 如需参考代码：`index-py --root <legacy_py> --query <kw>` 查遗留封装，`index-cli --root <target_src> --pack <pack> --name <mod>` 扫被测源码 CLI 宏；
   - 将具体 IP、主机名、裸盘符参数化为 `${node.<role>.*}` / `${resource.*}`，补齐 `precheck / execute / verify_effect / cleanup` 四槽位，调用 `kp-draft --pack <pack> --card-file <tmp.json> --topo-file <redacted_topo.json>`。
3. **真机试跑与实测盖戳（过闸门 3）**：
   - 启动免 MCP 守护会话：`session-start --store <store> --topo-id <id> --data-root <data_root>`，拿到 `config_path` 与 `transcript_path`；
   - 在 `probe_readonly` 阶段跑 `precheck`（`exec` / `http --method GET`）；
   - 调 `register-cleanup` 解锁 `armed`，跑 `execute` 与 `verify_effect`，再调 `run-cleanups` 验证真机恢复；
   - 调 `kp-promote --pack <pack> --id <card_id> --transcript <transcript_path> --command-ids <cmd1,cmd2,cleanup_cmd>` 盖戳转正；
   - 调 `session-close --config <config_path>` 清理并退出守护进程，最后 `kp-lint --pack <pack>` 确认全库洁净。

---

## 模式二：受控真机核验流（Verifier —— 拿用例/风险上机拿铁证）

当需要验证具体测试用例或代码风险时执行：

1. **双路寻址（零向量库、不爆 Token）**：
   - 调 `kp-catalog --pack <pack>` 只读检索已转正（`verified` / `human_attested`）能力卡目录，按需 `kp-card --pack <pack> --id <id>` 读取详情；
   - 结合 `code-maps/` 中的白盒 CLI 与桩点索引拼装核验步骤。
2. **受控执行与刚性判定**：
   - 启动 `session-start` → 只读探活（缺工具或前置条件立即停机判 `blocked`）→ `register-cleanup` 解锁 `armed` → 下发激励与观测 → `session-close` 自动逆序恢复；
   - 输出四态结论（`confirmed | excluded | not_triggered | blocked`），每条非 `blocked` 结论必须附真实 `command_id`；打桩模式未观测到非零命中严禁判 `confirmed` 或 `excluded`；
   - 若某张老正式卡在新版本固件失效，**严禁跑批中途改卡**，仅调用 `kp-feedback --pack <pack> --id <card_id> --summary "<失配说明>"` 记账，留待驯化态升级。

详细字段与命令契约见 [references/contracts.md](references/contracts.md)。
