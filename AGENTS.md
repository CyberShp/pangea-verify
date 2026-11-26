# pangea-verify 协作与边界说明

本项目是 PANGEA 独立解耦的真机动态核验与测试专家知识进化引擎（Node.js ESM）。中文沟通，代码符号、协议字段与路径保持原文。

## 1. 净室安全红线

- **100% 业务无关净室仓库**：本仓库严禁硬编码任何内网设备私有 CLI、内部自动化类名、真实环境 IP、账号密码或私有拓扑字段。测试统一使用本地回环 `ssh2.Server` / `node:http` 与脱敏模拟夹具。
- **不直接 `import` 外部遗留自动化代码**：内网运行期挂载的遗留 Python 测试仓仅允许静态只读蒸馏（提取裸命令与拓扑映射），或通过受控网关以独立子进程黑盒调用，禁止耦合进本引擎运行时。
- **知识资产外置**：运行期沉淀的 `topo-adapters`、源码命令映射与原子能力卡统一存放在外部挂载的明文 `Knowledge Pack` 目录（内网独立 Git 仓）中。

## 2. 铁律底座与 Agent 权限边界

- **受控底座不可由运行期 Agent 自改**：凭据加密代填、管理面禁区与靶场白名单校验（`safety-policy.js`）、阶段阀门（`PROBE_READONLY -> ARMED`）、`transcript.jsonl` 签名与结果强校验（`harness.js`）由确定性代码强制执行。
- **物理阶段锁**：在核验/试跑会话未调用 `register-cleanup` 登记合法对偶恢复动作前，网关保持 `probe_readonly` 状态，物理拒绝一切状态修改、控桩与破坏性靶场操作。
- **知识晋升四道闸门**：
  1. 拒绝残留当前环境真实 IP、主机名、密码及裸盘符（如 `/dev/sda`）的未参数化模板入库；
  2. `side_effect="mutating"` 能力卡必填 `precheck`、`execute`、`verify_effect`、`cleanup`；
  3. 晋升 `verified` 必须核验本地真实 `transcript.jsonl` 中的成功 `command_ids`；
  4. 无人值守跑批只读消费 `verified` / `attested` 卡片，异常仅追加 `feedback` 记账，禁止跑批中途自改正式卡片。
