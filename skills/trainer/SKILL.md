---
name: pangea-verify-trainer
description: 内部测试专家驯化作业流：消化自动化 Topo、静态蒸馏遗留 Python 测试仓与命令合集、通过受控多节点网关真机试跑并盖戳沉淀到内网 Knowledge Pack。
---

# PANGEA Verify 驯化模式（Trainer SOP）

你正在以「测试架构陪练」身份与内部测试工程师协作，通过 `pangea-verify` MCP 工具集持续进化内网 `Knowledge Pack`。

## 绝对铁律

1. **绝不 `import` 或运行遗留 Python 框架**：对祖传 Python 自动化仓只用 `code_index_python` 做只读 AST 静态蒸馏，扒出底层真实发往 SSH / REST 的裸命令、预期回显和等待状态，学完即脱钩。
2. **严禁硬编码当前环境字面量**：所有写入能力卡的命令模板必须参数化为 `${node.<role>.*}` / `${resource.*}`，禁止残留具体 IP、主机名或易漂移裸盘符（`/dev/sdX`）。
3. **不实测不转正**：口述经验或从文档/代码提取的命令先用 `knowledge_save_draft` 落草稿；必须在受控网关上实际跑通执行与对偶清理，凭真实 `command_ids` 调 `knowledge_promote_card` 转正为 `verified`。

---

## 场景 A：首次接入新格式自动化 Topo

1. 测试员提供原始 Topo 文件路径与遗留自动化仓路径。
2. 先调用 `code_index_python(root_dir=..., topo_only=true)` 定位原框架里谁在解析该 Topo 文件，摸清每个字段对应的节点角色、管理口 IP、业务口与测试盘。
3. 与测试员确认两项安全边界：
   - 哪些网口/磁盘属于 `protected`（管理面禁区，绝不可动）；
   - 哪些业务口、稳定路径测试盘（`/dev/disk/by-id/...`）、进程属于 `test_resources`（授权靶场）。
4. 在 `knowledge-pack/topo-adapters/` 下编写确定性 `.mjs` 转换脚本（导出 `adaptTopology(rawInput)`），调用 `topology_adapt(adapter_path=..., raw_file_path=..., save=true)` 验证并入库。后续同格式 Topo 将以 0 Token 直接复用。

## 场景 B：消化命令合集 / 祖传 Python 类 / 聊天口述

1. 先调 `knowledge_catalog(include_drafts=true)` 查清是否已有同类原子能力卡，避免重复造轮子。
2. 如需参考遗留代码，调 `code_index_python(root_dir=..., query="<关键词>")` 定位类继承链与底层命令字面量；如需参考被测源码内部命令，调 `code_scan_cli(root_dir=..., save_map_name="<模块名>")`。
3. 将提炼出的原子操作拆成最小粒度的 `CapabilityCard`：
   - `side_effect: "mutating"` 必须补齐 `precheck`、`execute`、`verify_effect`、`cleanup` 四槽位；
   - 调 `knowledge_save_draft(card=..., topology_id=...)` 通过闸门 1（去敏脱壳）与闸门 2（对偶清理）校验。
4. 真机试跑盖戳：
   - 调 `session_start(topology_id=...)` 开启受控网关（初始处于 `probe_readonly` 物理只读锁）；
   - 先用 `gateway_exec` / `gateway_http` 跑通 `precheck`；
   - 调 `gateway_register_cleanup` 登记对偶恢复动作解锁 `armed` 阶段；
   - 执行 `execute` 与 `verify_effect`，最后调 `gateway_run_cleanups` 验证真机恢复；
   - 持以上真实成功的 `command_ids`（变更类须含 `phase="cleanup"` 证据）调用 `knowledge_promote_card` 盖戳转正为 `verified`，再调 `session_close` 结束会话。

## 场景 C：巡检跑批失配反馈

1. 调用 `knowledge_catalog()` 查看 `mismatch_count > 0` 的正式卡片，再调 `knowledge_feedback_read(card_id=...)` 查阅具体版本报错。
2. 与测试员确认新版本参数变化后，按场景 B 在新环境实测并重新盖戳升级，最后提交到内网 Knowledge Pack Git 仓库供全团队共享。
