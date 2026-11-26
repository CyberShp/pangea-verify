import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { randomUUID } from 'node:crypto'
import { TopologyStore, adaptTopologyFile, normalizeTopology } from './topology.js'
import { startGatewaySession } from './harness.js'
import { KnowledgePack } from './knowledge.js'
import { indexPythonAutomation, saveCodeMap, scanSourceCli } from './code-index.js'

const PROTOCOL_VERSION = '2024-11-05'

const TOOL_DEFINITIONS = [
  {
    name: 'topology_list',
    description: '列出当前已保存的多节点靶场拓扑（已脱敏，不含明文凭据）',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'topology_get',
    description: '查看指定拓扑的节点角色、管理面禁区（protected）与靶场资源白名单（test_resources）',
    inputSchema: {
      type: 'object',
      properties: { topology_id: { type: 'string' } },
      required: ['topology_id'],
    },
  },
  {
    name: 'topology_adapt',
    description: '使用确定性 topo-adapter 脚本解析原始自动化 Topo 文件，校验规范并可选保存到本地拓扑库',
    inputSchema: {
      type: 'object',
      properties: {
        adapter_path: { type: 'string', description: '确定性 .mjs 转换器文件路径' },
        raw_file_path: { type: 'string', description: '原始 Topo 文件路径' },
        save: { type: 'boolean', description: '校验通过后是否持久化到 TopologyStore' },
      },
      required: ['adapter_path', 'raw_file_path'],
    },
  },
  {
    name: 'session_start',
    description: '启动一个受控多节点网关会话（默认锁在 PROBE_READONLY 物理只读态，全部操作记入 transcript.jsonl）',
    inputSchema: {
      type: 'object',
      properties: {
        topology_id: { type: 'string' },
        max_calls: { type: 'number' },
      },
      required: ['topology_id'],
    },
  },
  {
    name: 'session_status',
    description: '查询当前受控网关会话的阶段（probe_readonly / armed）、配额与已登记清理项',
    inputSchema: {
      type: 'object',
      properties: { session_id: { type: 'string' } },
      required: ['session_id'],
    },
  },
  {
    name: 'session_close',
    description: '关闭受控网关会话，并自动逆序执行所有尚未执行的已登记清理动作',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: { type: 'string' },
        run_cleanups: { type: 'boolean' },
      },
      required: ['session_id'],
    },
  },
  {
    name: 'gateway_register_cleanup',
    description: '登记对偶恢复命令（SSH 或 HTTP），合法登记后将物理阶段锁从 PROBE_READONLY 解锁至 ARMED',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: { type: 'string' },
        target: { type: 'string' },
        kind: { type: 'string', enum: ['ssh', 'http'] },
        command: { type: 'string' },
        method: { type: 'string' },
        path: { type: 'string' },
        json: { type: 'object' },
        description: { type: 'string' },
      },
      required: ['session_id', 'target'],
    },
  },
  {
    name: 'gateway_exec',
    description: '在受控网关的指定节点上执行 SSH 命令并返回真实 command_id',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: { type: 'string' },
        target: { type: 'string' },
        command: { type: 'string' },
        timeout_ms: { type: 'number' },
      },
      required: ['session_id', 'target', 'command'],
    },
  },
  {
    name: 'gateway_interactive',
    description: '在指定节点上执行交互式 PTY（expect/send 数组）并返回真实 command_id',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: { type: 'string' },
        target: { type: 'string' },
        exchanges: { type: 'array', items: { type: 'object' } },
      },
      required: ['session_id', 'target', 'exchanges'],
    },
  },
  {
    name: 'gateway_http',
    description: '通过受控网关调用节点管理面 HTTP/HTTPS REST API（底座代填凭据）并返回真实 command_id',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: { type: 'string' },
        target: { type: 'string' },
        method: { type: 'string' },
        path: { type: 'string' },
        query: { type: 'object' },
        json: { type: 'object' },
      },
      required: ['session_id', 'target', 'path'],
    },
  },
  {
    name: 'gateway_run_cleanups',
    description: '立即逆序执行当前会话所有待执行的已登记清理命令并返回清理 command_id',
    inputSchema: {
      type: 'object',
      properties: { session_id: { type: 'string' } },
      required: ['session_id'],
    },
  },
  {
    name: 'knowledge_catalog',
    description: '检索 Knowledge Pack 轻量二级目录（默认返回已转正卡片，驯化态可传 include_drafts=true）',
    inputSchema: {
      type: 'object',
      properties: {
        domain: { type: 'string' },
        source_module: { type: 'string' },
        role: { type: 'string' },
        keyword: { type: 'string' },
        include_drafts: { type: 'boolean' },
      },
    },
  },
  {
    name: 'knowledge_get_card',
    description: '按 card_id 读取完整原子能力卡内容',
    inputSchema: {
      type: 'object',
      properties: {
        card_id: { type: 'string' },
        allow_draft: { type: 'boolean' },
      },
      required: ['card_id'],
    },
  },
  {
    name: 'knowledge_save_draft',
    description: '保存参数化能力卡草稿（强制过闸门 1 去敏脱壳校验与闸门 2 对偶清理绑定校验）',
    inputSchema: {
      type: 'object',
      properties: {
        card: { type: 'object' },
        topology_id: { type: 'string', description: '用于反向检测硬编码 IP/盘符字面量的当前拓扑 ID' },
      },
      required: ['card'],
    },
  },
  {
    name: 'knowledge_promote_card',
    description: '持真机试跑会话的真实 command_ids 将草稿能力卡盖戳转正为 verified（强制过闸门 3）',
    inputSchema: {
      type: 'object',
      properties: {
        card_id: { type: 'string' },
        session_id: { type: 'string' },
        command_ids: { type: 'array', items: { type: 'string' } },
        firmware_hint: { type: 'string' },
        topology_id: { type: 'string' },
      },
      required: ['card_id', 'session_id', 'command_ids'],
    },
  },
  {
    name: 'knowledge_attest_card',
    description: '对暂无法现场实测的草稿卡片进行测试专家人工签字背书（human_attested）',
    inputSchema: {
      type: 'object',
      properties: {
        card_id: { type: 'string' },
        attested_by: { type: 'string' },
        reason: { type: 'string' },
        firmware_hint: { type: 'string' },
      },
      required: ['card_id', 'attested_by', 'reason'],
    },
  },
  {
    name: 'knowledge_feedback_read',
    description: '读取指定正式能力卡在无人值守跑批中记录的失配反馈日志',
    inputSchema: {
      type: 'object',
      properties: { card_id: { type: 'string' } },
      required: ['card_id'],
    },
  },
  {
    name: 'topology_save_adapter',
    description: '校验语法与 adaptTopology 导出并原子保存确定性 Topo 转换器至 knowledge-pack/topo-adapters/<id>.mjs',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: '适配器名称（小写字母、数字、点、连字符或下划线）' },
        code: { type: 'string', description: 'ESM JavaScript 源码，须导出 adaptTopology(rawInput, context)' },
      },
      required: ['id', 'code'],
    },
  },
  {
    name: 'knowledge_lint',
    description: '校验 Knowledge Pack 目录白名单洁净度以及 verified/attested 正式卡片防伪印章',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'code_index_python',
    description: '只读 AST 索引遗留 Python 自动化代码仓（零 import，提取类继承链、命令字符串与 Topo 解析器信号）',
    inputSchema: {
      type: 'object',
      properties: {
        root_dir: { type: 'string' },
        query: { type: 'string' },
        topo_only: { type: 'boolean' },
        max_files: { type: 'number' },
      },
      required: ['root_dir'],
    },
  },
  {
    name: 'code_scan_cli',
    description: '只读扫描被测源码仓中的 CLI 注册宏与打桩点定义，可选持久化到 Knowledge Pack code-maps/',
    inputSchema: {
      type: 'object',
      properties: {
        root_dir: { type: 'string' },
        save_map_name: { type: 'string' },
        max_files: { type: 'number' },
      },
      required: ['root_dir'],
    },
  },
]

export class TrainerMcpServer {
  constructor({ storePath, packDir, dataRoot } = {}) {
    if (!packDir) throw new Error('TrainerMcpServer 需要指定 packDir（Knowledge Pack 目录）')
    if (!dataRoot) throw new Error('TrainerMcpServer 需要指定 dataRoot（会话日志落盘目录）')
    this.store = new TopologyStore(storePath)
    this.pack = new KnowledgePack(packDir)
    this.dataRoot = path.resolve(dataRoot)
    this.sessions = new Map()
    this.transcriptBySession = new Map()
  }

  async callGateway(sessionId, route, payload) {
    const entry = this.sessions.get(sessionId)
    if (!entry) throw new Error(`未找到活动网关会话：${sessionId}（请先调用 session_start）`)
    const res = await fetch(`${entry.gateway.gatewayUrl}${route}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${entry.gateway.token}`,
      },
      body: JSON.stringify(payload || {}),
    })
    const data = await res.json()
    if (!res.ok) {
      const err = new Error(data?.error || `gateway HTTP ${res.status}`)
      err.payload = data
      throw err
    }
    return data
  }

  async executeTool(name, args = {}) {
    if (name === 'topology_list') {
      return { topologies: await this.store.list() }
    }
    if (name === 'topology_get') {
      const topo = await this.store.get(args.topology_id)
      if (!topo) throw new Error(`未找到拓扑：${args.topology_id}`)
      return topo
    }
    if (name === 'topology_adapt') {
      const raw = await readFile(path.resolve(args.raw_file_path), 'utf8')
      const adapted = await adaptTopologyFile(args.adapter_path, raw, { rawFilePath: args.raw_file_path })
      const normalized = await normalizeTopology(
        { ...adapted, source_adapter: path.basename(args.adapter_path) },
        { keyDir: this.store.keyDir, platform: this.store.platform },
      )
      if (args.save) {
        return { saved: true, topology: await this.store.save({ ...adapted, source_adapter: path.basename(args.adapter_path) }) }
      }
      return { saved: false, topology_id: normalized.id, nodes: Object.keys(normalized.nodes) }
    }
    if (name === 'session_start') {
      const resolved = await this.store.getResolved(args.topology_id)
      if (!resolved) throw new Error(`未找到拓扑：${args.topology_id}`)
      const sessionId = `train-${new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14)}-${randomUUID().slice(0, 6)}`
      const transcriptPath = path.join(this.dataRoot, 'trainer-sessions', sessionId, 'transcript.jsonl')
      const gateway = await startGatewaySession({
        sessionId,
        resolvedTopology: resolved,
        transcriptPath,
        maxCalls: Number.isInteger(args.max_calls) && args.max_calls > 0 ? args.max_calls : 80,
        initialPhase: 'probe_readonly',
        actorPhaseLabel: 'trainer',
      })
      this.sessions.set(sessionId, { gateway, topologyId: args.topology_id, transcriptPath })
      this.transcriptBySession.set(sessionId, transcriptPath)
      return {
        session_id: sessionId,
        topology_id: args.topology_id,
        phase: gateway.getPhase(),
        transcript_path: transcriptPath,
        nodes: Object.keys(resolved.nodes),
      }
    }
    if (name === 'session_status') {
      return await this.callGateway(args.session_id, '/status', {})
    }
    if (name === 'session_close') {
      const entry = this.sessions.get(args.session_id)
      if (!entry) throw new Error(`未找到活动网关会话：${args.session_id}`)
      const cleanup = await entry.gateway.close({ runCleanups: args.run_cleanups !== false })
      this.sessions.delete(args.session_id)
      return { closed: true, session_id: args.session_id, transcript_path: entry.transcriptPath, cleanup }
    }
    if (name === 'gateway_register_cleanup') {
      return await this.callGateway(args.session_id, '/register-cleanup', {
        target: args.target,
        kind: args.kind || 'ssh',
        ...(args.command ? { command: args.command } : {}),
        ...(args.method ? { method: args.method } : {}),
        ...(args.path ? { path: args.path } : {}),
        ...(args.json !== undefined ? { json: args.json } : {}),
        description: args.description || '',
      })
    }
    if (name === 'gateway_exec') {
      return await this.callGateway(args.session_id, '/exec', {
        target: args.target,
        command: args.command,
        ...(args.timeout_ms ? { timeout_ms: args.timeout_ms } : {}),
      })
    }
    if (name === 'gateway_interactive') {
      return await this.callGateway(args.session_id, '/interactive', {
        target: args.target,
        exchanges: args.exchanges,
      })
    }
    if (name === 'gateway_http') {
      return await this.callGateway(args.session_id, '/http', {
        target: args.target,
        method: args.method || 'GET',
        path: args.path,
        ...(args.query ? { query: args.query } : {}),
        ...(args.json !== undefined ? { json: args.json } : {}),
      })
    }
    if (name === 'gateway_run_cleanups') {
      return await this.callGateway(args.session_id, '/run-cleanups', {})
    }
    if (name === 'knowledge_catalog') {
      return {
        cards: await this.pack.queryCatalog({
          domain: args.domain || '',
          sourceModule: args.source_module || '',
          role: args.role || '',
          keyword: args.keyword || '',
          includeDrafts: Boolean(args.include_drafts),
        }),
      }
    }
    if (name === 'knowledge_get_card') {
      const card = await this.pack.getCard(args.card_id, { allowDraft: Boolean(args.allow_draft) })
      if (!card) throw new Error(`未找到能力卡：${args.card_id}`)
      return card
    }
    if (name === 'knowledge_save_draft') {
      const topo = args.topology_id ? await this.store.get(args.topology_id) : null
      return await this.pack.saveDraft(args.card, { topology: topo })
    }
    if (name === 'knowledge_promote_card') {
      const transcriptPath = this.transcriptBySession.get(args.session_id)
      if (!transcriptPath) throw new Error(`未找到会话「${args.session_id}」的真实 transcript 记录`)
      const topo = args.topology_id ? await this.store.get(args.topology_id) : null
      return await this.pack.promoteCard({
        cardId: args.card_id,
        transcriptPath,
        commandIds: args.command_ids || [],
        firmwareHint: args.firmware_hint || '',
        topology: topo,
      })
    }
    if (name === 'knowledge_attest_card') {
      return await this.pack.attestCard({
        cardId: args.card_id,
        attestedBy: args.attested_by,
        reason: args.reason,
        firmwareHint: args.firmware_hint || '',
      })
    }
    if (name === 'knowledge_feedback_read') {
      return { card_id: args.card_id, entries: await this.pack.readFeedback(args.card_id) }
    }
    if (name === 'topology_save_adapter') {
      return await this.pack.saveTopoAdapter({ id: args.id, code: args.code })
    }
    if (name === 'knowledge_lint') {
      return await this.pack.lint()
    }
    if (name === 'code_index_python') {
      return await indexPythonAutomation(args.root_dir, {
        query: args.query || '',
        topoOnly: Boolean(args.topo_only),
        maxFiles: args.max_files || 200,
      })
    }
    if (name === 'code_scan_cli') {
      const scanned = await scanSourceCli(args.root_dir, { maxFiles: args.max_files || 500 })
      let savedPath = ''
      if (args.save_map_name) {
        savedPath = await saveCodeMap(this.pack.root, args.save_map_name, scanned)
      }
      return { ...scanned, ...(savedPath ? { saved_path: savedPath } : {}) }
    }
    throw new Error(`未知 MCP 工具：${name}`)
  }

  async handleMessage(msg) {
    if (!msg || typeof msg !== 'object') return null
    const { id, method, params } = msg
    if (id === undefined || id === null) return null // JSON-RPC notification

    try {
      if (method === 'initialize') {
        return {
          jsonrpc: '2.0',
          id,
          result: {
            protocolVersion: PROTOCOL_VERSION,
            capabilities: { tools: {} },
            serverInfo: { name: 'pangea-verify', version: '0.1.0' },
          },
        }
      }
      if (method === 'ping') {
        return { jsonrpc: '2.0', id, result: {} }
      }
      if (method === 'tools/list') {
        return { jsonrpc: '2.0', id, result: { tools: TOOL_DEFINITIONS } }
      }
      if (method === 'tools/call') {
        const toolName = params?.name
        const toolArgs = params?.arguments || {}
        try {
          const data = await this.executeTool(toolName, toolArgs)
          return {
            jsonrpc: '2.0',
            id,
            result: {
              content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
              isError: false,
            },
          }
        } catch (toolError) {
          return {
            jsonrpc: '2.0',
            id,
            result: {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  error: toolError instanceof Error ? toolError.message : String(toolError),
                  ...(toolError?.payload ? { details: toolError.payload } : {}),
                }, null, 2),
              }],
              isError: true,
            },
          }
        }
      }
      return {
        jsonrpc: '2.0',
        id,
        error: { code: -32601, message: `Method not found: ${method}` },
      }
    } catch (error) {
      return {
        jsonrpc: '2.0',
        id,
        error: { code: -32603, message: error instanceof Error ? error.message : String(error) },
      }
    }
  }

  async dispose() {
    for (const entry of this.sessions.values()) {
      try { await entry.gateway.close({ runCleanups: true }) } catch {}
    }
    this.sessions.clear()
  }
}

export function serveMcpStdio(server, { input = process.stdin, output = process.stdout } = {}) {
  let buffer = Buffer.alloc(0)
  let framing = 'ndjson'

  const sendResponse = payload => {
    const json = JSON.stringify(payload)
    if (framing === 'content-length') {
      const len = Buffer.byteLength(json, 'utf8')
      output.write(`Content-Length: ${len}\r\n\r\n${json}`)
    } else {
      output.write(`${json}\n`)
    }
  }

  const dispatchMessage = async rawJson => {
    let msg
    try {
      msg = JSON.parse(rawJson)
    } catch {
      return
    }
    const reply = await server.handleMessage(msg)
    if (reply) sendResponse(reply)
  }

  const drainBuffer = () => {
    while (buffer.length > 0) {
      const prefix = buffer.subarray(0, Math.min(32, buffer.length)).toString('utf8')
      if (/^Content-Length:/i.test(prefix)) {
        framing = 'content-length'
        const sepIdx = buffer.indexOf('\r\n\r\n')
        if (sepIdx === -1) break
        const headerText = buffer.subarray(0, sepIdx).toString('utf8')
        const lenMatch = /Content-Length:\s*(\d+)/i.exec(headerText)
        if (!lenMatch) {
          buffer = buffer.subarray(sepIdx + 4)
          continue
        }
        const bodyLen = Number(lenMatch[1])
        const totalLen = sepIdx + 4 + bodyLen
        if (buffer.length < totalLen) break
        const body = buffer.subarray(sepIdx + 4, totalLen).toString('utf8')
        buffer = buffer.subarray(totalLen)
        void dispatchMessage(body)
      } else {
        const nlIdx = buffer.indexOf('\n')
        if (nlIdx === -1) break
        const line = buffer.subarray(0, nlIdx).toString('utf8').trim()
        buffer = buffer.subarray(nlIdx + 1)
        if (line) {
          framing = 'ndjson'
          void dispatchMessage(line)
        }
      }
    }
  }

  input.on('data', chunk => {
    buffer = Buffer.concat([buffer, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)])
    drainBuffer()
  })

  const cleanup = () => { void server.dispose() }
  input.once('end', cleanup)
  input.once('close', cleanup)
}
