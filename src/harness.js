import { createServer } from 'node:http'
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { appendFile, chmod, mkdir, readFile, readdir, rename, unlink, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { redactTopology } from './topology.js'
import { evaluateCommandSafety, evaluateHttpSafety } from './safety-policy.js'
import { SshTransport } from './transport-ssh.js'
import { HttpTransport } from './transport-http.js'

const CLI_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'cli.mjs')
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/
const ACTIVE_STATUSES = new Set(['preflight', 'running'])
const MAX_TRANSCRIPT_FIELD = 16_000

export const LIVE_VERDICT_VALUES = Object.freeze(['confirmed', 'excluded', 'not_triggered', 'blocked'])

const serviceError = (message, statusCode = 400) => Object.assign(new Error(message), { statusCode })
const shellSingleQuote = text => `'${String(text ?? '').replace(/'/g, "'\\''")}'`
const posixPath = value => String(value ?? '').replaceAll('\\', '/')

export function buildPidLookupCommand(processName) {
  const quoted = shellSingleQuote(String(processName ?? '').trim())
  return `pidof ${quoted} 2>/dev/null || pgrep -x ${quoted} 2>/dev/null`
}

function parsePidList(stdout) {
  return [...new Set(String(stdout || '').trim().split(/\s+/).filter(tok => /^\d+$/.test(tok)))]
}

function truncateOutput(text) {
  const value = String(text ?? '')
  if (value.length <= MAX_TRANSCRIPT_FIELD) return value
  return `${value.slice(0, 7500)}\n…（输出过长，中间已省略 ${value.length - 15000} 字符）…\n${value.slice(-7500)}`
}

function safeTokenEqual(provided, expected) {
  const a = Buffer.from(String(provided ?? ''), 'utf8')
  const b = Buffer.from(String(expected ?? ''), 'utf8')
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

async function writeAtomicJson(filePath, value) {
  const dir = path.dirname(filePath)
  await mkdir(dir, { recursive: true })
  const tmp = `${filePath}.${process.pid}.${randomUUID().slice(0, 8)}.tmp`
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
  await rename(tmp, filePath)
}

function readBodyJson(req, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let total = 0
    const chunks = []
    req.on('data', chunk => {
      total += chunk.length
      if (total > limit) {
        reject(serviceError('请求体过大', 413))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8').trim()
        resolve(raw ? JSON.parse(raw) : {})
      } catch {
        reject(serviceError('无效的 JSON 请求体', 400))
      }
    })
    req.on('error', reject)
  })
}

export function hasPositiveHitCount(hits) {
  const text = String(hits ?? '').trim()
  if (!text) return false
  const matches = text.match(/(?:=|:\s*|hit[s]?\s*[:=]?\s*)(\d+)/gi)
  if (matches && matches.length) {
    return matches.some(m => {
      const num = m.match(/(\d+)/)
      return num && Number(num[1]) > 0
    })
  }
  return /^\d+$/.test(text) && Number(text) > 0
}

export function validateVerificationResult(result, { targetKeys = [], validCommandIds = new Set(), requireNonZeroHits = false } = {}) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    return { ok: false, error: '结果 JSON 必须是对象' }
  }
  if (!Array.isArray(result.items) || result.items.length === 0) {
    return { ok: false, error: '结果 JSON 必须包含非空 items 数组' }
  }
  const expectedSet = new Set(targetKeys)
  const seen = new Set()
  const normalizedItems = []
  for (const item of result.items) {
    if (!item || typeof item !== 'object') return { ok: false, error: 'items 元素必须是对象' }
    const targetKey = typeof item.target_key === 'string' ? item.target_key.trim() : ''
    if (!targetKey) return { ok: false, error: 'items[].target_key 不能为空' }
    if (expectedSet.size > 0 && !expectedSet.has(targetKey)) {
      return { ok: false, error: `items[].target_key「${targetKey}」不在本次核验目标列表中` }
    }
    if (seen.has(targetKey)) return { ok: false, error: `items[].target_key「${targetKey}」重复` }
    seen.add(targetKey)
    const verdict = typeof item.verdict === 'string' ? item.verdict.trim() : ''
    if (!LIVE_VERDICT_VALUES.includes(verdict)) {
      return { ok: false, error: `items[${targetKey}].verdict 无效（须为 ${LIVE_VERDICT_VALUES.join(' / ')}）` }
    }
    const hits = typeof item.hits === 'string' ? item.hits.trim() : ''
    if (requireNonZeroHits && (verdict === 'confirmed' || verdict === 'excluded') && !hasPositiveHitCount(hits)) {
      return { ok: false, error: `items[${targetKey}] 在打桩核验模式下未观测到非零桩命中（hits="${hits || '空'}"），不得判为 ${verdict}；请补充真实命中计数或改判 not_triggered` }
    }
    const evidenceIds = Array.isArray(item.evidence_command_ids)
      ? [...new Set(item.evidence_command_ids.map(v => typeof v === 'string' ? v.trim() : '').filter(Boolean))]
      : []
    if (verdict !== 'blocked' && evidenceIds.length === 0) {
      return { ok: false, error: `items[${targetKey}] 给出 ${verdict} 结论时必须提供至少一条真实 evidence_command_ids` }
    }
    for (const cmdId of evidenceIds) {
      if (!validCommandIds.has(cmdId)) {
        return { ok: false, error: `items[${targetKey}] 引用了不存在的 command_id「${cmdId}」（必须引用宿主网关实际返回的 command_id）` }
      }
    }
    normalizedItems.push({
      target_key: targetKey,
      verdict,
      hits,
      evidence_command_ids: evidenceIds,
      observed_behavior: typeof item.observed_behavior === 'string' ? item.observed_behavior.trim() : '',
      cleanup_verified: item.cleanup_verified === true,
      notes: typeof item.notes === 'string' ? item.notes.trim() : '',
    })
  }
  for (const key of expectedSet) {
    if (!seen.has(key)) return { ok: false, error: `缺少目标「${key}」的核验结论` }
  }
  return {
    ok: true,
    value: {
      summary: typeof result.summary === 'string' ? result.summary.trim() : '',
      items: normalizedItems,
    },
  }
}

export async function startGatewaySession({
  sessionId = `gw-${randomUUID().slice(0, 8)}`,
  resolvedTopology,
  transcriptPath,
  gatewayConfigPath = '',
  maxCalls = 60,
  initialPhase = 'probe_readonly',
  actorPhaseLabel = 'worker',
  signal = null,
  onStateChange = null,
} = {}) {
  if (!resolvedTopology?.nodes) throw new Error('resolvedTopology 不能为空')
  if (!transcriptPath) throw new Error('transcriptPath 不能为空')
  await mkdir(path.dirname(transcriptPath), { recursive: true })

  const ssh = new SshTransport(resolvedTopology)
  const httpTransport = new HttpTransport(resolvedTopology)
  const validCommandIds = new Set()
  const registeredCleanups = []
  let seq = 0
  let callsUsed = 0
  let phase = initialPhase === 'armed' ? 'armed' : 'probe_readonly'
  const token = randomBytes(32).toString('hex')

  const requireNode = target => {
    const id = String(target || '').trim()
    const node = resolvedTopology.nodes?.[id]
    if (!node) throw serviceError(`未知拓扑节点「${id}」（可用节点：${Object.keys(resolvedTopology.nodes).join(', ')}）`, 400)
    return node
  }

  const appendTranscript = async entry => {
    seq += 1
    const commandId = `cmd-${String(seq).padStart(4, '0')}`
    validCommandIds.add(commandId)
    const signed = {
      command_id: commandId,
      session_id: sessionId,
      seq,
      at: new Date().toISOString(),
      ...entry,
    }
    await appendFile(transcriptPath, `${JSON.stringify(signed)}\n`, 'utf8')
    return signed
  }

  const execSshInternal = async (target, command, { timeoutMs = 60_000, enforceSafety = true, safetyPhase = phase, phaseLabel = actorPhaseLabel, execSignal = signal } = {}) => {
    const node = requireNode(target)
    if (enforceSafety) {
      const check = evaluateCommandSafety(command, { phase: safetyPhase, node })
      if (check.blocked) {
        const signed = await appendTranscript({
          phase: phaseLabel,
          gate_phase: safetyPhase,
          target: node.id,
          kind: 'exec',
          command,
          blocked: true,
          code: check.code,
          success: false,
          exit_code: null,
          duration_ms: 0,
          stdout: '',
          stderr: '',
          error: check.reason,
        })
        return signed
      }
    }
    const res = await ssh.exec(node.id, command, { timeoutMs, signal: execSignal })
    return await appendTranscript({
      phase: phaseLabel,
      gate_phase: safetyPhase,
      target: node.id,
      kind: 'exec',
      command,
      blocked: false,
      success: Boolean(res.success),
      exit_code: res.exit_code,
      timed_out: Boolean(res.timed_out),
      duration_ms: res.duration_ms ?? 0,
      stdout: truncateOutput(res.stdout),
      stderr: truncateOutput(res.stderr),
      ...(res.error ? { error: res.error } : {}),
    })
  }

  const execHttpInternal = async (target, reqSpec, { enforceSafety = true, safetyPhase = phase, phaseLabel = actorPhaseLabel, execSignal = signal } = {}) => {
    const node = requireNode(target)
    const method = String(reqSpec.method || 'GET').trim().toUpperCase()
    const reqPath = String(reqSpec.path || '/').trim()
    if (enforceSafety) {
      const check = evaluateHttpSafety({ method, path: reqPath }, { phase: safetyPhase, node })
      if (check.blocked) {
        return await appendTranscript({
          phase: phaseLabel,
          gate_phase: safetyPhase,
          target: node.id,
          kind: 'http',
          method,
          path: reqPath,
          blocked: true,
          code: check.code,
          success: false,
          status_code: null,
          duration_ms: 0,
          body: '',
          error: check.reason,
        })
      }
    }
    const res = await httpTransport.request(node.id, { ...reqSpec, method, path: reqPath, signal: execSignal })
    return await appendTranscript({
      phase: phaseLabel,
      gate_phase: safetyPhase,
      target: node.id,
      kind: 'http',
      method,
      path: reqPath,
      blocked: false,
      success: Boolean(res.success),
      status_code: res.status_code,
      timed_out: Boolean(res.timed_out),
      duration_ms: res.duration_ms ?? 0,
      body: truncateOutput(res.body),
      ...(res.json !== undefined ? { json: res.json } : {}),
      ...(res.error ? { error: res.error } : {}),
    })
  }

  const executeRegisteredCleanups = async ({ onlyPending = true } = {}) => {
    const steps = []
    let allOk = true
    const items = [...registeredCleanups].reverse()
    for (const item of items) {
      if (onlyPending && item.executed) continue
      try {
        let res
        if (item.kind === 'http') {
          res = await execHttpInternal(item.target, item.http_request, {
            enforceSafety: true,
            safetyPhase: 'armed',
            phaseLabel: 'cleanup',
            execSignal: null,
          })
        } else {
          res = await execSshInternal(item.target, item.command, {
            timeoutMs: 30_000,
            enforceSafety: true,
            safetyPhase: 'armed',
            phaseLabel: 'cleanup',
            execSignal: null,
          })
        }
        item.executed = true
        steps.push({
          kind: item.kind,
          target: item.target,
          description: item.description,
          command_id: res.command_id,
          ok: Boolean(res.success),
          ...(res.exit_code !== undefined ? { exit_code: res.exit_code } : {}),
          ...(res.status_code !== undefined ? { status_code: res.status_code } : {}),
          ...(res.error ? { error: res.error } : {}),
        })
        if (!res.success) allOk = false
      } catch (error) {
        allOk = false
        steps.push({
          kind: item.kind,
          target: item.target,
          description: item.description,
          ok: false,
          error: error.message,
        })
      }
    }
    return { status: allOk ? 'ok' : 'failed', steps }
  }

  const server = createServer(async (req, res) => {
    const respond = (code, payload) => {
      res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(`${JSON.stringify(payload)}\n`)
    }
    try {
      if (req.method !== 'POST') return respond(405, { error: 'method-not-allowed' })
      const auth = String(req.headers.authorization || '')
      if (!auth.startsWith('Bearer ') || !safeTokenEqual(auth.slice(7), token)) {
        return respond(401, { error: 'unauthorized' })
      }
      const body = await readBodyJson(req)
      const route = new URL(req.url || '/', 'http://127.0.0.1').pathname

      if (route === '/status') {
        return respond(200, {
          ok: true,
          session_id: sessionId,
          phase,
          calls_used: callsUsed,
          max_calls: maxCalls,
          registered_cleanups_count: registeredCleanups.length,
          nodes: Object.fromEntries(Object.entries(resolvedTopology.nodes).map(([id, n]) => [id, {
            role: n.role,
            has_ssh: Boolean(n.ssh),
            has_http: Boolean(n.http),
          }])),
        })
      }

      if (route === '/register-cleanup') {
        const node = requireNode(body.target)
        const kind = body.kind === 'http' ? 'http' : 'ssh'
        if (kind === 'http') {
          if (!node.http) return respond(400, { error: `节点「${node.id}」未配置 HTTP 通道` })
          const method = String(body.method || 'DELETE').trim().toUpperCase()
          const reqPath = String(body.path || '').trim()
          if (!reqPath) return respond(400, { error: 'HTTP cleanup 必须指定 path' })
          const check = evaluateHttpSafety({ method, path: reqPath }, { phase: 'armed', node })
          if (check.blocked) return respond(403, { blocked: true, code: check.code, error: check.reason })
          registeredCleanups.push({
            kind: 'http',
            target: node.id,
            http_request: { method, path: reqPath, ...(body.json !== undefined ? { json: body.json } : {}), ...(body.body !== undefined ? { body: body.body } : {}) },
            description: String(body.description || '').trim(),
            registered_at: new Date().toISOString(),
            executed: false,
          })
        } else {
          if (!node.ssh) return respond(400, { error: `节点「${node.id}」未配置 SSH 通道` })
          const cmd = String(body.command || '').trim()
          if (!cmd) return respond(400, { error: 'cleanup command 不能为空' })
          const check = evaluateCommandSafety(cmd, { phase: 'armed', node })
          if (check.blocked) return respond(403, { blocked: true, code: check.code, error: check.reason })
          registeredCleanups.push({
            kind: 'ssh',
            target: node.id,
            command: cmd,
            description: String(body.description || '').trim(),
            registered_at: new Date().toISOString(),
            executed: false,
          })
        }
        if (phase === 'probe_readonly') {
          phase = 'armed'
        }
        await onStateChange?.({ phase, callsUsed, registeredCleanups: [...registeredCleanups] })
        return respond(200, { ok: true, phase, count: registeredCleanups.length })
      }

      if (route === '/run-cleanups') {
        const report = await executeRegisteredCleanups({ onlyPending: body.only_pending !== false })
        await onStateChange?.({ phase, callsUsed, registeredCleanups: [...registeredCleanups] })
        return respond(200, { ok: report.status === 'ok', ...report })
      }

      if (['/exec', '/bg-start', '/interactive', '/http'].includes(route)) {
        if (callsUsed >= maxCalls) {
          return respond(429, { error: `已达到单次会话网关调用上限（${maxCalls} 次），请立即基于已有真实证据收口` })
        }
        callsUsed += 1
        await onStateChange?.({ phase, callsUsed, registeredCleanups: [...registeredCleanups] })
      }

      if (route === '/exec') {
        const clampedTimeout = Math.min(Math.max(Number(body.timeout_ms) || 60_000, 1000), 180_000)
        const signed = await execSshInternal(body.target, String(body.command || ''), { timeoutMs: clampedTimeout })
        return respond(signed.blocked ? 403 : 200, signed)
      }

      if (route === '/bg-start') {
        const node = requireNode(body.target)
        const cmd = String(body.command || '')
        const check = evaluateCommandSafety(cmd, { phase, node })
        if (check.blocked) {
          const signed = await appendTranscript({
            phase: actorPhaseLabel,
            gate_phase: phase,
            target: node.id,
            kind: 'bg-start',
            command: cmd,
            blocked: true,
            code: check.code,
            success: false,
            exit_code: null,
            duration_ms: 0,
            stdout: '',
            stderr: '',
            error: check.reason,
          })
          return respond(403, signed)
        }
        const job = await ssh.startBackground(node.id, cmd, { ownerId: sessionId })
        const signed = await appendTranscript({
          phase: actorPhaseLabel,
          gate_phase: phase,
          target: node.id,
          kind: 'bg-start',
          command: cmd,
          job_id: job.job_id,
          blocked: false,
          success: true,
          exit_code: job.exit_code,
          duration_ms: 0,
          stdout: truncateOutput(job.stdout),
          stderr: truncateOutput(job.stderr),
        })
        return respond(200, { ...job, command_id: signed.command_id })
      }

      if (route === '/bg-read') {
        const job = await ssh.readBackground(String(body.job_id || ''), Number(body.wait_ms) || 0)
        const signed = await appendTranscript({
          phase: actorPhaseLabel,
          gate_phase: phase,
          target: job.target,
          kind: 'bg-read',
          job_id: job.job_id,
          blocked: false,
          success: !job.error,
          exit_code: job.exit_code,
          duration_ms: 0,
          stdout: truncateOutput(job.stdout),
          stderr: truncateOutput(job.stderr),
        })
        return respond(200, { ...job, command_id: signed.command_id })
      }

      if (route === '/bg-stop') {
        const job = await ssh.stopBackground(String(body.job_id || ''))
        const signed = await appendTranscript({
          phase: actorPhaseLabel,
          gate_phase: phase,
          target: job.target,
          kind: 'bg-stop',
          job_id: job.job_id,
          blocked: false,
          success: true,
          exit_code: job.exit_code,
          duration_ms: 0,
          stdout: truncateOutput(job.stdout),
          stderr: truncateOutput(job.stderr),
        })
        return respond(200, { ...job, command_id: signed.command_id })
      }

      if (route === '/interactive') {
        const node = requireNode(body.target)
        const exchanges = Array.isArray(body.exchanges) ? body.exchanges : []
        for (const ex of exchanges) {
          if (ex?.send === undefined || ex?.send === null) continue
          const check = evaluateCommandSafety(ex.send, { phase, node })
          if (check.blocked) {
            const signed = await appendTranscript({
              phase: actorPhaseLabel,
              gate_phase: phase,
              target: node.id,
              kind: 'interactive',
              command: String(ex.send || ''),
              blocked: true,
              code: check.code,
              success: false,
              exit_code: null,
              duration_ms: 0,
              stdout: '',
              stderr: '',
              error: check.reason,
            })
            return respond(403, signed)
          }
        }
        const resInteractive = await ssh.interactive(node.id, exchanges, { signal })
        const signed = await appendTranscript({
          phase: actorPhaseLabel,
          gate_phase: phase,
          target: node.id,
          kind: 'interactive',
          command: exchanges.map(e => e.send ?? '<wait>').join(' -> '),
          blocked: false,
          success: Boolean(resInteractive.success),
          exit_code: resInteractive.exit_code,
          duration_ms: resInteractive.duration_ms ?? 0,
          stdout: truncateOutput(resInteractive.stdout),
          stderr: truncateOutput(resInteractive.stderr),
          ...(resInteractive.error ? { error: resInteractive.error } : {}),
        })
        return respond(200, { ...resInteractive, command_id: signed.command_id })
      }

      if (route === '/http') {
        const clampedTimeout = Math.min(Math.max(Number(body.timeout_ms) || 30_000, 1000), 120_000)
        const signed = await execHttpInternal(body.target, {
          method: body.method || 'GET',
          path: body.path || '/',
          query: body.query,
          headers: body.headers,
          json: body.json,
          body: body.body,
          expected_statuses: body.expected_statuses,
          timeoutMs: clampedTimeout,
        })
        return respond(signed.blocked ? 403 : 200, signed)
      }

      return respond(404, { error: 'not-found' })
    } catch (error) {
      return respond(error.statusCode ?? 400, { error: error instanceof Error ? error.message : String(error) })
    }
  })

  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const gatewayUrl = `http://127.0.0.1:${server.address().port}`

  if (gatewayConfigPath) {
    await mkdir(path.dirname(gatewayConfigPath), { recursive: true })
    await writeFile(gatewayConfigPath, `${JSON.stringify({ url: gatewayUrl, token, session_id: sessionId })}\n`, { encoding: 'utf8', mode: 0o600 })
    try { await chmod(gatewayConfigPath, 0o600) } catch {}
  }

  let closed = false
  return {
    sessionId,
    gatewayUrl,
    token,
    transcriptPath,
    gatewayConfigPath,
    validCommandIds,
    getPhase: () => phase,
    getCallsUsed: () => callsUsed,
    getRegisteredCleanups: () => [...registeredCleanups],
    execInternalSsh: execSshInternal,
    execInternalHttp: execHttpInternal,
    runCleanups: executeRegisteredCleanups,
    async close({ runCleanups = true } = {}) {
      if (closed) return null
      closed = true
      if (gatewayConfigPath) {
        try { await unlink(gatewayConfigPath) } catch {}
      }
      try { server.closeAllConnections?.() } catch {}
      await new Promise(resolve => server.close(() => resolve()))
      try { await ssh.disposeOwner(sessionId) } catch {}
      let cleanupReport = null
      if (runCleanups && registeredCleanups.length > 0) {
        cleanupReport = await executeRegisteredCleanups({ onlyPending: true })
      }
      await ssh.closeAll()
      return cleanupReport
    },
  }
}

export function buildVerificationPrompt({ inputPath, outputPath, cliPath = CLI_PATH, configPath, maxGatewayCalls = 40 }) {
  const cli = `node "${posixPath(cliPath)}"`
  const cfgFlag = `--config "${posixPath(configPath)}"`
  return [
    '你正在执行 pangea-verify 多节点真机核验任务。所有远端 SSH 与管理面 REST 操作必须通过受控网关 CLI 执行，严禁尝试直连或读取凭据。',
    `任务输入 JSON：${posixPath(inputPath)}（含多节点拓扑角色与白名单、Stage-0 基线、待核验目标及已匹配的 Knowledge Pack 原子能力目录）。`,
    `最终结果 JSON 写入路径：${posixPath(outputPath)}。`,
    '',
    `网关物理阀门纪律（总调用上限 ${maxGatewayCalls} 次）：`,
    '1. 会话初始处于 PROBE_READONLY（物理只读锁）阶段，仅允许执行只读探活（SSH 查询命令、HTTP GET）。',
    '2. 在执行任何状态变更、发包激励、挂桩或白名单网卡/块设备操作前，必须先调用 register-cleanup 登记对偶恢复命令，网关才会解锁进入 ARMED 阶段：',
    `   ${cli} register-cleanup ${cfgFlag} --target <node_id> --cmd "<恢复命令>" --desc "<说明>"`,
    `   ${cli} register-cleanup ${cfgFlag} --target <node_id> --kind http --method DELETE --path "/api/..." --desc "<说明>"`,
    '3. 可用执行命令：',
    `   ${cli} status ${cfgFlag}`,
    `   ${cli} exec ${cfgFlag} --target <node_id> --cmd "<命令>" [--timeout-ms 60000]`,
    `   ${cli} bg-start ${cfgFlag} --target <node_id> --cmd "<后台命令>"`,
    `   ${cli} bg-read ${cfgFlag} --job-id "<job_id>" [--wait-ms 2000]`,
    `   ${cli} bg-stop ${cfgFlag} --job-id "<job_id>"`,
    `   ${cli} interactive ${cfgFlag} --target <node_id> --exchanges-file "<json路径>"`,
    `   ${cli} http ${cfgFlag} --target <node_id> --method GET|POST|PUT|DELETE --path "/api/..." [--json-file "<json路径>"]`,
    `   ${cli} run-cleanups ${cfgFlag}`,
    '',
    '输出要求：每个非 blocked 结论必须引用真实 command_id；打桩模式下未观测到 hits > 0 严禁判为 confirmed 或 excluded（须判 not_triggered）。',
  ].join('\n')
}

export class VerificationHarness {
  constructor({ topologies, runWorker = null, maxGatewayCalls = null } = {}) {
    this.topologies = topologies
    this.runWorker = runWorker
    this.maxGatewayCalls = Number.isInteger(maxGatewayCalls) && maxGatewayCalls > 0 ? maxGatewayCalls : null
    this.active = new Map()
    this.lockedEndpoints = new Map()
  }

  getLocks() {
    return Object.fromEntries([...this.lockedEndpoints.entries()].map(([k, v]) => [k, { ...v }]))
  }

  acquireLocks(topology, verifyId) {
    const keys = new Set([`topo:${topology.id}`])
    for (const node of Object.values(topology.nodes || {})) {
      if (node.role === 'jump') continue
      if (node.ssh?.ip) keys.add(`ssh:${node.ssh.ip}:${node.ssh.port ?? 22}`)
      if (node.http?.base_url) keys.add(`http:${node.http.base_url}`)
    }
    for (const key of keys) {
      const holder = this.lockedEndpoints.get(key)
      if (holder && holder.verify_id !== verifyId) {
        throw serviceError(`拓扑资源「${key}」正被核验任务「${holder.verify_id}」占用`, 409)
      }
    }
    const info = { verify_id: verifyId, topology_id: topology.id, topology_name: topology.name, started_at: new Date().toISOString() }
    for (const key of keys) this.lockedEndpoints.set(key, info)
    return [...keys]
  }

  releaseLocks(keys, verifyId) {
    for (const key of keys || []) {
      if (this.lockedEndpoints.get(key)?.verify_id === verifyId) {
        this.lockedEndpoints.delete(key)
      }
    }
  }

  taskRoot(dataRoot) {
    return path.join(path.resolve(dataRoot), '.pangea-verify', 'runs')
  }

  taskDir(dataRoot, verifyId) {
    if (!ID_RE.test(verifyId || '') || verifyId === '.' || verifyId === '..') {
      throw serviceError('无效的核验任务 ID')
    }
    return path.join(this.taskRoot(dataRoot), verifyId)
  }

  recordFile(dataRoot, verifyId) {
    return path.join(this.taskDir(dataRoot, verifyId), 'record.json')
  }

  transcriptFile(dataRoot, verifyId) {
    return path.join(this.taskDir(dataRoot, verifyId), 'transcript.jsonl')
  }

  async saveRecord(dataRoot, record) {
    record.updated_at = new Date().toISOString()
    await writeAtomicJson(this.recordFile(dataRoot, record.id), record)
    return record
  }

  async readRecord(dataRoot, verifyId) {
    const file = this.recordFile(dataRoot, verifyId)
    const activeKey = `${path.resolve(dataRoot)}\0${verifyId}`
    let record
    try {
      record = JSON.parse(await readFile(file, 'utf8'))
    } catch (error) {
      if (error?.code === 'ENOENT') throw serviceError(`未找到核验任务：${verifyId}`, 404)
      return { id: verifyId, status: 'unreadable', error: error.message }
    }
    if (ACTIVE_STATUSES.has(record.status) && !this.active.has(activeKey)) {
      record = { ...record, status: 'interrupted', error: record.error || '宿主进程重启，原核验任务已中断' }
      try { await writeAtomicJson(file, record) } catch {}
    }
    return record
  }

  async readTranscript(dataRoot, verifyId) {
    try {
      const raw = await readFile(this.transcriptFile(dataRoot, verifyId), 'utf8')
      return raw.split(/\r?\n/).filter(Boolean).map(line => {
        try { return JSON.parse(line) } catch { return null }
      }).filter(Boolean)
    } catch (error) {
      if (error?.code === 'ENOENT') return []
      throw error
    }
  }

  async list(dataRoot) {
    let entries
    try {
      entries = await readdir(this.taskRoot(dataRoot), { withFileTypes: true })
    } catch (error) {
      if (error?.code === 'ENOENT') return []
      throw error
    }
    const items = []
    for (const entry of entries) {
      if (!entry.isDirectory() || !ID_RE.test(entry.name)) continue
      items.push(await this.readRecord(dataRoot, entry.name))
    }
    return items.sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')))
  }

  async runPreflight({ record, resolvedTopology, session, signal }) {
    const checks = []
    const commandIds = []
    for (const [nodeId, node] of Object.entries(resolvedTopology.nodes)) {
      if (node.ssh) {
        const res = await session.execInternalSsh(nodeId, 'echo PANGEA_VERIFY_PREFLIGHT_OK', {
          timeoutMs: 15_000,
          enforceSafety: false,
          safetyPhase: 'preflight',
          phaseLabel: 'preflight',
          execSignal: signal,
        })
        commandIds.push(res.command_id)
        const ok = Boolean(res.success && /PANGEA_VERIFY_PREFLIGHT_OK/.test(res.stdout || ''))
        checks.push({ kind: 'ssh', target: nodeId, ok, command_id: res.command_id, detail: ok ? 'SSH 连通正常' : (res.error || res.stderr || `exit ${res.exit_code}`) })
        if (!ok) {
          return { ok: false, error: `节点「${nodeId}」SSH 预检失败：${res.error || res.stderr || `exit ${res.exit_code}`}`, checks, command_ids: commandIds, baseline: null }
        }
      }
    }

    const defaultController = Object.values(resolvedTopology.nodes).find(n => n.role === 'controller' && n.ssh)
    const targetNodeId = record.target_node || defaultController?.id || ''
    const targetProcess = record.target_process || (targetNodeId ? resolvedTopology.nodes[targetNodeId]?.ssh?.default_process || '' : '')
    const baseline = {
      target_node: targetNodeId,
      process: targetProcess,
      pid: record.target_pid || '',
      binary_path: record.target_binary || '',
    }

    if (targetNodeId && resolvedTopology.nodes[targetNodeId]?.ssh && !baseline.pid && baseline.process) {
      const pidRes = await session.execInternalSsh(targetNodeId, buildPidLookupCommand(baseline.process), {
        timeoutMs: 15_000,
        enforceSafety: false,
        safetyPhase: 'preflight',
        phaseLabel: 'preflight',
        execSignal: signal,
      })
      commandIds.push(pidRes.command_id)
      const pids = parsePidList(pidRes.stdout)
      if (pids.length === 1) baseline.pid = pids[0]
      else if (pids.length > 1) baseline.candidate_pids = pids
    }

    if (record.mode === 'fault_injection' && record.marker_strings.length > 0) {
      if (!targetNodeId || !resolvedTopology.nodes[targetNodeId]?.ssh) {
        return { ok: false, error: '打桩核验模式缺少可执行二进制验包的目标 SSH 节点（target_node）', checks, command_ids: commandIds, baseline }
      }
      let verifyTarget = baseline.binary_path
      if (!verifyTarget && baseline.candidate_pids?.length > 1) {
        return { ok: false, error: `节点「${targetNodeId}」存在多个同名进程「${baseline.process}」（PID: ${baseline.candidate_pids.join(', ')}），请显式指定 target_pid 或 target_binary`, checks, command_ids: commandIds, baseline }
      }
      if (!verifyTarget && baseline.pid) verifyTarget = `/proc/${baseline.pid}/exe`
      if (!verifyTarget) {
        return { ok: false, error: 'Stage-0 预检无法确定目标运行二进制路径', checks, command_ids: commandIds, baseline }
      }
      baseline.binary_path = verifyTarget
      const missing = []
      for (const marker of record.marker_strings) {
        const cmd = `grep -aFq -- ${shellSingleQuote(marker)} ${shellSingleQuote(verifyTarget)}`
        const res = await session.execInternalSsh(targetNodeId, cmd, {
          timeoutMs: 20_000,
          enforceSafety: false,
          safetyPhase: 'preflight',
          phaseLabel: 'preflight',
          execSignal: signal,
        })
        commandIds.push(res.command_id)
        if (res.exit_code !== 0 && res.exit_code !== 1) {
          return { ok: false, error: `Stage-0 无法读取目标二进制 ${verifyTarget}：${res.stderr || res.error}`, checks, command_ids: commandIds, baseline }
        }
        const ok = res.exit_code === 0
        checks.push({ kind: 'marker', target: targetNodeId, marker, binary: verifyTarget, ok, command_id: res.command_id })
        if (!ok) missing.push(marker)
      }
      if (missing.length > 0) {
        return { ok: false, error: `Stage-0 验包失败：${verifyTarget} 缺少打桩标记（${missing.join('、')}）`, missing_markers: missing, checks, command_ids: commandIds, baseline }
      }
    }

    return { ok: true, checks, command_ids: commandIds, baseline }
  }

  async runTask(input = {}) {
    const {
      dataRoot,
      cwd = process.cwd(),
      name = '',
      mode = 'direct_case',
      topology_id: topologyId,
      resolved_topology: directResolvedTopology = null,
      targets = [],
      points = [],
      profiles = [],
      marker_strings: markerStrings = [],
      target_node: targetNode = '',
      target_process: targetProcess = '',
      target_pid: targetPid = '',
      target_binary: targetBinary = '',
      knowledge_catalog: knowledgeCatalog = null,
      instructions = '',
      max_gateway_calls: maxCallsInput = null,
      runWorker: customWorker = null,
    } = input

    if (!dataRoot) throw serviceError('data_root 不能为空')
    const workerFn = customWorker || this.runWorker
    if (typeof workerFn !== 'function') throw serviceError('未配置核验 Worker 执行器', 503)

    const resolvedTopology = directResolvedTopology || (topologyId ? await this.topologies?.getResolved(topologyId) : null)
    if (!resolvedTopology) throw serviceError(`未找到目标拓扑：${topologyId || '未指定'}`, 404)

    const normalizedTargets = (Array.isArray(targets) ? targets : []).map(item => {
      const targetKey = String(item?.target_key || item?.case_key || item?.risk_id || '').trim()
      if (!targetKey) return null
      const entry = {
        target_key: targetKey,
        title: String(item.title || targetKey).trim(),
        kind: item.kind === 'risk' ? 'risk' : 'case',
        ...(item.steps ? { steps: item.steps } : {}),
        ...(item.expected_results ? { expected_results: item.expected_results } : {}),
        ...(item.external_observation ? { external_observation: item.external_observation } : {}),
        ...(item.exclusion_condition ? { exclusion_condition: item.exclusion_condition } : {}),
        ...(Array.isArray(item.source_evidence) ? { source_evidence: item.source_evidence } : {}),
      }
      entry.content_hash = createHash('sha256').update(JSON.stringify(entry)).digest('hex').slice(0, 16)
      return entry
    }).filter(Boolean)
    if (normalizedTargets.length === 0) throw serviceError('请至少提供一个有效核验目标（targets）')

    const verifyId = `pv-${new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14)}-${randomUUID().slice(0, 6)}`
    const lockedKeys = this.acquireLocks(resolvedTopology, verifyId)
    const dir = this.taskDir(dataRoot, verifyId)
    const scratchDirectory = path.join(dir, 'scratch')
    await mkdir(scratchDirectory, { recursive: true })

    const dynamicBudget = Math.min(120, Math.max(30, 14 + normalizedTargets.length * 8))
    const effectiveMaxCalls = Number.isInteger(maxCallsInput) && maxCallsInput > 0
      ? maxCallsInput
      : (this.maxGatewayCalls ?? dynamicBudget)

    const record = {
      schema_version: 1,
      id: verifyId,
      name: String(name || '').trim() || `真机核验 · ${resolvedTopology.name}`,
      mode: mode === 'fault_injection' ? 'fault_injection' : 'direct_case',
      status: 'preflight',
      gate_phase: 'preflight',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      topology: redactTopology(resolvedTopology),
      target_node: String(targetNode || '').trim(),
      target_process: String(targetProcess || '').trim(),
      target_pid: String(targetPid || '').trim(),
      target_binary: String(targetBinary || '').trim(),
      marker_strings: [...new Set((Array.isArray(markerStrings) ? markerStrings : []).map(v => String(v || '').trim()).filter(Boolean))],
      targets: normalizedTargets,
      instructions: String(instructions || '').trim(),
      max_gateway_calls: effectiveMaxCalls,
      gateway_calls_used: 0,
      preflight: null,
      registered_cleanups: [],
      draft_verdicts: [],
      summary: '',
      cleanup: null,
      error: '',
    }
    await this.saveRecord(dataRoot, record)

    const controller = new AbortController()
    const activeKey = `${path.resolve(dataRoot)}\0${verifyId}`
    let session = null
    const gatewayConfigPath = path.join(scratchDirectory, '.gateway.json')

    const runPromise = (async () => {
      try {
        session = await startGatewaySession({
          sessionId: verifyId,
          resolvedTopology,
          transcriptPath: this.transcriptFile(dataRoot, verifyId),
          gatewayConfigPath,
          maxCalls: effectiveMaxCalls,
          initialPhase: 'probe_readonly',
          actorPhaseLabel: 'worker',
          signal: controller.signal,
          onStateChange: async ({ phase, callsUsed, registeredCleanups }) => {
            record.gate_phase = phase
            record.gateway_calls_used = callsUsed
            record.registered_cleanups = registeredCleanups
          },
        })

        const preflight = await this.runPreflight({ record, resolvedTopology, session, signal: controller.signal })
        record.preflight = preflight
        if (!preflight.ok) {
          record.status = 'blocked'
          record.gate_phase = 'blocked'
          record.error = preflight.error
          record.draft_verdicts = record.targets.map(t => ({
            target_key: t.target_key,
            verdict: 'blocked',
            hits: '',
            evidence_command_ids: preflight.command_ids || [],
            observed_behavior: preflight.error,
            cleanup_verified: true,
            notes: '',
          }))
          await this.saveRecord(dataRoot, record)
          return record
        }

        record.status = 'running'
        record.gate_phase = session.getPhase()
        await this.saveRecord(dataRoot, record)

        const inputPath = path.join(scratchDirectory, 'input.json')
        const outputPath = path.join(scratchDirectory, 'result.json')
        await writeFile(inputPath, `${JSON.stringify({
          verify_id: record.id,
          mode: record.mode,
          topology: record.topology,
          preflight: record.preflight,
          targets: record.targets,
          points,
          profiles,
          ...(knowledgeCatalog ? { knowledge_catalog: knowledgeCatalog } : {}),
          instructions: record.instructions,
        }, null, 2)}\n`, 'utf8')

        const prompt = buildVerificationPrompt({
          inputPath,
          outputPath,
          cliPath: CLI_PATH,
          configPath: gatewayConfigPath,
          maxGatewayCalls: effectiveMaxCalls,
        })
        const targetKeys = record.targets.map(t => t.target_key)
        const requireNonZeroHits = record.mode === 'fault_injection' && Array.isArray(points) && points.length > 0

        const workerOutput = await workerFn({
          record,
          cwd,
          scratchDirectory,
          inputPath,
          outputPath,
          prompt,
          gatewayUrl: session.gatewayUrl,
          gatewayToken: session.token,
          gatewayConfigPath,
          cliPath: CLI_PATH,
          signal: controller.signal,
          validateOutput: candidate => validateVerificationResult(candidate, {
            targetKeys,
            validCommandIds: session.validCommandIds,
            requireNonZeroHits,
          }),
        })

        const checked = validateVerificationResult(workerOutput, {
          targetKeys,
          validCommandIds: session.validCommandIds,
          requireNonZeroHits,
        })
        if (!checked.ok) throw new Error(`核验结果校验失败：${checked.error}`)

        record.summary = checked.value.summary
        record.draft_verdicts = checked.value.items
        record._terminal_status = 'completed'
      } catch (error) {
        if (controller.signal.aborted) {
          record._terminal_status = 'cancelled'
          record.error = '用户已停止本次真机核验'
        } else {
          record._terminal_status = 'failed'
          record.error = error instanceof Error ? error.message : String(error)
        }
      } finally {
        if (session) {
          record.gate_phase = 'teardown_audit'
          let postCheck = null
          const cleanupReport = await session.runCleanups({ onlyPending: true })
          const bNode = record.preflight?.baseline?.target_node
          const bProc = record.preflight?.baseline?.process
          if (record.preflight?.ok && bNode && bProc && resolvedTopology.nodes[bNode]?.ssh) {
            try {
              const pidRes = await session.execInternalSsh(bNode, buildPidLookupCommand(bProc), {
                timeoutMs: 15_000,
                enforceSafety: false,
                safetyPhase: 'post_check',
                phaseLabel: 'post_check',
                execSignal: null,
              })
              const afterPids = parsePidList(pidRes.stdout)
              const baselinePid = record.preflight.baseline.pid || ''
              postCheck = {
                target_node: bNode,
                baseline_pid: baselinePid,
                after_pids: afterPids,
                pid_changed: Boolean(baselinePid && afterPids.length > 0 && !afterPids.includes(baselinePid)),
                process_alive: afterPids.length > 0,
                command_id: pidRes.command_id,
              }
            } catch {}
          }
          await session.close({ runCleanups: false })
          if (record.preflight?.ok) {
            record.cleanup = { ...cleanupReport, post_check: postCheck }
          }
        }
        if (record._terminal_status) {
          record.status = record._terminal_status
          delete record._terminal_status
        }
        record.gate_phase = 'archived'
        await this.saveRecord(dataRoot, record)
        this.releaseLocks(lockedKeys, verifyId)
        this.active.delete(activeKey)
      }
      return record
    })()

    this.active.set(activeKey, { controller, done: runPromise, verifyId })
    return await runPromise
  }
}
