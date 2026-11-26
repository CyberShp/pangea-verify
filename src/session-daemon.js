import { spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { mkdir, readFile, stat } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { TopologyStore } from './topology.js'
import { startGatewaySession } from './harness.js'

const CLI_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'cli.mjs')
const DEFAULT_IDLE_TIMEOUT_MS = 30 * 60 * 1000

async function waitForConfigReady(configPath, child, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs
  let exitInfo = null
  child.once('exit', (code, signal) => { exitInfo = { code, signal } })
  while (Date.now() < deadline) {
    if (exitInfo) {
      throw new Error(`受控网关守护进程异常退出（code=${exitInfo.code}, signal=${exitInfo.signal}）`)
    }
    try {
      const info = await stat(configPath)
      if (info.size > 0) {
        const parsed = JSON.parse(await readFile(configPath, 'utf8'))
        if (parsed?.url && parsed?.token) return parsed
      }
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 60))
  }
  try { child.kill('SIGTERM') } catch {}
  throw new Error(`等待受控网关守护进程就绪超时（${timeoutMs}ms）`)
}

export async function startDetachedGatewaySession({
  storePath,
  topologyId,
  dataRoot,
  maxCalls = 80,
  idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS,
  cliPath = CLI_PATH,
} = {}) {
  if (!topologyId) throw new Error('topologyId 不能为空')
  if (!dataRoot) throw new Error('dataRoot 不能为空')

  const store = new TopologyStore(storePath)
  const topo = await store.get(topologyId)
  if (!topo) throw new Error(`未找到拓扑：${topologyId}`)

  const sessionId = `cli-${new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14)}-${randomUUID().slice(0, 6)}`
  const sessionDir = path.join(path.resolve(dataRoot), 'trainer-sessions', sessionId)
  await mkdir(sessionDir, { recursive: true })
  const configPath = path.join(sessionDir, '.gateway.json')
  const transcriptPath = path.join(sessionDir, 'transcript.jsonl')

  const child = spawn(
    process.execPath,
    [
      cliPath,
      '__session-daemon',
      '--store', store.file,
      '--topo-id', topologyId,
      '--session-id', sessionId,
      '--config', configPath,
      '--transcript', transcriptPath,
      '--max-calls', String(maxCalls),
      '--idle-timeout-ms', String(idleTimeoutMs),
    ],
    {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
    },
  )
  child.unref()

  await waitForConfigReady(configPath, child)
  return {
    ok: true,
    session_id: sessionId,
    topology_id: topologyId,
    config_path: configPath,
    transcript_path: transcriptPath,
    phase: 'probe_readonly',
    nodes: Object.keys(topo.nodes || {}),
    pid: child.pid,
    idle_timeout_ms: idleTimeoutMs,
  }
}

export async function runGatewayDaemon({
  storePath,
  topologyId,
  sessionId,
  configPath,
  transcriptPath,
  maxCalls = 80,
  idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS,
} = {}) {
  const store = new TopologyStore(storePath)
  const resolved = await store.getResolved(topologyId)
  if (!resolved) throw new Error(`未找到拓扑：${topologyId}`)

  let exiting = false
  const finishProcess = () => {
    if (exiting) return
    exiting = true
    process.exit(0)
  }

  const gateway = await startGatewaySession({
    sessionId,
    resolvedTopology: resolved,
    transcriptPath,
    gatewayConfigPath: configPath,
    maxCalls: Number(maxCalls) > 0 ? Number(maxCalls) : 80,
    initialPhase: 'probe_readonly',
    actorPhaseLabel: 'trainer',
    idleTimeoutMs: Number(idleTimeoutMs) > 0 ? Number(idleTimeoutMs) : DEFAULT_IDLE_TIMEOUT_MS,
    onShutdown: finishProcess,
  })

  const onSignal = () => {
    void gateway.close({ runCleanups: true }).finally(finishProcess)
  }
  process.once('SIGTERM', onSignal)
  process.once('SIGINT', onSignal)

  return gateway
}
