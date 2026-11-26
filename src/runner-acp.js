import { readFile } from 'node:fs/promises'
import { KnowledgePack, validateFormalCardStamp } from './knowledge.js'
import { lookupCodeCliHints } from './code-index.js'

const posixPath = value => String(value ?? '').replaceAll('\\', '/')

function collectSourcePathsFromTargets(targets = []) {
  const paths = []
  for (const target of targets) {
    if (!Array.isArray(target?.source_evidence)) continue
    for (const item of target.source_evidence) {
      if (typeof item === 'string' && item.trim()) {
        paths.push(item.trim())
      } else if (item && typeof item === 'object') {
        const p = item.path || item.file || item.location || ''
        if (typeof p === 'string' && p.trim()) paths.push(p.trim())
      }
    }
  }
  return [...new Set(paths)]
}

export async function buildBatchKnowledgeContext({ packDir, targets = [], topology = null } = {}) {
  if (!packDir) return null
  const pack = new KnowledgePack(packDir)
  // Gate 4: Batch execution strictly consumes verified/human_attested cards only (never drafts)
  const catalog = await pack.readCatalog({ includeDrafts: false })
  const availableRoles = topology?.nodes
    ? new Set(Object.values(topology.nodes).map(n => n.role))
    : null
  const roleMatched = availableRoles
    ? catalog.cards.filter(c => (c.required_roles || []).every(r => availableRoles.has(r)))
    : catalog.cards

  const cards = []
  const warnings = []
  for (const summary of roleMatched) {
    const full = await pack.getCard(summary.id, { allowDraft: false })
    if (!full) continue
    const stamp = validateFormalCardStamp(full)
    if (!stamp.ok) {
      warnings.push(stamp.error)
      continue
    }
    cards.push(summary)
  }

  const sourcePaths = collectSourcePathsFromTargets(targets)
  const codeCliHints = await lookupCodeCliHints(packDir, sourcePaths)

  return {
    pack_root: pack.root,
    read_only_batch_policy: '只允许读取 verified/human_attested 能力卡；如遇参数失效，请将失配信息写入结果的 card_feedback 字段，严禁跑批中途改写正式卡片。',
    cards,
    code_cli_hints: codeCliHints,
    ...(warnings.length ? { warnings } : {}),
  }
}

export function createAcpWorkerAdapter({
  launchSession,
  maxRepairTurns = 1,
  hardDurationMs = 20 * 60 * 1000,
} = {}) {
  if (typeof launchSession !== 'function') {
    throw new Error('createAcpWorkerAdapter 需要提供 launchSession(context) 函数')
  }

  return async context => {
    const { outputPath, prompt, signal, validateOutput } = context
    let session = null
    let hardTimer = null

    try {
      session = await launchSession({ ...context, prompt })
      const deadline = new Promise((_, reject) => {
        hardTimer = setTimeout(() => reject(new Error(`真机核验超过总时长上限（${Math.round(hardDurationMs / 1000)}s），已终止`)), hardDurationMs)
      })
      deadline.catch(() => {})

      await Promise.race([Promise.resolve(session.result), deadline])
      signal?.throwIfAborted?.()

      const readOutputJson = async () => {
        try {
          const text = await readFile(outputPath, 'utf8')
          return text.trim() ? JSON.parse(text) : null
        } catch {
          return null
        }
      }

      let parsed = await readOutputJson()
      let checked = validateOutput(parsed)
      let repairs = 0

      while (!checked.ok && repairs < maxRepairTurns && typeof session.continuePrompt === 'function') {
        repairs += 1
        const repairPrompt = [
          `宿主对 ${posixPath(outputPath)} 的确定性证据校验未通过：${checked.error}`,
          '请保留已完成的真实核验事实，仅修正上述字段错误（确保 evidence_command_ids 均来自宿主网关实际返回的 command_id，打桩模式未命中不得判 confirmed/excluded），覆写结果文件后立即结束。',
        ].join('\n')
        await Promise.race([Promise.resolve(session.continuePrompt(repairPrompt)), deadline])
        signal?.throwIfAborted?.()
        parsed = await readOutputJson()
        checked = validateOutput(parsed)
      }

      if (!checked.ok) {
        throw new Error(`核验结果校验失败：${checked.error}`)
      }
      return {
        ...checked.value,
        ...(Array.isArray(parsed?.card_feedback) ? { card_feedback: parsed.card_feedback } : {}),
      }
    } finally {
      clearTimeout(hardTimer)
      try { await session?.dispose?.() } catch {}
    }
  }
}

export async function runAutonomousVerification({
  harness,
  packDir = '',
  taskInput = {},
  workerAdapter,
  firmwareHint = '',
} = {}) {
  if (!harness) throw new Error('harness 实例不能为空')
  if (typeof workerAdapter !== 'function') throw new Error('workerAdapter 必须是函数')

  const resolvedTopology = taskInput.resolved_topology
    || (taskInput.topology_id ? await harness.topologies?.getResolved(taskInput.topology_id) : null)

  const knowledgeContext = packDir
    ? await buildBatchKnowledgeContext({ packDir, targets: taskInput.targets || [], topology: resolvedTopology })
    : null

  let capturedFeedback = []
  const wrappedWorker = async ctx => {
    const out = await workerAdapter(ctx)
    if (Array.isArray(out?.card_feedback)) {
      capturedFeedback = out.card_feedback
    }
    return out
  }

  const record = await harness.runTask({
    ...taskInput,
    ...(knowledgeContext ? { knowledge_catalog: knowledgeContext } : {}),
    runWorker: wrappedWorker,
  })

  // Gate 4: Record any card mismatch feedback without touching verified cards
  const recordedFeedback = []
  if (packDir && capturedFeedback.length > 0) {
    const pack = new KnowledgePack(packDir)
    for (const fb of capturedFeedback) {
      if (!fb?.card_id || !fb?.error_summary) continue
      try {
        const entry = await pack.recordFeedback({
          cardId: String(fb.card_id),
          sessionId: record.id,
          commandId: String(fb.command_id || ''),
          errorSummary: String(fb.error_summary),
          firmwareHint: String(fb.firmware_hint || firmwareHint || ''),
        })
        recordedFeedback.push(entry)
      } catch {
        // Ignore feedback for unknown/non-verified cards so batch verdict is never disrupted
      }
    }
  }

  return { record, recorded_feedback: recordedFeedback }
}
