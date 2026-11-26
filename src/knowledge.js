import { execFile } from 'node:child_process'
import { appendFile, mkdir, readFile, readdir, rename, unlink, writeFile } from 'node:fs/promises'
import { createHash, randomUUID } from 'node:crypto'
import path from 'node:path'
import { extractEnvironmentLiterals, NODE_ROLES } from './topology.js'

const CARD_ID_RE = /^[a-z0-9][a-z0-9._-]*$/
const ADAPTER_ID_RE = /^[a-z0-9][a-z0-9._-]*$/
const SHA256_HEX_RE = /^[a-f0-9]{64}$/i
const GENERIC_IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
const VOLATILE_DEV_RE = /\/dev\/(?:sd[a-z]+\d*|vd[a-z]+\d*|hd[a-z]+\d*|xvd[a-z]+\d*|nvme\d+n\d+(?:p\d+)?)\b/i
const ALLOWED_ROOT_FILES = new Set(['catalog.json', 'README.md', '.gitignore'])
const ALLOWED_ROOT_DIRS = new Set(['.git', 'cards', 'topo-adapters', 'code-maps', 'feedback'])
const ALLOWED_CARD_TIERS = new Set(['drafts', 'attested', 'verified'])

export function validateFormalCardStamp(card) {
  if (!card || typeof card !== 'object') return { ok: false, error: '能力卡不是合法对象' }
  if (card.status === 'verified') {
    const sha = typeof card.proof?.transcript_sha256 === 'string' ? card.proof.transcript_sha256.trim() : ''
    const ids = Array.isArray(card.proof?.command_ids) ? card.proof.command_ids.filter(v => typeof v === 'string' && v.trim()) : []
    if (!SHA256_HEX_RE.test(sha)) {
      return { ok: false, error: `verified 卡片「${card.id || 'unknown'}」缺少合法 64 位 proof.transcript_sha256 实测指纹（疑似绕过闸门伪造）` }
    }
    if (ids.length === 0) {
      return { ok: false, error: `verified 卡片「${card.id || 'unknown'}」缺少非空 proof.command_ids` }
    }
    return { ok: true }
  }
  if (card.status === 'human_attested') {
    const by = typeof card.attestation?.attested_by === 'string' ? card.attestation.attested_by.trim() : ''
    const reason = typeof card.attestation?.reason === 'string' ? card.attestation.reason.trim() : ''
    if (!by || !reason) {
      return { ok: false, error: `human_attested 卡片「${card.id || 'unknown'}」缺少 attestation.attested_by 或 reason` }
    }
    return { ok: true }
  }
  return { ok: false, error: `卡片「${card.id || 'unknown'}」状态「${card.status || '空'}」不属于正式卡片` }
}

function cleanText(value) {
  return typeof value === 'string' ? value.trim() : ''
}

function cleanStringList(value) {
  if (!Array.isArray(value)) return []
  return [...new Set(value.map(cleanText).filter(Boolean))]
}

async function writeAtomicJson(filePath, value) {
  await mkdir(path.dirname(filePath), { recursive: true })
  const tmp = `${filePath}.${process.pid}.${randomUUID().slice(0, 8)}.tmp`
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
  await rename(tmp, filePath)
}

function normalizeStepSlot(slot) {
  if (typeof slot === 'string') {
    const trimmed = slot.trim()
    return trimmed ? [trimmed] : []
  }
  if (Array.isArray(slot)) {
    return slot.map(item => {
      if (typeof item === 'string') return item.trim()
      if (item && typeof item === 'object') {
        const cmd = cleanText(item.command || item.path || '')
        const target = cleanText(item.target_role || item.target || '')
        if (!cmd) return null
        return {
          ...(target ? { target } : {}),
          ...(item.kind === 'http' ? { kind: 'http', method: cleanText(item.method || 'GET').toUpperCase(), path: cmd } : { kind: 'ssh', command: cmd }),
          ...(cleanText(item.expect) ? { expect: cleanText(item.expect) } : {}),
        }
      }
      return null
    }).filter(Boolean)
  }
  return []
}

function flattenStepText(steps) {
  return (steps || []).map(item => {
    if (typeof item === 'string') return item
    return [item.target, item.command, item.path, item.expect].filter(Boolean).join(' ')
  }).join('\n')
}

export function checkCardDeBinding(card, { topology = null } = {}) {
  const slots = ['precheck', 'execute', 'verify_effect', 'cleanup']
  const combined = slots.map(k => flattenStepText(normalizeStepSlot(card?.[k]))).join('\n')
  const envLiterals = extractEnvironmentLiterals(topology)

  for (const [literal, source] of envLiterals.entries()) {
    if (combined.includes(literal)) {
      return {
        ok: false,
        code: 'HARDCODED_TOPOLOGY_LITERAL',
        error: `能力卡步骤模板残留当前环境硬编码字面量「${literal}」（源自 ${source}），请参数化为 \${node.<role>.*} 或 \${resource.*} 变量`,
      }
    }
  }

  for (const match of combined.matchAll(GENERIC_IPV4_RE)) {
    const ip = match[0]
    if (ip === '127.0.0.1' || ip === '0.0.0.0') continue
    return {
      ok: false,
      code: 'HARDCODED_IPV4_LITERAL',
      error: `能力卡步骤模板包含硬编码 IPv4 地址「${ip}」，禁止把具体环境 IP 写入可复用知识包，请改用拓扑变量插槽`,
    }
  }

  const devMatch = VOLATILE_DEV_RE.exec(combined)
  if (devMatch) {
    return {
      ok: false,
      code: 'VOLATILE_DEVICE_LITERAL',
      error: `能力卡步骤模板包含易漂移裸盘符「${devMatch[0]}」，换环境极易误伤系统盘，请改用 \${resource.<lun>.by_id_path} 等稳定拓扑资源变量`,
    }
  }

  return { ok: true }
}

export function validateCapabilityCard(rawCard, { topology = null } = {}) {
  if (!rawCard || typeof rawCard !== 'object' || Array.isArray(rawCard)) {
    return { ok: false, error: '能力卡必须是 JSON 对象' }
  }
  const id = cleanText(rawCard.id)
  if (!CARD_ID_RE.test(id)) {
    return { ok: false, error: `无效的能力卡 id「${id}」（须使用小写字母、数字、点、连字符或下划线，如 san.iscsi.host_login）` }
  }
  const title = cleanText(rawCard.title)
  const domain = cleanText(rawCard.domain)
  const intent = cleanText(rawCard.intent)
  if (!title || !domain || !intent) {
    return { ok: false, error: '能力卡必填 title、domain 与 intent' }
  }
  const sideEffect = rawCard.side_effect === 'readonly' ? 'readonly' : rawCard.side_effect === 'mutating' ? 'mutating' : ''
  if (!sideEffect) {
    return { ok: false, error: '能力卡 side_effect 必须显式声明为 "readonly" 或 "mutating"' }
  }
  const requiredRoles = cleanStringList(rawCard.required_roles)
  if (requiredRoles.length === 0 || requiredRoles.some(r => !NODE_ROLES.includes(r))) {
    return { ok: false, error: `required_roles 必须至少包含一个合法节点角色（${NODE_ROLES.join(' / ')}）` }
  }

  const precheck = normalizeStepSlot(rawCard.precheck)
  const execute = normalizeStepSlot(rawCard.execute)
  const verifyEffect = normalizeStepSlot(rawCard.verify_effect)
  const cleanup = normalizeStepSlot(rawCard.cleanup)

  if (execute.length === 0 || verifyEffect.length === 0) {
    return { ok: false, error: '能力卡必须提供非空 execute 与 verify_effect 步骤' }
  }
  if (sideEffect === 'mutating') {
    if (precheck.length === 0) {
      return { ok: false, error: 'mutating 变更类能力卡必须提供非空 precheck 前置探活步骤' }
    }
    if (cleanup.length === 0) {
      return { ok: false, error: 'mutating 变更类能力卡必须绑定非空 cleanup 对偶恢复步骤（严禁只管注入不管清理）' }
    }
  }

  const debind = checkCardDeBinding(
    { precheck, execute, verify_effect: verifyEffect, cleanup },
    { topology },
  )
  if (!debind.ok) return debind

  return {
    ok: true,
    value: {
      schema_version: 1,
      id,
      title,
      domain,
      intent,
      source_modules: cleanStringList(rawCard.source_modules),
      required_roles: requiredRoles,
      side_effect: sideEffect,
      ...(cleanText(rawCard.version_match) ? { version_match: cleanText(rawCard.version_match) } : {}),
      parameters: cleanStringList(rawCard.parameters),
      precheck,
      execute,
      verify_effect: verifyEffect,
      cleanup,
      ...(cleanText(rawCard.notes) ? { notes: cleanText(rawCard.notes) } : {}),
    },
  }
}

export class KnowledgePack {
  constructor(packDir) {
    if (!packDir) throw new Error('KnowledgePack 目录路径不能为空')
    this.root = path.resolve(packDir)
  }

  catalogPath() {
    return path.join(this.root, 'catalog.json')
  }

  cardPath(tier, cardId) {
    if (!CARD_ID_RE.test(cardId || '')) throw new Error(`无效的 cardId：${cardId}`)
    const folder = tier === 'verified' ? 'verified' : tier === 'attested' ? 'attested' : 'drafts'
    return path.join(this.root, 'cards', folder, `${cardId}.json`)
  }

  feedbackPath(cardId) {
    if (!CARD_ID_RE.test(cardId || '')) throw new Error(`无效的 cardId：${cardId}`)
    return path.join(this.root, 'feedback', `${cardId}.jsonl`)
  }

  async ensureLayout() {
    await Promise.all([
      mkdir(path.join(this.root, 'cards', 'drafts'), { recursive: true }),
      mkdir(path.join(this.root, 'cards', 'verified'), { recursive: true }),
      mkdir(path.join(this.root, 'cards', 'attested'), { recursive: true }),
      mkdir(path.join(this.root, 'topo-adapters'), { recursive: true }),
      mkdir(path.join(this.root, 'code-maps'), { recursive: true }),
      mkdir(path.join(this.root, 'feedback'), { recursive: true }),
    ])
  }

  async countFeedback(cardId) {
    try {
      const raw = await readFile(this.feedbackPath(cardId), 'utf8')
      return raw.split(/\r?\n/).filter(Boolean).length
    } catch (error) {
      if (error?.code === 'ENOENT') return 0
      throw error
    }
  }

  async readTierCards(tier) {
    const dir = path.dirname(this.cardPath(tier, 'placeholder'))
    let entries
    try {
      entries = await readdir(dir, { withFileTypes: true })
    } catch (error) {
      if (error?.code === 'ENOENT') return []
      throw error
    }
    const out = []
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith('.json')) continue
      try {
        out.push(JSON.parse(await readFile(path.join(dir, entry.name), 'utf8')))
      } catch {}
    }
    return out
  }

  async rebuildCatalog() {
    await this.ensureLayout()
    const [verified, attested, drafts] = await Promise.all([
      this.readTierCards('verified'),
      this.readTierCards('attested'),
      this.readTierCards('drafts'),
    ])
    const summaryMap = new Map()
    // Precedence: verified > attested > draft
    for (const card of [...drafts, ...attested, ...verified]) {
      if (!card?.id) continue
      const mismatchCount = await this.countFeedback(card.id)
      summaryMap.set(card.id, {
        id: card.id,
        title: card.title,
        domain: card.domain,
        intent: card.intent,
        source_modules: card.source_modules || [],
        required_roles: card.required_roles || [],
        side_effect: card.side_effect,
        status: card.status,
        ...(card.version_match ? { version_match: card.version_match } : {}),
        mismatch_count: mismatchCount,
      })
    }
    const catalog = {
      version: 1,
      updated_at: new Date().toISOString(),
      cards: [...summaryMap.values()].sort((a, b) => a.id.localeCompare(b.id)),
    }
    await writeAtomicJson(this.catalogPath(), catalog)
    return catalog
  }

  async readCatalog({ includeDrafts = false } = {}) {
    let catalog
    try {
      catalog = JSON.parse(await readFile(this.catalogPath(), 'utf8'))
    } catch (error) {
      if (error?.code === 'ENOENT') catalog = await this.rebuildCatalog()
      else throw error
    }
    const cards = Array.isArray(catalog.cards) ? catalog.cards : []
    return {
      ...catalog,
      cards: includeDrafts ? cards : cards.filter(c => c.status === 'verified' || c.status === 'human_attested'),
    }
  }

  async queryCatalog({ domain = '', sourceModule = '', role = '', keyword = '', includeDrafts = false } = {}) {
    const catalog = await this.readCatalog({ includeDrafts })
    const kw = cleanText(keyword).toLowerCase()
    const dom = cleanText(domain).toLowerCase()
    const mod = cleanText(sourceModule).toLowerCase()
    const r = cleanText(role)
    return catalog.cards.filter(card => {
      if (dom && String(card.domain || '').toLowerCase() !== dom) return false
      if (r && !(card.required_roles || []).includes(r)) return false
      if (mod && !(card.source_modules || []).some(m => m.toLowerCase().includes(mod) || mod.includes(m.toLowerCase()))) return false
      if (kw) {
        const hay = `${card.id} ${card.title} ${card.domain} ${card.intent} ${(card.source_modules || []).join(' ')}`.toLowerCase()
        if (!hay.includes(kw)) return false
      }
      return true
    })
  }

  async getCard(cardId, { allowDraft = false } = {}) {
    const tiers = allowDraft ? ['verified', 'attested', 'drafts'] : ['verified', 'attested']
    for (const tier of tiers) {
      try {
        return JSON.parse(await readFile(this.cardPath(tier, cardId), 'utf8'))
      } catch (error) {
        if (error?.code !== 'ENOENT') throw error
      }
    }
    return null
  }

  async saveDraft(rawCard, { topology = null } = {}) {
    await this.ensureLayout()
    const checked = validateCapabilityCard(rawCard, { topology })
    if (!checked.ok) {
      const err = new Error(checked.error)
      err.code = checked.code || 'INVALID_CAPABILITY_CARD'
      throw err
    }
    const now = new Date().toISOString()
    const draftRecord = {
      ...checked.value,
      status: 'draft',
      updated_at: now,
    }
    await writeAtomicJson(this.cardPath('drafts', draftRecord.id), draftRecord)
    await this.rebuildCatalog()
    return draftRecord
  }

  async promoteCard({ cardId, transcriptPath, commandIds = [], firmwareHint = '', topology = null } = {}) {
    await this.ensureLayout()
    const candidate = await this.getCard(cardId, { allowDraft: true })
    if (!candidate) throw new Error(`未找到待转正能力卡：${cardId}`)

    const checked = validateCapabilityCard(candidate, { topology })
    if (!checked.ok) throw new Error(`能力卡校验未通过：${checked.error}`)

    const ids = cleanStringList(commandIds)
    if (ids.length === 0) {
      throw new Error('晋升 verified 必须提供至少一条真实网关执行过的 commandIds')
    }
    if (!transcriptPath) {
      throw new Error('晋升 verified 必须提供本地真实 transcript.jsonl 路径')
    }
    const rawTranscript = await readFile(path.resolve(transcriptPath), 'utf8')
    const transcriptSha256 = createHash('sha256').update(rawTranscript).digest('hex')
    const entriesById = new Map()
    for (const line of rawTranscript.split(/\r?\n/).filter(Boolean)) {
      const parsed = JSON.parse(line)
      if (parsed?.command_id) entriesById.set(parsed.command_id, parsed)
    }

    let hasCleanupProof = false
    let hasExecutionProof = false
    for (const cmdId of ids) {
      const entry = entriesById.get(cmdId)
      if (!entry) {
        throw new Error(`实测晋升被拒：transcript 中不存在 command_id「${cmdId}」`)
      }
      if (entry.blocked) {
        throw new Error(`实测晋升被拒：command_id「${cmdId}」被安全策略拦截，不能作为成功证据`)
      }
      if (!entry.success) {
        throw new Error(`实测晋升被拒：command_id「${cmdId}」未执行成功（${entry.error || `exit=${entry.exit_code ?? entry.status_code}`}）`)
      }
      if (entry.phase === 'cleanup') hasCleanupProof = true
      else if (entry.phase !== 'preflight') hasExecutionProof = true
    }

    if (!hasExecutionProof) {
      throw new Error('实测晋升被拒：commandIds 中缺少实际执行/验证命令证据')
    }
    if (checked.value.side_effect === 'mutating' && !hasCleanupProof) {
      throw new Error('实测晋升被拒：mutating 变更类能力卡必须在真机上实际跑通 register-cleanup 清理动作（需包含 phase="cleanup" 的成功 command_id）才能转正')
    }

    const verifiedCard = {
      ...checked.value,
      status: 'verified',
      proof: {
        verified_at: new Date().toISOString(),
        transcript_sha256: transcriptSha256,
        command_ids: ids,
        ...(cleanText(firmwareHint) ? { firmware_hint: cleanText(firmwareHint) } : {}),
      },
      updated_at: new Date().toISOString(),
    }
    await writeAtomicJson(this.cardPath('verified', verifiedCard.id), verifiedCard)
    try { await unlink(this.cardPath('drafts', verifiedCard.id)) } catch {}
    try { await unlink(this.cardPath('attested', verifiedCard.id)) } catch {}
    await this.rebuildCatalog()
    return verifiedCard
  }

  async attestCard({ cardId, attestedBy, reason, firmwareHint = '', topology = null } = {}) {
    await this.ensureLayout()
    const by = cleanText(attestedBy)
    const why = cleanText(reason)
    if (!by || !why) throw new Error('人工签字背书（attestCard）必须提供 attestedBy 与 reason')
    const candidate = await this.getCard(cardId, { allowDraft: true })
    if (!candidate) throw new Error(`未找到待背书能力卡：${cardId}`)
    if (candidate.status === 'verified') throw new Error(`能力卡「${cardId}」已是实测转正（verified）状态，无需降级背书`)

    const checked = validateCapabilityCard(candidate, { topology })
    if (!checked.ok) throw new Error(`能力卡校验未通过：${checked.error}`)

    const attestedCard = {
      ...checked.value,
      status: 'human_attested',
      attestation: {
        attested_at: new Date().toISOString(),
        attested_by: by,
        reason: why,
        ...(cleanText(firmwareHint) ? { firmware_hint: cleanText(firmwareHint) } : {}),
      },
      updated_at: new Date().toISOString(),
    }
    await writeAtomicJson(this.cardPath('attested', attestedCard.id), attestedCard)
    try { await unlink(this.cardPath('drafts', attestedCard.id)) } catch {}
    await this.rebuildCatalog()
    return attestedCard
  }

  async recordFeedback({ cardId, sessionId = '', commandId = '', errorSummary, firmwareHint = '' } = {}) {
    await this.ensureLayout()
    const summary = cleanText(errorSummary)
    if (!summary) throw new Error('errorSummary 不能为空')
    const existing = await this.getCard(cardId, { allowDraft: false })
    if (!existing) throw new Error(`未找到正式能力卡「${cardId}」，无法记录跑批失配反馈`)

    const entry = {
      at: new Date().toISOString(),
      card_id: cardId,
      ...(cleanText(sessionId) ? { session_id: cleanText(sessionId) } : {}),
      ...(cleanText(commandId) ? { command_id: cleanText(commandId) } : {}),
      ...(cleanText(firmwareHint) ? { firmware_hint: cleanText(firmwareHint) } : {}),
      error_summary: summary,
    }
    await appendFile(this.feedbackPath(cardId), `${JSON.stringify(entry)}\n`, 'utf8')
    await this.rebuildCatalog()
    return entry
  }

  async readFeedback(cardId) {
    try {
      const raw = await readFile(this.feedbackPath(cardId), 'utf8')
      return raw.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line))
    } catch (error) {
      if (error?.code === 'ENOENT') return []
      throw error
    }
  }

  async saveTopoAdapter({ id, code } = {}) {
    await this.ensureLayout()
    const cleanId = cleanText(id).replace(/\.mjs$/i, '')
    if (!ADAPTER_ID_RE.test(cleanId)) {
      throw new Error(`无效的 topo-adapter 名称「${id || ''}」（仅允许小写字母、数字、点、连字符或下划线）`)
    }
    const source = typeof code === 'string' ? code : ''
    if (!source.trim()) throw new Error('topo-adapter 代码内容不能为空')
    if (!/\bexport\s+(?:async\s+)?function\s+adaptTopology\b|\bexport\s+const\s+adaptTopology\b|\bexport\s+default\b|\bexport\s*\{[^}]*\badaptTopology\b/.test(source)) {
      throw new Error('topo-adapter 必须显式导出 adaptTopology(rawInput, context) 函数或 default 函数')
    }

    const adaptersDir = path.join(this.root, 'topo-adapters')
    const targetPath = path.join(adaptersDir, `${cleanId}.mjs`)
    const tmpPath = path.join(adaptersDir, `.${cleanId}.${process.pid}.${randomUUID().slice(0, 8)}.tmp.mjs`)
    await writeFile(tmpPath, `${source.replace(/\r?\n$/, '')}\n`, 'utf8')
    try {
      await new Promise((resolve, reject) => {
        execFile(process.execPath, ['--check', tmpPath], { timeout: 10_000, windowsHide: true }, (err, _stdout, stderr) => {
          if (err) reject(new Error(`topo-adapter 语法校验失败：${(stderr || err.message || '').trim()}`))
          else resolve()
        })
      })
      await rename(tmpPath, targetPath)
      return { ok: true, id: cleanId, path: targetPath }
    } catch (error) {
      try { await unlink(tmpPath) } catch {}
      throw error
    }
  }

  async lint() {
    const errors = []
    let rootEntries
    try {
      rootEntries = await readdir(this.root, { withFileTypes: true })
    } catch (error) {
      if (error?.code === 'ENOENT') return { ok: true, errors: [] }
      throw error
    }

    for (const entry of rootEntries) {
      if (entry.isDirectory()) {
        if (!ALLOWED_ROOT_DIRS.has(entry.name)) {
          errors.push(`发现非法顶层目录「${entry.name}」（Knowledge Pack 仅允许 ${[...ALLOWED_ROOT_DIRS].join(', ')}）`)
        }
      } else if (entry.isFile()) {
        if (!ALLOWED_ROOT_FILES.has(entry.name)) {
          errors.push(`发现非法顶层文件「${entry.name}」（Knowledge Pack 根目录仅允许 ${[...ALLOWED_ROOT_FILES].join(', ')}）`)
        }
      } else {
        errors.push(`发现不支持的顶层条目「${entry.name}」`)
      }
    }

    const checkDirFiles = async (relDir, ext, pattern, onFile) => {
      const absDir = path.join(this.root, relDir)
      let items
      try { items = await readdir(absDir, { withFileTypes: true }) } catch (e) { if (e?.code === 'ENOENT') return; throw e }
      for (const item of items) {
        const rel = `${relDir}/${item.name}`
        if (!item.isFile()) {
          errors.push(`目录「${relDir}」下禁止出现非文件条目「${rel}」`)
          continue
        }
        if (!item.name.endsWith(ext) || (pattern && !pattern.test(item.name.slice(0, -ext.length)))) {
          errors.push(`文件「${rel}」不符合命名规范（须为 *${ext}）`)
          continue
        }
        if (onFile) await onFile(path.join(absDir, item.name), rel)
      }
    }

    await checkDirFiles('topo-adapters', '.mjs', ADAPTER_ID_RE)
    await checkDirFiles('code-maps', '.json', /^[A-Za-z0-9._-]+$/, async (full, rel) => {
      try { JSON.parse(await readFile(full, 'utf8')) } catch { errors.push(`code-map JSON 损坏：${rel}`) }
    })
    await checkDirFiles('feedback', '.jsonl', CARD_ID_RE, async (full, rel) => {
      const raw = await readFile(full, 'utf8')
      for (const line of raw.split(/\r?\n/).filter(Boolean)) {
        try { JSON.parse(line) } catch { errors.push(`feedback JSONL 含非法行：${rel}`); break }
      }
    })

    // Check cards directory tiers
    const cardsDir = path.join(this.root, 'cards')
    try {
      const cardEntries = await readdir(cardsDir, { withFileTypes: true })
      for (const entry of cardEntries) {
        if (!entry.isDirectory() || !ALLOWED_CARD_TIERS.has(entry.name)) {
          errors.push(`cards/ 下发现非法条目「cards/${entry.name}」（仅允许 drafts/attested/verified）`)
        }
      }
    } catch (e) {
      if (e?.code !== 'ENOENT') throw e
    }

    for (const tier of ALLOWED_CARD_TIERS) {
      await checkDirFiles(`cards/${tier}`, '.json', CARD_ID_RE, async (full, rel) => {
        let card
        try { card = JSON.parse(await readFile(full, 'utf8')) } catch { errors.push(`能力卡 JSON 损坏：${rel}`); return }
        const checked = validateCapabilityCard(card)
        if (!checked.ok) {
          errors.push(`能力卡「${rel}」结构校验失败：${checked.error}`)
          return
        }
        const expectedStatus = tier === 'verified' ? 'verified' : tier === 'attested' ? 'human_attested' : 'draft'
        if (card.status !== expectedStatus) {
          errors.push(`能力卡「${rel}」status 为「${card.status}」，与所在目录 ${tier} 不匹配`)
          return
        }
        if (tier === 'verified' || tier === 'attested') {
          const stamp = validateFormalCardStamp(card)
          if (!stamp.ok) errors.push(`${rel}：${stamp.error}`)
        }
      })
    }

    return { ok: errors.length === 0, errors }
  }
}
