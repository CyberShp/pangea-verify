import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { homedir } from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { decryptSecret, encryptSecret, isEncryptedSecret } from './credentials.js'

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/
export const NODE_ROLES = Object.freeze(['host', 'controller', 'switch', 'bmc', 'jump'])
const FORBIDDEN_TEST_PROCESSES = new Set(['sshd', 'systemd', 'init', 'launchd'])
const VOLATILE_BLOCK_DEV_RE = /^\/dev\/(?:sd[a-z]+\d*|vd[a-z]+\d*|hd[a-z]+\d*|xvd[a-z]+\d*|nvme\d+n\d+(?:p\d+)?|mmcblk\d+(?:p\d+)?)$/i
const STABLE_BLOCK_DEV_RE = /^\/dev\/(?:disk\/by-(?:id|wwn|path|partuuid|uuid)\/\S+|mapper\/\S+|dm-\d+|md\d+|loop\d+)$/

function cleanText(value) {
  return typeof value === 'string' ? value.trim() : ''
}

function cleanStringList(value) {
  if (!Array.isArray(value)) return []
  return [...new Set(value.map(cleanText).filter(Boolean))]
}

export function defaultTopologyStorePath() {
  const root = path.resolve(process.env.PANGEA_VERIFY_HOME || path.join(homedir(), '.pangea-verify'))
  return path.join(root, 'topologies.json')
}

export function isStableBlockDevicePath(devicePath) {
  const text = cleanText(devicePath)
  if (!text) return false
  if (VOLATILE_BLOCK_DEV_RE.test(text)) return false
  return STABLE_BLOCK_DEV_RE.test(text)
}

async function normalizeSshEndpoint(value, nodeLabel, { existing = null, keyDir, platform } = {}) {
  if (value === undefined || value === null || value === '') return null
  if (typeof value !== 'object' || Array.isArray(value)) throw new Error(`${nodeLabel}.ssh 必须是对象`)
  const ip = cleanText(value.ip)
  if (!ip) return null
  const username = cleanText(value.username)
  const port = value.port === undefined || value.port === '' ? 22 : Number(value.port)
  if (!username) throw new Error(`${nodeLabel}.ssh.username 不能为空`)
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`${nodeLabel}.ssh.port 必须在 1 到 65535 之间`)

  const authKind = value.auth_kind === 'key' ? 'key' : value.auth_kind === 'agent' ? 'agent' : 'password'
  const extra = {
    ...(cleanText(value.default_workdir) ? { default_workdir: cleanText(value.default_workdir) } : {}),
    ...(cleanText(value.default_process) ? { default_process: cleanText(value.default_process) } : {}),
    ...(cleanStringList(value.default_log_paths).length ? { default_log_paths: cleanStringList(value.default_log_paths) } : {}),
  }

  if (authKind === 'agent') {
    return {
      ip, port, username, auth_kind: 'agent',
      ...(cleanText(value.agent_path) ? { agent_path: cleanText(value.agent_path) } : {}),
      ...extra,
    }
  }

  if (authKind === 'key') {
    const keyPath = cleanText(value.key_path)
    if (!keyPath) throw new Error(`${nodeLabel}.ssh.key_path 不能为空`)
    let passphraseEncrypted = null
    if (isEncryptedSecret(value.passphrase_encrypted)) {
      passphraseEncrypted = value.passphrase_encrypted
    } else if (typeof value.passphrase === 'string' && value.passphrase.length > 0) {
      passphraseEncrypted = await encryptSecret(value.passphrase, { keyDir, platform })
    } else if (value.keep_passphrase !== false && existing?.auth_kind === 'key' && existing?.key_path === keyPath && isEncryptedSecret(existing?.passphrase_encrypted)) {
      passphraseEncrypted = existing.passphrase_encrypted
    }
    return {
      ip, port, username, auth_kind: 'key', key_path: keyPath,
      ...(passphraseEncrypted ? { passphrase_encrypted: passphraseEncrypted } : {}),
      ...extra,
    }
  }

  let passwordEncrypted = null
  if (isEncryptedSecret(value.password_encrypted)) {
    passwordEncrypted = value.password_encrypted
  } else if (typeof value.password === 'string' && value.password.length > 0) {
    passwordEncrypted = await encryptSecret(value.password, { keyDir, platform })
  } else if (value.keep_password !== false && existing?.ip === ip && existing?.username === username && isEncryptedSecret(existing?.password_encrypted)) {
    passwordEncrypted = existing.password_encrypted
  }
  if (!passwordEncrypted) throw new Error(`${nodeLabel}.ssh.password 不能为空`)
  return { ip, port, username, auth_kind: 'password', password_encrypted: passwordEncrypted, ...extra }
}

async function normalizeHttpEndpoint(value, nodeLabel, { existing = null, keyDir, platform } = {}) {
  if (value === undefined || value === null || value === '') return null
  if (typeof value !== 'object' || Array.isArray(value)) throw new Error(`${nodeLabel}.http 必须是对象`)
  const baseUrlRaw = cleanText(value.base_url)
  if (!baseUrlRaw) return null
  let parsedUrl
  try {
    parsedUrl = new URL(baseUrlRaw)
  } catch {
    throw new Error(`${nodeLabel}.http.base_url 不是合法的 URL`)
  }
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    throw new Error(`${nodeLabel}.http.base_url 仅支持 http 或 https 协议`)
  }
  const authKind = ['none', 'bearer', 'basic', 'header'].includes(value.auth_kind) ? value.auth_kind : 'none'
  const verifyTls = value.verify_tls === true
  const allowReadonlyPostPaths = cleanStringList(value.allow_readonly_post_paths)
  const base = {
    base_url: baseUrlRaw.replace(/\/$/, ''),
    hostname: parsedUrl.hostname,
    verify_tls: verifyTls,
    auth_kind: authKind,
    ...(allowReadonlyPostPaths.length ? { allow_readonly_post_paths: allowReadonlyPostPaths } : {}),
  }
  if (authKind === 'none') return base

  let secretEncrypted = null
  const rawSecret = typeof value.secret === 'string' && value.secret.length > 0
    ? value.secret
    : (typeof value.token === 'string' && value.token.length > 0
      ? value.token
      : (typeof value.password === 'string' && value.password.length > 0 ? value.password : ''))
  if (isEncryptedSecret(value.secret_encrypted)) {
    secretEncrypted = value.secret_encrypted
  } else if (rawSecret) {
    secretEncrypted = await encryptSecret(rawSecret, { keyDir, platform })
  } else if (value.keep_secret !== false && existing?.base_url === base.base_url && existing?.auth_kind === authKind && isEncryptedSecret(existing?.secret_encrypted)) {
    secretEncrypted = existing.secret_encrypted
  }
  if (!secretEncrypted) throw new Error(`${nodeLabel}.http 认证方式为 ${authKind} 时必须提供 secret/token/password`)

  if (authKind === 'basic') {
    const username = cleanText(value.username)
    if (!username) throw new Error(`${nodeLabel}.http.username 不能为空（basic 认证）`)
    return { ...base, username, secret_encrypted: secretEncrypted }
  }
  if (authKind === 'header') {
    const headerName = cleanText(value.header_name) || 'X-Auth-Token'
    return { ...base, header_name: headerName, secret_encrypted: secretEncrypted }
  }
  return { ...base, secret_encrypted: secretEncrypted }
}

function normalizeVars(vars, ownerLabel) {
  if (vars === undefined || vars === null) return {}
  if (typeof vars !== 'object' || Array.isArray(vars)) throw new Error(`${ownerLabel}.vars 必须是键值对象`)
  const out = {}
  for (const [k, v] of Object.entries(vars)) {
    const key = cleanText(k)
    if (!key) continue
    if (!['string', 'number', 'boolean'].includes(typeof v)) {
      throw new Error(`${ownerLabel}.vars.${key} 仅支持字符串、数字或布尔值`)
    }
    out[key] = v
  }
  return out
}

export async function normalizeTopology(profile, { existing = null, keyDir, platform = process.platform } = {}) {
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)) throw new Error('topology 必须是对象')
  const id = cleanText(profile.id)
  const name = cleanText(profile.name)
  if (!id) throw new Error('topology.id 不能为空')
  if (!ID_RE.test(id)) throw new Error(`无效的 topology.id「${id}」（仅允许字母、数字、点、连字符或下划线）`)
  if (!name) throw new Error('topology.name 不能为空')
  if (!profile.nodes || typeof profile.nodes !== 'object' || Array.isArray(profile.nodes)) {
    throw new Error('topology.nodes 必须是非空节点对象')
  }
  const nodeEntries = Object.entries(profile.nodes)
  if (nodeEntries.length === 0) throw new Error('topology.nodes 至少需要定义一个节点')

  const normalizedNodes = {}
  for (const [rawNodeId, rawNode] of nodeEntries) {
    const nodeId = cleanText(rawNodeId)
    if (!ID_RE.test(nodeId)) throw new Error(`无效的节点 ID「${rawNodeId}」`)
    if (!rawNode || typeof rawNode !== 'object' || Array.isArray(rawNode)) {
      throw new Error(`nodes.${nodeId} 必须是对象`)
    }
    const role = cleanText(rawNode.role)
    if (!NODE_ROLES.includes(role)) {
      throw new Error(`nodes.${nodeId}.role 无效（须为 ${NODE_ROLES.join(' / ')}）`)
    }
    const existingNode = existing?.nodes?.[nodeId] ?? null
    const ssh = await normalizeSshEndpoint(rawNode.ssh, `nodes.${nodeId}`, { existing: existingNode?.ssh, keyDir, platform })
    const http = await normalizeHttpEndpoint(rawNode.http, `nodes.${nodeId}`, { existing: existingNode?.http, keyDir, platform })
    if (!ssh && !http) {
      throw new Error(`nodes.${nodeId} 至少需要配置 ssh 或 http 连接通道之一`)
    }

    const jumpVia = cleanText(rawNode.jump_via)
    const rawProtected = rawNode.protected && typeof rawNode.protected === 'object' ? rawNode.protected : {}
    const mgmtIps = cleanStringList([
      ...(Array.isArray(rawProtected.mgmt_ips) ? rawProtected.mgmt_ips : []),
      ssh?.ip || '',
      http?.hostname || '',
    ])
    const mgmtNics = cleanStringList(rawProtected.mgmt_nics)
    const bootDisks = cleanStringList(rawProtected.boot_disks)

    const rawTest = rawNode.test_resources && typeof rawNode.test_resources === 'object' ? rawNode.test_resources : {}
    const dataNics = cleanStringList(rawTest.data_nics)
    const dataIps = cleanStringList(rawTest.data_ips)
    const blockDevices = cleanStringList(rawTest.block_devices)
    const processes = cleanStringList(rawTest.processes)
    const paths = cleanStringList(rawTest.paths)
    const allowReboot = rawTest.allow_reboot === true

    if (allowReboot && role === 'jump') {
      throw new Error(`nodes.${nodeId} 角色为 jump（跳板机），禁止开启 allow_reboot`)
    }
    for (const nic of dataNics) {
      if (mgmtNics.includes(nic)) {
        throw new Error(`nodes.${nodeId} 的靶场网卡「${nic}」与 protected.mgmt_nics 管理网口冲突`)
      }
    }
    for (const ip of dataIps) {
      if (mgmtIps.includes(ip)) {
        throw new Error(`nodes.${nodeId} 的靶场业务 IP「${ip}」与 protected.mgmt_ips 管理面 IP 冲突`)
      }
    }
    for (const dev of blockDevices) {
      if (bootDisks.includes(dev)) {
        throw new Error(`nodes.${nodeId} 的靶场块设备「${dev}」与 protected.boot_disks 系统盘冲突`)
      }
      if (!isStableBlockDevicePath(dev)) {
        throw new Error(`nodes.${nodeId}.test_resources.block_devices 不允许使用易漂移裸盘符「${dev}」，请使用 /dev/disk/by-id/...、/dev/disk/by-wwn/... 或 /dev/mapper/... 稳定路径`)
      }
    }
    for (const proc of processes) {
      if (FORBIDDEN_TEST_PROCESSES.has(proc.toLowerCase())) {
        throw new Error(`nodes.${nodeId}.test_resources.processes 禁止纳入核心系统守护进程「${proc}」`)
      }
    }

    normalizedNodes[nodeId] = {
      id: nodeId,
      role,
      ...(jumpVia ? { jump_via: jumpVia } : {}),
      ...(ssh ? { ssh } : {}),
      ...(http ? { http } : {}),
      protected: {
        mgmt_ips: mgmtIps,
        mgmt_nics: mgmtNics,
        boot_disks: bootDisks,
      },
      test_resources: {
        data_nics: dataNics,
        data_ips: dataIps,
        block_devices: blockDevices,
        processes,
        paths,
        allow_reboot: allowReboot,
      },
      vars: normalizeVars(rawNode.vars, `nodes.${nodeId}`),
    }
  }

  // Validate jump_via references and cycle-freedom
  for (const [nodeId, node] of Object.entries(normalizedNodes)) {
    if (!node.jump_via) continue
    let cursor = node.jump_via
    const visited = new Set([nodeId])
    while (cursor) {
      if (visited.has(cursor)) {
        throw new Error(`nodes.${nodeId} 的 jump_via 跳板链路存在环路`)
      }
      const target = normalizedNodes[cursor]
      if (!target) {
        throw new Error(`nodes.${nodeId}.jump_via 引用了不存在的节点「${cursor}」`)
      }
      if (!target.ssh) {
        throw new Error(`nodes.${nodeId}.jump_via 引用的跳板节点「${cursor}」未配置 ssh 通道`)
      }
      visited.add(cursor)
      cursor = target.jump_via || ''
    }
  }

  return {
    schema_version: 1,
    id,
    name,
    ...(cleanText(profile.notes) ? { notes: cleanText(profile.notes) } : {}),
    ...(cleanText(profile.source_adapter) ? { source_adapter: cleanText(profile.source_adapter) } : {}),
    vars: normalizeVars(profile.vars, 'topology'),
    nodes: normalizedNodes,
    updated_at: profile.updated_at || new Date().toISOString(),
  }
}

export function redactTopology(topology) {
  if (!topology || typeof topology !== 'object') return null
  const nodes = {}
  for (const [nodeId, node] of Object.entries(topology.nodes || {})) {
    const ssh = node.ssh ? {
      ip: node.ssh.ip,
      port: node.ssh.port ?? 22,
      username: node.ssh.username,
      auth_kind: node.ssh.auth_kind,
      has_password: Boolean(isEncryptedSecret(node.ssh.password_encrypted) || node.ssh.password),
      ...(node.ssh.auth_kind === 'key' ? {
        key_path: node.ssh.key_path || '',
        has_passphrase: Boolean(isEncryptedSecret(node.ssh.passphrase_encrypted) || node.ssh.passphrase),
      } : {}),
      ...(node.ssh.default_workdir ? { default_workdir: node.ssh.default_workdir } : {}),
      ...(node.ssh.default_process ? { default_process: node.ssh.default_process } : {}),
      ...(node.ssh.default_log_paths?.length ? { default_log_paths: [...node.ssh.default_log_paths] } : {}),
    } : undefined
    const http = node.http ? {
      base_url: node.http.base_url,
      hostname: node.http.hostname,
      verify_tls: Boolean(node.http.verify_tls),
      auth_kind: node.http.auth_kind,
      ...(node.http.username ? { username: node.http.username } : {}),
      ...(node.http.header_name ? { header_name: node.http.header_name } : {}),
      ...(node.http.allow_readonly_post_paths?.length ? { allow_readonly_post_paths: [...node.http.allow_readonly_post_paths] } : {}),
      has_secret: Boolean(isEncryptedSecret(node.http.secret_encrypted) || node.http.secret),
    } : undefined
    nodes[nodeId] = {
      id: nodeId,
      role: node.role,
      ...(node.jump_via ? { jump_via: node.jump_via } : {}),
      ...(ssh ? { ssh } : {}),
      ...(http ? { http } : {}),
      protected: structuredClone(node.protected),
      test_resources: structuredClone(node.test_resources),
      vars: structuredClone(node.vars || {}),
    }
  }
  return {
    schema_version: topology.schema_version ?? 1,
    id: topology.id,
    name: topology.name,
    ...(topology.notes ? { notes: topology.notes } : {}),
    ...(topology.source_adapter ? { source_adapter: topology.source_adapter } : {}),
    vars: structuredClone(topology.vars || {}),
    nodes,
    ...(topology.updated_at ? { updated_at: topology.updated_at } : {}),
  }
}

export async function resolveTopologySecrets(topology, { keyDir, platform = process.platform } = {}) {
  if (!topology || typeof topology !== 'object') return null
  const nodes = {}
  for (const [nodeId, node] of Object.entries(topology.nodes || {})) {
    let ssh
    if (node.ssh) {
      const { password_encrypted: pwEnc, passphrase_encrypted: ppEnc, ...restSsh } = node.ssh
      ssh = { ...restSsh }
      if (node.ssh.auth_kind === 'password') {
        ssh.password = isEncryptedSecret(pwEnc)
          ? await decryptSecret(pwEnc, { keyDir, platform })
          : (node.ssh.password || '')
      } else if (node.ssh.auth_kind === 'key' && isEncryptedSecret(ppEnc)) {
        ssh.passphrase = await decryptSecret(ppEnc, { keyDir, platform })
      }
    }
    let http
    if (node.http) {
      const { secret_encrypted: secEnc, ...restHttp } = node.http
      http = { ...restHttp }
      if (node.http.auth_kind !== 'none') {
        http.secret = isEncryptedSecret(secEnc)
          ? await decryptSecret(secEnc, { keyDir, platform })
          : (node.http.secret || '')
      }
    }
    nodes[nodeId] = {
      ...node,
      ...(ssh ? { ssh } : {}),
      ...(http ? { http } : {}),
    }
  }
  return { ...topology, nodes }
}

export function extractEnvironmentLiterals(topology) {
  const literals = new Map()
  if (!topology || typeof topology !== 'object') return literals
  const add = (value, label) => {
    const v = cleanText(value)
    if (!v || v.length < 4) return
    if (['127.0.0.1', '0.0.0.0', 'localhost', 'root', 'admin'].includes(v.toLowerCase())) return
    if (!literals.has(v)) literals.set(v, label)
  }
  for (const [nodeId, node] of Object.entries(topology.nodes || {})) {
    if (node.ssh?.ip) add(node.ssh.ip, `nodes.${nodeId}.ssh.ip`)
    if (node.ssh?.username) add(node.ssh.username, `nodes.${nodeId}.ssh.username`)
    if (node.http?.base_url) add(node.http.base_url, `nodes.${nodeId}.http.base_url`)
    if (node.http?.hostname) add(node.http.hostname, `nodes.${nodeId}.http.hostname`)
    for (const ip of node.protected?.mgmt_ips || []) add(ip, `nodes.${nodeId}.protected.mgmt_ips`)
    for (const dev of node.protected?.boot_disks || []) add(dev, `nodes.${nodeId}.protected.boot_disks`)
    for (const ip of node.test_resources?.data_ips || []) add(ip, `nodes.${nodeId}.test_resources.data_ips`)
    for (const nic of node.test_resources?.data_nics || []) {
      if (nic.length >= 4) add(nic, `nodes.${nodeId}.test_resources.data_nics`)
    }
    for (const dev of node.test_resources?.block_devices || []) add(dev, `nodes.${nodeId}.test_resources.block_devices`)
  }
  return literals
}

export async function adaptTopologyFile(adapterPath, rawInput, context = {}) {
  const absAdapter = path.resolve(adapterPath)
  const mod = await import(`${pathToFileURL(absAdapter).href}?t=${Date.now()}`)
  const fn = mod.adaptTopology || mod.default
  if (typeof fn !== 'function') {
    throw new Error(`Topo 转换器「${absAdapter}」必须导出 adaptTopology(rawInput, context) 函数`)
  }
  return await fn(rawInput, context)
}

export class TopologyStore {
  constructor(file = defaultTopologyStorePath(), { platform = process.platform } = {}) {
    this.file = path.resolve(file)
    this.keyDir = path.dirname(this.file)
    this.platform = platform
  }

  async readRaw() {
    try {
      const payload = JSON.parse(await readFile(this.file, 'utf8'))
      if (payload?.version !== 1 || !Array.isArray(payload.topologies)) {
        throw new Error('topology store format is invalid')
      }
      const items = []
      for (const item of payload.topologies) {
        items.push(await normalizeTopology(item, { keyDir: this.keyDir, platform: this.platform }))
      }
      return items
    } catch (error) {
      if (error?.code === 'ENOENT') return []
      throw error
    }
  }

  async writeRaw(topologies) {
    const dir = path.dirname(this.file)
    await mkdir(dir, { recursive: true })
    const tmp = `${this.file}.${process.pid}.${randomUUID().slice(0, 8)}.tmp`
    await writeFile(tmp, `${JSON.stringify({ version: 1, topologies }, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
    try { await chmod(tmp, 0o600) } catch {}
    await rename(tmp, this.file)
  }

  async list() {
    return (await this.readRaw()).map(redactTopology)
  }

  async get(id) {
    const found = (await this.readRaw()).find(item => item.id === id)
    return found ? redactTopology(found) : undefined
  }

  async getResolved(id) {
    const found = (await this.readRaw()).find(item => item.id === id)
    if (!found) return undefined
    return await resolveTopologySecrets(found, { keyDir: this.keyDir, platform: this.platform })
  }

  async save(profile) {
    const items = await this.readRaw()
    const id = cleanText(profile?.id) || `topo-${randomUUID().slice(0, 8)}`
    const existing = items.find(item => item.id === id) ?? null
    const normalized = await normalizeTopology(
      { ...profile, id, updated_at: new Date().toISOString() },
      { existing, keyDir: this.keyDir, platform: this.platform },
    )
    const next = existing
      ? items.map(item => item.id === id ? normalized : item)
      : [...items, normalized]
    await this.writeRaw(next)
    return redactTopology(normalized)
  }

  async remove(id) {
    const items = await this.readRaw()
    const next = items.filter(item => item.id !== id)
    if (next.length === items.length) return false
    await this.writeRaw(next)
    return true
  }
}
