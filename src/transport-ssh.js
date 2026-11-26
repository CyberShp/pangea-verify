import { randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import path from 'node:path'
import ssh2 from 'ssh2'

const { Client } = ssh2
const OUTPUT_LIMIT = 2 * 1024 * 1024

function expandHome(value) {
  if (value === '~') return homedir()
  if (value.startsWith('~/') || value.startsWith('~\\')) return path.join(homedir(), value.slice(2))
  return value
}

function append(current, chunk) {
  const next = current + chunk.toString('utf8')
  return next.length > OUTPUT_LIMIT ? next.slice(next.length - OUTPUT_LIMIT) : next
}

function stripAnsi(value) {
  return value.replace(/[\u001b\u009b][[\]()#;?]*(?:(?:(?:[a-zA-Z\d]*(?:;[-a-zA-Z\d/#&.:=?%@~_]+)*)?\u0007)|(?:(?:\d{1,4}(?:[;:]\d{0,4})*)?[\dA-PR-TZcf-nq-uy=><~]))/g, '')
}

function buildAuthConfig(sshEndpoint) {
  const config = {
    username: sshEndpoint.username,
    readyTimeout: 20_000,
  }
  if (sshEndpoint.auth_kind === 'password') {
    config.password = sshEndpoint.password ?? ''
  } else if (sshEndpoint.auth_kind === 'key') {
    config.privateKey = readFileSync(expandHome(sshEndpoint.key_path))
    if (sshEndpoint.passphrase) config.passphrase = sshEndpoint.passphrase
  } else if (sshEndpoint.auth_kind === 'agent') {
    config.agent = sshEndpoint.agent_path || process.env.SSH_AUTH_SOCK
  } else {
    throw new Error(`Unsupported SSH auth_kind: ${sshEndpoint.auth_kind}`)
  }
  return config
}

function connectClient(config) {
  return new Promise((resolve, reject) => {
    const client = new Client()
    const fail = error => {
      client.removeAllListeners()
      try { client.end() } catch {}
      reject(error)
    }
    client.once('ready', () => {
      client.removeListener('error', fail)
      client.on('error', () => {})
      resolve(client)
    })
    client.once('error', fail)
    client.connect(config)
  })
}

function forwardStream(jumpClient, targetIp, targetPort) {
  return new Promise((resolve, reject) => {
    jumpClient.forwardOut('127.0.0.1', 0, targetIp, targetPort, (error, stream) => {
      if (error) reject(error)
      else resolve(stream)
    })
  })
}

export class SshTransport {
  constructor(resolvedTopology) {
    this.topology = resolvedTopology
    this.sessions = new Map()
    this.jobs = new Map()
  }

  getNode(nodeId) {
    const node = this.topology?.nodes?.[nodeId]
    if (!node) throw new Error(`未知拓扑节点：${nodeId}`)
    if (!node.ssh) throw new Error(`节点「${nodeId}」未配置 SSH 通道`)
    return node
  }

  async openNodeClient(nodeId) {
    const node = this.getNode(nodeId)
    const authConfig = buildAuthConfig(node.ssh)
    if (node.jump_via) {
      const jumpSession = this.getSession(node.jump_via)
      const jumpClient = await jumpSession.getClient()
      const sock = await forwardStream(jumpClient, node.ssh.ip, node.ssh.port ?? 22)
      return await connectClient({ ...authConfig, sock })
    }
    return await connectClient({
      ...authConfig,
      host: node.ssh.ip,
      port: node.ssh.port ?? 22,
    })
  }

  getSession(nodeId) {
    this.getNode(nodeId)
    if (this.sessions.has(nodeId)) return this.sessions.get(nodeId)

    let client = null
    let connecting = null
    let closed = false
    const depth = (() => {
      let d = 0
      let cur = this.topology.nodes[nodeId]?.jump_via
      while (cur) {
        d += 1
        cur = this.topology.nodes[cur]?.jump_via
      }
      return d
    })()

    const session = {
      nodeId,
      depth,
      async getClient() {
        if (closed) throw new Error(`SSH session for ${nodeId} is closed`)
        if (client) return client
        if (!connecting) {
          connecting = selfOpen().then(conn => {
            if (closed) {
              try { conn.end() } catch {}
              throw new Error(`SSH session for ${nodeId} is closed`)
            }
            client = conn
            const clear = () => { if (client === conn) client = null }
            conn.once('close', clear)
            conn.once('end', clear)
            return conn
          }).finally(() => { connecting = null })
        }
        return connecting
      },
      close() {
        closed = true
        if (client) {
          try { client.end() } catch {}
          client = null
        }
      },
    }
    const selfOpen = () => this.openNodeClient(nodeId)
    this.sessions.set(nodeId, session)
    return session
  }

  async exec(nodeId, command, { timeoutMs = 60_000, signal = null } = {}) {
    if (signal?.aborted) {
      return { success: false, exit_code: null, timed_out: false, aborted: true, error: 'aborted', stdout: '', stderr: '', duration_ms: 0 }
    }
    const started = Date.now()
    let client
    try {
      client = await this.getSession(nodeId).getClient()
    } catch (error) {
      return { success: false, exit_code: null, timed_out: false, error: error.message, stdout: '', stderr: '', duration_ms: Date.now() - started }
    }

    return await new Promise(resolve => {
      let stdout = ''
      let stderr = ''
      let settled = false
      let activeStream = null
      const finish = value => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        if (onAbort) signal?.removeEventListener('abort', onAbort)
        resolve({ ...value, stdout, stderr, duration_ms: Date.now() - started })
      }
      const onAbort = signal ? () => {
        try { activeStream?.signal('TERM') } catch {}
        try { activeStream?.close() } catch {}
        finish({ success: false, exit_code: null, timed_out: false, aborted: true, error: 'aborted' })
      } : null
      if (onAbort) {
        if (signal.aborted) { onAbort(); return }
        signal.addEventListener('abort', onAbort, { once: true })
      }
      const timer = setTimeout(() => {
        try { activeStream?.signal('TERM') } catch {}
        try { activeStream?.close() } catch {}
        finish({ success: false, exit_code: null, timed_out: true, error: 'timeout' })
      }, timeoutMs)

      client.exec(command, (error, stream) => {
        if (settled) { try { stream?.close() } catch {}; return }
        if (error) return finish({ success: false, exit_code: null, timed_out: false, error: error.message })
        activeStream = stream
        stream.on('data', chunk => { stdout = append(stdout, chunk) })
        stream.stderr.on('data', chunk => { stderr = append(stderr, chunk) })
        stream.once('close', code => finish({ success: code === 0, exit_code: code, timed_out: false }))
        stream.once('error', streamError => finish({ success: false, exit_code: null, timed_out: false, error: streamError.message }))
      })
    })
  }

  async startBackground(nodeId, command, { ownerId = null } = {}) {
    const client = await this.openNodeClient(nodeId)
    const jobId = `job-${randomUUID().slice(0, 8)}`
    return await new Promise((resolve, reject) => {
      client.exec(command, { pty: true }, (error, stream) => {
        if (error) {
          try { client.end() } catch {}
          reject(error)
          return
        }
        let complete
        const done = new Promise(r => { complete = r })
        const job = {
          job_id: jobId,
          owner_id: ownerId,
          target: nodeId,
          client,
          stream,
          stdout: '',
          stderr: '',
          running: true,
          exit_code: null,
          error: undefined,
          stopped: false,
          started_at: new Date().toISOString(),
          ended_at: undefined,
          done,
        }
        stream.on('data', chunk => { job.stdout = append(job.stdout, chunk) })
        stream.stderr.on('data', chunk => { job.stderr = append(job.stderr, chunk) })
        stream.once('close', code => {
          job.running = false
          job.exit_code = code
          job.ended_at = new Date().toISOString()
          try { client.end() } catch {}
          complete()
        })
        stream.once('error', streamError => {
          job.error = streamError.message
          job.running = false
          job.ended_at = new Date().toISOString()
          try { client.end() } catch {}
          complete()
        })
        this.jobs.set(jobId, job)
        resolve(this.snapshotJob(job))
      })
    })
  }

  snapshotJob(job) {
    return {
      job_id: job.job_id,
      target: job.target,
      running: job.running,
      exit_code: job.exit_code,
      stdout: job.stdout,
      stderr: job.stderr,
      ...(job.error ? { error: job.error } : {}),
      stopped: job.stopped === true,
      started_at: job.started_at,
      ...(job.ended_at ? { ended_at: job.ended_at } : {}),
    }
  }

  async readBackground(jobId, waitMs = 0) {
    const job = this.jobs.get(jobId)
    if (!job) throw new Error(`未找到后台任务：${jobId}`)
    if (job.running && waitMs > 0) {
      await Promise.race([job.done, new Promise(resolve => setTimeout(resolve, waitMs))])
    }
    return this.snapshotJob(job)
  }

  async stopBackground(jobId) {
    const job = this.jobs.get(jobId)
    if (!job) throw new Error(`未找到后台任务：${jobId}`)
    if (job.running) {
      job.stopped = true
      try { job.stream.signal('INT') } catch {}
      try { job.stream.write('\x03') } catch {}
      await Promise.race([job.done, new Promise(resolve => setTimeout(resolve, 1000))])
      if (job.running) {
        try { job.stream.close() } catch {}
        try { job.client.end() } catch {}
        job.running = false
        job.ended_at = new Date().toISOString()
      }
    }
    return this.snapshotJob(job)
  }

  async interactive(nodeId, exchanges, { signal = null } = {}) {
    if (signal?.aborted) {
      return { success: false, exit_code: null, aborted: true, error: 'aborted', stdout: '', stderr: '', duration_ms: 0 }
    }
    const started = Date.now()
    let client
    try {
      client = await this.getSession(nodeId).getClient()
    } catch (error) {
      return { success: false, exit_code: null, error: error.message, stdout: '', stderr: '', duration_ms: Date.now() - started }
    }

    return await new Promise(resolve => {
      let transcript = ''
      let settled = false
      let pending
      let activeStream = null
      const finish = value => {
        if (settled) return
        settled = true
        if (pending?.timer) clearTimeout(pending.timer)
        if (onAbort) signal?.removeEventListener('abort', onAbort)
        try { pending?.reject(new Error('interactive session closed')) } catch {}
        resolve({ ...value, stdout: transcript, stderr: '', duration_ms: Date.now() - started })
      }
      const onAbort = signal ? () => {
        try { activeStream?.close() } catch {}
        finish({ success: false, exit_code: null, aborted: true, error: 'aborted' })
      } : null
      if (onAbort) {
        if (signal.aborted) { onAbort(); return }
        signal.addEventListener('abort', onAbort, { once: true })
      }

      client.shell({ term: 'xterm-256color', cols: 120, rows: 40 }, async (error, stream) => {
        if (settled) { try { stream?.close() } catch {}; return }
        if (error) return finish({ success: false, exit_code: null, error: error.message })
        activeStream = stream
        stream.on('data', chunk => {
          transcript = append(transcript, chunk)
          if (pending && pending.pattern.test(stripAnsi(transcript.slice(pending.offset)))) {
            clearTimeout(pending.timer)
            const resolvePending = pending.resolve
            pending = undefined
            resolvePending()
          }
        })
        stream.once('error', streamError => finish({ success: false, exit_code: null, error: streamError.message }))
        stream.once('close', code => finish({ success: false, exit_code: code, error: 'interactive shell closed before all exchanges completed' }))

        try {
          for (const exchange of exchanges || []) {
            const pattern = new RegExp(exchange.expect, 'm')
            const offset = transcript.length
            const waitPromise = new Promise((resolveExchange, rejectExchange) => {
              const timer = setTimeout(() => {
                pending = undefined
                rejectExchange(new Error(`interactive expect timeout: ${exchange.expect}`))
              }, (exchange.timeout_seconds ?? 30) * 1000)
              pending = { pattern, offset, timer, resolve: resolveExchange, reject: rejectExchange }
              if (pattern.test(stripAnsi(transcript.slice(offset)))) {
                clearTimeout(timer)
                pending = undefined
                resolveExchange()
              }
            })
            if (exchange.send !== undefined && exchange.send !== null) {
              stream.write(`${exchange.send}\n`)
            }
            await waitPromise
          }
          try { stream.close() } catch {}
          finish({ success: true, exit_code: 0 })
        } catch (exchangeError) {
          try { stream.close() } catch {}
          finish({ success: false, exit_code: null, error: exchangeError.message })
        }
      })
    })
  }

  async disposeOwner(ownerId) {
    if (!ownerId) return
    const jobIds = [...this.jobs.values()].filter(j => j.owner_id === ownerId).map(j => j.job_id)
    await Promise.all(jobIds.map(id => this.stopBackground(id).catch(() => undefined)))
  }

  async closeAll() {
    await Promise.all([...this.jobs.keys()].map(id => this.stopBackground(id).catch(() => undefined)))
    // Close deeper tunneled sessions before jump hosts
    const ordered = [...this.sessions.values()].sort((a, b) => b.depth - a.depth)
    for (const session of ordered) {
      session.close()
    }
    this.sessions.clear()
  }
}
