import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm, readFile, stat } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { generateKeyPairSync } from 'node:crypto'
import ssh2 from 'ssh2'
import { startGatewaySession } from '../src/harness.js'
import { KnowledgePack } from '../src/knowledge.js'
import { normalizeTopology, resolveTopologySecrets } from '../src/topology.js'

const { Server } = ssh2

function startMockSshServer(handler) {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  })
  return new Promise((resolve, reject) => {
    const clients = new Set()
    const server = new Server({ hostKeys: [privateKey] }, client => {
      clients.add(client)
      client.on('close', () => clients.delete(client))
      client.on('error', () => {})
      client.on('authentication', ctx => ctx.accept())
      client.on('ready', () => {
        client.on('session', accept => {
          const session = accept()
          session.on('pty', acceptPty => { acceptPty?.() })
          session.on('exec', (acceptExec, _rejectExec, info) => {
            const stream = acceptExec()
            const res = handler(info.command) || { code: 0, stdout: 'ok\n', stderr: '' }
            if (res.stdout) stream.write(res.stdout)
            if (res.stderr) stream.stderr.write(res.stderr)
            stream.exit(res.code ?? 0)
            stream.end()
          })
        })
      })
    })
    server.on('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address()
      resolve({
        port: addr.port,
        close: () => new Promise(res => {
          for (const c of clients) { try { c.end() } catch {} }
          server.close(() => res())
        }),
      })
    })
  })
}

test('#15 failed registered cleanup remains failed in subsequent onlyPending teardown report without re-running', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'pv-audit15-'))
  t.after(() => rm(root, { recursive: true, force: true }))

  let cleanupCalls = 0
  const ssh = await startMockSshServer(cmd => {
    if (cmd.includes('cleanup-fail-cmd')) {
      cleanupCalls += 1
      return { code: 7, stdout: '', stderr: 'device busy' }
    }
    return { code: 0, stdout: 'ok\n', stderr: '' }
  })
  t.after(() => ssh.close())

  const rawTopo = await normalizeTopology({
    id: 'topo-1',
    name: 'mock',
    nodes: {
      array: {
        role: 'controller',
        ssh: { ip: '127.0.0.1', port: ssh.port, username: 'tester', auth_kind: 'password', password: 'secret' },
        protected: { mgmt_ips: [], mgmt_nics: [], boot_disks: [] },
        test_resources: { data_nics: [], data_ips: [], block_devices: [], processes: [], paths: ['/tmp'], allow_reboot: false },
      },
    },
  }, { keyDir: root })
  const resolvedTopology = await resolveTopologySecrets(rawTopo, { keyDir: root })

  const session = await startGatewaySession({
    sessionId: 'sess-audit15',
    resolvedTopology,
    transcriptPath: path.join(root, 'transcript.jsonl'),
    gatewayConfigPath: path.join(root, '.gateway.json'),
  })
  t.after(() => session.close({ runCleanups: false }))

  const gw = JSON.parse(await readFile(path.join(root, '.gateway.json'), 'utf8'))
  const regRes = await fetch(`${gw.url}/register-cleanup`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${gw.token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ target: 'array', command: 'echo cleanup-fail-cmd', description: 'remove stub' }),
  })
  assert.equal(regRes.status, 200)

  const first = await session.runCleanups({ onlyPending: true })
  assert.equal(first.status, 'failed')
  assert.equal(first.steps.length, 1)
  assert.equal(first.steps[0].ok, false)
  assert.equal(first.steps[0].exit_code, 7)
  assert.equal(cleanupCalls, 1)

  // Host finally teardown calls runCleanups({ onlyPending: true }) again -> must NOT overwrite failure with ok / []
  const second = await session.runCleanups({ onlyPending: true })
  assert.equal(second.status, 'failed')
  assert.equal(second.steps.length, 1)
  assert.equal(second.steps[0].ok, false)
  assert.equal(second.steps[0].exit_code, 7)
  assert.equal(cleanupCalls, 1)
})

test('#19 attesting and promoting v2 draft publishes v2 content instead of re-publishing v1 and deleting draft', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'pv-audit19-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const pack = new KnowledgePack(root)

  const v1Draft = await pack.saveDraft({
    id: 'card.check.health',
    title: 'Health Check v1',
    domain: 'storage',
    intent: 'verify storage health v1',
    required_roles: ['controller'],
    side_effect: 'readonly',
    execute: [{ role: 'controller', kind: 'ssh', command: 'echo v1' }],
    verify_effect: [{ role: 'controller', kind: 'ssh', command: 'echo verify-v1' }],
  })
  assert.equal(v1Draft.revision, 1)
  const v1Attested = await pack.attestCard({
    cardId: 'card.check.health',
    attestedBy: 'engineer-a',
    reason: 'approved v1',
    expectedRevision: v1Draft.revision,
    expectedContentSha256: v1Draft.content_sha256,
  })
  assert.equal(v1Attested.status, 'human_attested')
  assert.equal(v1Attested.title, 'Health Check v1')

  // Save revised v2 draft with same card ID
  const v2Draft = await pack.saveDraft({
    id: 'card.check.health',
    title: 'Health Check v2 revised',
    domain: 'storage',
    intent: 'verify storage health v2',
    required_roles: ['controller'],
    side_effect: 'readonly',
    execute: [{ role: 'controller', kind: 'ssh', command: 'echo v2' }],
    verify_effect: [{ role: 'controller', kind: 'ssh', command: 'echo verify-v2' }],
  })
  assert.equal(v2Draft.revision, 2)

  // Wrong revision must be rejected and leave v2 draft intact
  await assert.rejects(
    () => pack.attestCard({ cardId: 'card.check.health', attestedBy: 'engineer-b', reason: 'stale', expectedRevision: 1 }),
    /修订号不匹配/,
  )
  await stat(path.join(root, 'cards', 'drafts', 'card.check.health.json'))

  // Attesting v2 publishes v2 content and cleans draft
  const v2Attested = await pack.attestCard({
    cardId: 'card.check.health',
    attestedBy: 'engineer-b',
    reason: 'approved v2',
    expectedRevision: v2Draft.revision,
    expectedContentSha256: v2Draft.content_sha256,
  })
  assert.equal(v2Attested.status, 'human_attested')
  assert.equal(v2Attested.title, 'Health Check v2 revised')
  assert.equal(v2Attested.execute[0].command, 'echo v2')
  assert.equal(v2Attested.revision, 2)

  const formal = await pack.getCard('card.check.health', { allowDraft: false })
  assert.equal(formal.title, 'Health Check v2 revised')
  assert.equal(formal.execute[0].command, 'echo v2')
  await assert.rejects(() => stat(path.join(root, 'cards', 'drafts', 'card.check.health.json')), { code: 'ENOENT' })
})
