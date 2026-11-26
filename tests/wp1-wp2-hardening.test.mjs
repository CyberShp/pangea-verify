import test from 'node:test'
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { mkdir, mkdtemp, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import ssh2 from 'ssh2'
import {
  KnowledgePack,
  buildBatchKnowledgeContext,
} from '../src/index.js'

const { Server: SshServer } = ssh2
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const CLI_PATH = path.join(ROOT, 'bin', 'cli.mjs')
const PACK_SCRIPT = path.join(ROOT, 'scripts', 'pack-skill.mjs')

function runNode(scriptPath, args) {
  return new Promise(resolve => {
    execFile(process.execPath, [scriptPath, ...args], { timeout: 20_000 }, (error, stdout, stderr) => {
      resolve({
        ok: !error,
        code: error?.code ?? 0,
        stdout: String(stdout || '').trim(),
        stderr: String(stderr || '').trim(),
      })
    })
  })
}

async function startSimpleSsh({ onExec }) {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
  })
  const server = new SshServer({ hostKeys: [privateKey] }, client => {
    client.on('error', () => {})
    client.on('authentication', ctx => ctx.accept())
    client.on('ready', () => {
      client.on('session', accept => {
        const session = accept()
        session.on('exec', (acceptExec, _reject, info) => {
          const stream = acceptExec()
          const res = onExec ? onExec(info.command) : { code: 0, stdout: 'ok\n' }
          if (res.stdout) stream.write(res.stdout)
          if (res.stderr) stream.stderr.write(res.stderr)
          stream.exit(res.code ?? 0)
          stream.end()
        })
      })
    })
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  return {
    port: server.address().port,
    close: () => new Promise(resolve => server.close(() => resolve())),
  }
}

test('WP1: kp-save-adapter validates syntax/export, kp-lint catches rogue files & forged verified cards, and batch runner filters forged cards', async () => {
  const tempDir = await mkdtemp(path.join(tmpdir(), 'pv-wp1-'))
  try {
    const packDir = path.join(tempDir, 'kp')
    const pack = new KnowledgePack(packDir)
    await pack.ensureLayout()

    // Reject missing export
    await assert.rejects(
      () => pack.saveTopoAdapter({ id: 'bad-export', code: 'const x = 1;' }),
      /必须显式导出 adaptTopology/,
    )
    // Reject syntax error
    await assert.rejects(
      () => pack.saveTopoAdapter({ id: 'bad-syntax', code: 'export function adaptTopology( { return {} }' }),
      /语法校验失败/,
    )
    // Valid adapter succeeds
    const saved = await pack.saveTopoAdapter({
      id: 'xml-lab',
      code: 'export function adaptTopology(raw) { return JSON.parse(raw) }',
    })
    assert.equal(saved.ok, true)
    assert.ok((await stat(saved.path)).isFile())

    // Clean pack passes lint
    const cleanLint = await pack.lint()
    assert.equal(cleanLint.ok, true, JSON.stringify(cleanLint.errors))

    // Drop rogue file + forged verified card (missing proof.transcript_sha256)
    await writeFile(path.join(packDir, 'random-notes.md'), 'rogue note\n', 'utf8')
    await mkdir(path.join(packDir, 'rogue-dir'), { recursive: true })
    await writeFile(path.join(packDir, 'cards', 'verified', 'fake.card.json'), JSON.stringify({
      schema_version: 1,
      id: 'fake.card',
      title: '伪造正式卡',
      domain: 'san',
      intent: '绕过闸门写入的伪造卡',
      required_roles: ['host'],
      side_effect: 'readonly',
      execute: ['echo fake'],
      verify_effect: ['echo ok'],
      cleanup: [],
      status: 'verified',
    }, null, 2), 'utf8')
    await pack.rebuildCatalog()

    const badLint = await pack.lint()
    assert.equal(badLint.ok, false)
    assert.ok(badLint.errors.some(e => e.includes('random-notes.md')))
    assert.ok(badLint.errors.some(e => e.includes('rogue-dir')))
    assert.ok(badLint.errors.some(e => e.includes('proof.transcript_sha256')))

    // Batch runner filters out forged card and emits warning instead of crashing
    const batchCtx = await buildBatchKnowledgeContext({ packDir })
    assert.equal(batchCtx.cards.length, 0)
    assert.ok(batchCtx.warnings?.some(w => w.includes('fake.card')))
  } finally {
    await rm(tempDir, { recursive: true, force: true })
  }
})

test('WP2: MCP-free detached session-start -> phase lock -> register-cleanup -> session-close -> kp-promote -> pack:skill', async () => {
  const tempDir = await mkdtemp(path.join(tmpdir(), 'pv-wp2-'))
  const actions = []
  const sshSrv = await startSimpleSsh({
    onExec: cmd => {
      actions.push(cmd)
      return { code: 0, stdout: `ran:${cmd}\n` }
    },
  })

  try {
    const storePath = path.join(tempDir, 'topos.json')
    const packDir = path.join(tempDir, 'kp')
    const dataRoot = path.join(tempDir, 'data')

    // 1. Save topology via CLI
    const saveTopoRes = await runNode(CLI_PATH, [
      'topo-save',
      '--store', storePath,
      '--topo', JSON.stringify({
        id: 'daemon-lab-01',
        name: 'Daemon Lab',
        nodes: {
          host_0: {
            role: 'host',
            ssh: { ip: '127.0.0.1', port: sshSrv.port, username: 'root', auth_kind: 'password', password: 'pw' },
            protected: { mgmt_nics: ['eth0'] },
            test_resources: { data_nics: ['ens6f0'] },
          },
        },
      }),
    ])
    assert.equal(saveTopoRes.ok, true, saveTopoRes.stderr)

    // 2. Start detached MCP-free gateway session
    const startedRes = await runNode(CLI_PATH, [
      'session-start',
      '--store', storePath,
      '--topo-id', 'daemon-lab-01',
      '--data-root', dataRoot,
      '--idle-timeout-ms', '60000',
    ])
    assert.equal(startedRes.ok, true, startedRes.stderr)
    const session = JSON.parse(startedRes.stdout)
    assert.equal(session.phase, 'probe_readonly')
    assert.ok(session.config_path)

    // 3. Read-only probe passes, mutating blocked before register-cleanup
    const roRes = await runNode(CLI_PATH, ['exec', '--config', session.config_path, '--target', 'host_0', '--cmd', 'ip -br link show ens6f0'])
    assert.equal(roRes.ok, true, roRes.stderr)
    const preCmd = JSON.parse(roRes.stdout)

    const blockedRes = await runNode(CLI_PATH, ['exec', '--config', session.config_path, '--target', 'host_0', '--cmd', 'ip link set ens6f0 down'])
    assert.equal(blockedRes.ok, false)
    assert.match(blockedRes.stderr, /PROBE_READONLY/)

    // 4. Unlock via register-cleanup, execute mutation, then session-close automatically runs cleanup
    const regRes = await runNode(CLI_PATH, [
      'register-cleanup', '--config', session.config_path,
      '--target', 'host_0', '--cmd', 'ip link set ens6f0 up', '--desc', 'restore ens6f0',
    ])
    assert.equal(regRes.ok, true, regRes.stderr)

    const mutRes = await runNode(CLI_PATH, ['exec', '--config', session.config_path, '--target', 'host_0', '--cmd', 'ip link set ens6f0 down'])
    assert.equal(mutRes.ok, true, mutRes.stderr)
    const mutCmd = JSON.parse(mutRes.stdout)

    const closeRes = await runNode(CLI_PATH, ['session-close', '--config', session.config_path])
    assert.equal(closeRes.ok, true, closeRes.stderr)
    const closed = JSON.parse(closeRes.stdout)
    assert.equal(closed.cleanup.status, 'ok')
    assert.ok(actions.includes('ip link set ens6f0 up'))
    const cleanupCmdId = closed.cleanup.steps[0].command_id

    // 5. Save draft and promote using authentic daemon transcript
    const draftRes = await runNode(CLI_PATH, [
      'kp-draft', '--pack', packDir,
      '--card', JSON.stringify({
        id: 'net.nic.flap',
        title: '网卡闪断',
        domain: 'network',
        intent: '拉低业务口并恢复',
        required_roles: ['host'],
        side_effect: 'mutating',
        precheck: 'ip -br link show ${node.host.data_nics[0]}',
        execute: 'ip link set ${node.host.data_nics[0]} down',
        verify_effect: 'ip -br link show ${node.host.data_nics[0]}',
        cleanup: 'ip link set ${node.host.data_nics[0]} up',
      }),
    ])
    assert.equal(draftRes.ok, true, draftRes.stderr)

    const promoRes = await runNode(CLI_PATH, [
      'kp-promote', '--pack', packDir, '--id', 'net.nic.flap',
      '--transcript', session.transcript_path,
      '--command-ids', `${preCmd.command_id},${mutCmd.command_id},${cleanupCmdId}`,
    ])
    assert.equal(promoRes.ok, true, promoRes.stderr)
    assert.equal(JSON.parse(promoRes.stdout).status, 'verified')

    // 6. Pack self-contained contest Skill bundle and verify bundled CLI runs standalone
    const packOut = await runNode(PACK_SCRIPT, [])
    assert.equal(packOut.ok, true, packOut.stderr)
    const bundledCli = path.join(ROOT, 'dist', 'live-test-expert', 'bin', 'cli.mjs')
    const bundledLint = await runNode(bundledCli, ['kp-lint', '--pack', packDir])
    assert.equal(bundledLint.ok, true, bundledLint.stderr)
    assert.equal(JSON.parse(bundledLint.stdout).ok, true)
  } finally {
    await sshSrv.close()
    await rm(tempDir, { recursive: true, force: true })
  }
})
