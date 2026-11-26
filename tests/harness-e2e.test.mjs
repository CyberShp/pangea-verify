import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { execFile } from 'node:child_process'
import { createServer as createHttpServer } from 'node:http'
import net from 'node:net'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import ssh2 from 'ssh2'
import {
  TopologyStore,
  VerificationHarness,
} from '../src/index.js'

const { Server: SshServer } = ssh2

function generateTestHostKey() {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
  })
  return privateKey
}

function runCli(cliPath, args) {
  return new Promise(resolve => {
    execFile(process.execPath, [cliPath, ...args], { timeout: 15_000 }, (error, stdout, stderr) => {
      resolve({
        ok: !error,
        code: error?.code ?? 0,
        stdout: String(stdout || '').trim(),
        stderr: String(stderr || '').trim(),
      })
    })
  })
}

async function startMockSshNode({ password, allowTcpForward = false, onExec, onShellLines }) {
  const hostKey = generateTestHostKey()
  const sockets = new Set()
  const server = new SshServer({ hostKeys: [hostKey] }, client => {
    client.on('error', () => {})
    client.on('authentication', ctx => {
      if (ctx.method === 'password' && ctx.password === password) ctx.accept()
      else ctx.reject()
    })
    client.on('ready', () => {
      if (allowTcpForward) {
        client.on('tcpip', (accept, reject, info) => {
          const upstream = net.connect(info.destPort, info.destIP, () => {
            const ch = accept()
            sockets.add(upstream)
            upstream.pipe(ch).pipe(upstream)
            ch.on('close', () => upstream.destroy())
            upstream.on('close', () => { sockets.delete(upstream); try { ch.close() } catch {} })
          })
          upstream.on('error', () => reject())
        })
      }
      client.on('session', accept => {
        const session = accept()
        session.on('pty', acceptPty => { acceptPty?.() })
        session.on('exec', (acceptExec, _rejectExec, info) => {
          const stream = acceptExec()
          const result = onExec ? onExec(info.command) : { code: 0, stdout: 'OK\n', stderr: '' }
          if (result.stdout) stream.write(result.stdout)
          if (result.stderr) stream.stderr.write(result.stderr)
          stream.exit(result.code ?? 0)
          stream.end()
        })
        session.on('shell', acceptShell => {
          const stream = acceptShell()
          stream.write('diagnose> ')
          let buffer = ''
          stream.on('data', chunk => {
            buffer += chunk.toString('utf8')
            const lines = buffer.split(/\r?\n/)
            buffer = lines.pop() ?? ''
            for (const line of lines) {
              const reply = onShellLines ? onShellLines(line.trim()) : `echo:${line}\ndiagnose> `
              stream.write(reply)
            }
          })
        })
      })
    })
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  return {
    port: server.address().port,
    async close() {
      for (const s of sockets) s.destroy()
      await new Promise(resolve => server.close(() => resolve()))
    },
  }
}

test('VerificationHarness runs multi-node SSH (with jump_via tunnel) + controlled HTTP REST + phase lock + reverse cleanup', async () => {
  const tempDir = await mkdtemp(path.join(tmpdir(), 'pv-e2e-'))
  const state = {
    nicDown: false,
    daemonPid: '4242',
    luns: new Set(),
    actionLog: [],
    authHeadersSeen: [],
  }

  const jumpSsh = await startMockSshNode({
    password: 'jump-pw',
    allowTcpForward: true,
    onExec: cmd => {
      if (cmd.includes('PANGEA_PREFLIGHT_OK')) return { code: 0, stdout: 'PANGEA_PREFLIGHT_OK\n' }
      return { code: 0, stdout: 'jump-ok\n' }
    },
  })

  const hostSsh = await startMockSshNode({
    password: 'host-pw',
    onExec: cmd => {
      state.actionLog.push(`host:${cmd}`)
      if (cmd.includes('PANGEA_PREFLIGHT_OK')) return { code: 0, stdout: 'PANGEA_PREFLIGHT_OK\n' }
      if (cmd === 'ip link set ens2f0 down') {
        state.nicDown = true
        state.daemonPid = '4299' // simulate failover/respawn
        return { code: 0, stdout: 'ens2f0 down\n' }
      }
      if (cmd === 'ip link set ens2f0 up') {
        state.nicDown = false
        return { code: 0, stdout: 'ens2f0 up\n' }
      }
      return { code: 0, stdout: `ran:${cmd}\n` }
    },
  })

  const ctrlSsh = await startMockSshNode({
    password: 'ctrl-pw',
    onExec: cmd => {
      state.actionLog.push(`ctrl:${cmd}`)
      if (cmd.includes('PANGEA_PREFLIGHT_OK')) return { code: 0, stdout: 'PANGEA_PREFLIGHT_OK\n' }
      if (cmd.includes('pidof')) return { code: 0, stdout: `${state.daemonPid}\n` }
      if (cmd.startsWith('grep -aFq --')) {
        return cmd.includes('FI_MARKER_001') ? { code: 0, stdout: '' } : { code: 1, stdout: '' }
      }
      return { code: 0, stdout: 'ctrl-ok\n' }
    },
    onShellLines: line => {
      state.actionLog.push(`ctrl-pty:${line}`)
      if (line === 'inject show INJ-001') return 'INJ-001 hits=2\ndiagnose> '
      return 'ok\ndiagnose> '
    },
  })

  const apiServer = createHttpServer((req, res) => {
    state.authHeadersSeen.push(req.headers.authorization || '')
    let raw = ''
    req.on('data', c => { raw += c.toString('utf8') })
    req.on('end', () => {
      state.actionLog.push(`http:${req.method}:${req.url}`)
      if (req.headers.authorization !== 'Bearer secret-mgmt-token-999') {
        res.writeHead(401, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'bad-token' }))
        return
      }
      if (req.method === 'GET' && req.url === '/api/v1/luns') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ luns: [...state.luns] }))
        return
      }
      if (req.method === 'POST' && req.url === '/api/v1/luns') {
        const body = JSON.parse(raw || '{}')
        state.luns.add(body.id || 'lun-test-1')
        res.writeHead(201, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ created: body.id || 'lun-test-1' }))
        return
      }
      if (req.method === 'DELETE' && req.url === '/api/v1/luns/lun-test-1') {
        state.luns.delete('lun-test-1')
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ deleted: 'lun-test-1' }))
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'not-found' }))
    })
  })
  await new Promise(resolve => apiServer.listen(0, '127.0.0.1', resolve))
  const apiPort = apiServer.address().port

  try {
    const store = new TopologyStore(path.join(tempDir, 'topos.json'), { platform: 'linux' })
    await store.save({
      id: 'lab-tunneled-01',
      name: 'Tunneled Dual-Node Lab',
      nodes: {
        jump_0: {
          role: 'jump',
          ssh: { ip: '127.0.0.1', port: jumpSsh.port, username: 'jumper', auth_kind: 'password', password: 'jump-pw' },
        },
        host_0: {
          role: 'host',
          ssh: { ip: '127.0.0.1', port: hostSsh.port, username: 'root', auth_kind: 'password', password: 'host-pw' },
          protected: { mgmt_nics: ['eth0'] },
          test_resources: { data_nics: ['ens2f0'] },
        },
        ctrl_a: {
          role: 'controller',
          jump_via: 'jump_0',
          ssh: { ip: '127.0.0.1', port: ctrlSsh.port, username: 'root', auth_kind: 'password', password: 'ctrl-pw', default_process: 'san_tgt' },
          http: { base_url: `http://127.0.0.1:${apiPort}`, auth_kind: 'bearer', token: 'secret-mgmt-token-999' },
          protected: { mgmt_nics: ['mgmt0'] },
          test_resources: { processes: ['san_tgt'] },
        },
      },
    })

    const harness = new VerificationHarness({ topologies: store })
    const dataRoot = path.join(tempDir, 'data')

    const record = await harness.runTask({
      dataRoot,
      mode: 'fault_injection',
      topology_id: 'lab-tunneled-01',
      target_node: 'ctrl_a',
      target_binary: '/opt/san/bin/san_tgt',
      marker_strings: ['FI_MARKER_001'],
      points: [{ id: 'INJ-001' }],
      targets: [{ target_key: 'RISK-HA-01', title: '链路闪断并发控制风险', kind: 'risk' }],
      runWorker: async ({ cliPath, gatewayConfigPath, scratchDirectory, validateOutput }) => {
        // 1. Check initial PROBE_READONLY status
        const st1 = JSON.parse((await runCli(cliPath, ['status', '--config', gatewayConfigPath])).stdout)
        assert.equal(st1.phase, 'probe_readonly')

        // 2. Read-only HTTP GET succeeds in PROBE_READONLY (gateway injects Bearer token)
        const roGet = await runCli(cliPath, ['http', '--config', gatewayConfigPath, '--target', 'ctrl_a', '--method', 'GET', '--path', '/api/v1/luns'])
        assert.equal(roGet.ok, true)
        const roGetJson = JSON.parse(roGet.stdout)
        assert.equal(roGetJson.status_code, 200)

        // 3. Mutating SSH & HTTP POST are physically rejected before register-cleanup
        const prematureSsh = await runCli(cliPath, ['exec', '--config', gatewayConfigPath, '--target', 'host_0', '--cmd', 'ip link set ens2f0 down'])
        assert.equal(prematureSsh.ok, false)
        assert.match(prematureSsh.stderr, /PROBE_READONLY/)

        const prematurePost = await runCli(cliPath, ['http', '--config', gatewayConfigPath, '--target', 'ctrl_a', '--method', 'POST', '--path', '/api/v1/luns', '--json', '{"id":"lun-test-1"}'])
        assert.equal(prematurePost.ok, false)
        assert.match(prematurePost.stderr, /PROBE_READONLY/)

        // 4. Register SSH cleanup first, then HTTP cleanup -> unlocks ARMED
        const reg1 = await runCli(cliPath, ['register-cleanup', '--config', gatewayConfigPath, '--target', 'host_0', '--cmd', 'ip link set ens2f0 up', '--desc', '恢复业务网口'])
        assert.equal(reg1.ok, true)
        assert.equal(JSON.parse(reg1.stdout).phase, 'armed')

        const reg2 = await runCli(cliPath, ['register-cleanup', '--config', gatewayConfigPath, '--kind', 'http', '--target', 'ctrl_a', '--method', 'DELETE', '--path', '/api/v1/luns/lun-test-1', '--desc', '删除测试 LUN'])
        assert.equal(reg2.ok, true)

        // 5. Execute HTTP provisioning + SSH data NIC flap + interactive PTY hit check over jump_via tunnel
        const createLun = JSON.parse((await runCli(cliPath, ['http', '--config', gatewayConfigPath, '--target', 'ctrl_a', '--method', 'POST', '--path', '/api/v1/luns', '--json', '{"id":"lun-test-1"}'])).stdout)
        assert.equal(createLun.status_code, 201)
        assert.equal(state.luns.has('lun-test-1'), true)

        const flapNic = JSON.parse((await runCli(cliPath, ['exec', '--config', gatewayConfigPath, '--target', 'host_0', '--cmd', 'ip link set ens2f0 down'])).stdout)
        assert.equal(flapNic.success, true)
        assert.equal(state.nicDown, true)

        const exFile = path.join(scratchDirectory, 'ex.json')
        await writeFile(exFile, JSON.stringify([
          { expect: 'diagnose>' },
          { send: 'inject show INJ-001', expect: 'INJ-001 hits=2' },
        ]), 'utf8')
        const ptyRes = JSON.parse((await runCli(cliPath, ['interactive', '--config', gatewayConfigPath, '--target', 'ctrl_a', '--exchanges-file', exFile])).stdout)
        assert.equal(ptyRes.success, true)

        // 6. Verify deterministic output gate catches forged command_id and zero hits
        assert.equal(validateOutput({
          summary: 'bad',
          items: [{ target_key: 'RISK-HA-01', verdict: 'confirmed', hits: 'INJ-001=0', evidence_command_ids: [flapNic.command_id] }],
        }).ok, false)
        assert.equal(validateOutput({
          summary: 'forged',
          items: [{ target_key: 'RISK-HA-01', verdict: 'confirmed', hits: 'INJ-001=2', evidence_command_ids: ['cmd-9999'] }],
        }).ok, false)

        return {
          summary: '链路闪断触发守护进程重启，风险实锤',
          items: [{
            target_key: 'RISK-HA-01',
            verdict: 'confirmed',
            hits: 'INJ-001=2',
            evidence_command_ids: [createLun.command_id, flapNic.command_id, ptyRes.command_id],
            observed_behavior: 'ens2f0 down 后观测到 INJ-001 命中 2 次且守护进程 PID 发生变更',
            cleanup_verified: true,
          }],
        }
      },
    })

    assert.equal(record.status, 'completed')
    assert.equal(record.draft_verdicts[0].verdict, 'confirmed')
    assert.equal(record.cleanup.status, 'ok')
    assert.equal(record.cleanup.steps.length, 2)
    // Reverse order cleanup: HTTP DELETE (registered 2nd) ran before SSH ens2f0 up (registered 1st)
    assert.equal(record.cleanup.steps[0].kind, 'http')
    assert.equal(record.cleanup.steps[1].kind, 'ssh')
    assert.equal(state.luns.size, 0)
    assert.equal(state.nicDown, false)
    // Post-check detected PID respawn (4242 -> 4299)
    assert.equal(record.cleanup.post_check.baseline_pid, '4242')
    assert.equal(record.cleanup.post_check.pid_changed, true)
    assert.equal(record.cleanup.post_check.process_alive, true)
    assert.deepEqual(harness.getLocks(), {})
  } finally {
    await new Promise(resolve => apiServer.close(() => resolve()))
    await Promise.all([ctrlSsh.close(), hostSsh.close(), jumpSsh.close()])
    await rm(tempDir, { recursive: true, force: true })
  }
})
