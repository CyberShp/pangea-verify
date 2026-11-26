import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { spawn } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import ssh2 from 'ssh2'
import {
  KnowledgePack,
  TopologyStore,
  VerificationHarness,
  createAcpWorkerAdapter,
  runAutonomousVerification,
} from '../src/index.js'

const { Server: SshServer } = ssh2
const CLI_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'cli.mjs')

async function startLabNode({ onExec }) {
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
        session.on('pty', acceptPty => { acceptPty?.() })
        session.on('exec', (acceptExec, _reject, info) => {
          const stream = acceptExec()
          const res = onExec(info.command)
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

function createMcpClient(args) {
  const child = spawn(process.execPath, [CLI_PATH, ...args], { stdio: ['pipe', 'pipe', 'pipe'] })
  let nextId = 1
  let buf = ''
  const pending = new Map()

  child.stdout.on('data', chunk => {
    buf += chunk.toString('utf8')
    let idx
    while ((idx = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, idx).trim()
      buf = buf.slice(idx + 1)
      if (!line) continue
      const msg = JSON.parse(line)
      const resolver = pending.get(msg.id)
      if (resolver) {
        pending.delete(msg.id)
        resolver(msg)
      }
    }
  })

  const rpc = (method, params = {}) => new Promise((resolve, reject) => {
    const id = nextId
    nextId += 1
    const timer = setTimeout(() => {
      pending.delete(id)
      reject(new Error(`MCP RPC timeout: ${method}`))
    }, 15_000)
    pending.set(id, msg => {
      clearTimeout(timer)
      resolve(msg)
    })
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
  })

  const callTool = async (name, toolArgs = {}) => {
    const resp = await rpc('tools/call', { name, arguments: toolArgs })
    assert.ok(resp.result, `MCP tool ${name} missing result: ${JSON.stringify(resp)}`)
    const text = resp.result.content?.[0]?.text || '{}'
    return { isError: Boolean(resp.result.isError), data: JSON.parse(text) }
  }

  return {
    rpc,
    callTool,
    async close() {
      child.stdin.end()
      await new Promise(resolve => child.once('close', resolve))
    },
  }
}

test('Full Phase-2 lifecycle: MCP trainer distills legacy Python + XML topo -> promotes verified card -> ACP runner executes on brand-new topo with repair & Gate-4 feedback', async () => {
  const tempDir = await mkdtemp(path.join(tmpdir(), 'pv-phase2-e2e-'))
  const packDir = path.join(tempDir, 'knowledge-pack')
  const storePath = path.join(tempDir, 'topos.json')
  const dataRoot = path.join(tempDir, 'runtime-data')

  const labA = await startLabNode({
    onExec: cmd => ({ code: 0, stdout: `labA:${cmd}\n` }),
  })
  const labB = await startLabNode({
    onExec: cmd => {
      if (cmd.includes('PANGEA_VERIFY_PREFLIGHT_OK')) return { code: 0, stdout: 'PANGEA_VERIFY_PREFLIGHT_OK\n' }
      return { code: 0, stdout: `labB:${cmd}\n` }
    },
  })

  try {
    // 1. Prepare sanitized legacy Python repo, C source repo, raw XML topo, and deterministic topo-adapter
    const legacyPyDir = path.join(tempDir, 'legacy_py')
    const targetSrcDir = path.join(tempDir, 'target_src')
    await mkdir(legacyPyDir, { recursive: true })
    await mkdir(path.join(targetSrcDir, 'src', 'multipath'), { recursive: true })

    await writeFile(path.join(legacyPyDir, 'mp_helper.py'), [
      'import xml.etree.ElementTree as ET',
      'class MultipathHelper:',
      '    def down_data_port(self, nic):',
      '        return f"ip link set {nic} down"',
    ].join('\n'), 'utf8')

    await writeFile(path.join(targetSrcDir, 'src', 'multipath', 'mp_cli.c'), 'REGISTER_CLI("mp show paths");\n', 'utf8')

    const rawTopoXmlPath = path.join(tempDir, 'lab-a-topo.xml')
    await writeFile(rawTopoXmlPath, `<topo id="lab-a" host_ip="127.0.0.1" host_port="${labA.port}" mgmt_nic="eth0" data_nic="ens4f0"/>`, 'utf8')

    const adapterPath = path.join(packDir, 'topo-adapters', 'xml-lab-adapter.mjs')
    await mkdir(path.dirname(adapterPath), { recursive: true })
    await writeFile(adapterPath, [
      'export function adaptTopology(raw) {',
      '  const attr = name => (new RegExp(`${name}="([^"]+)"`).exec(raw) || [])[1]',
      '  return {',
      '    id: attr("id"),',
      '    name: `XML Lab ${attr("id")}`,',
      '    nodes: {',
      '      host_0: {',
      '        role: "host",',
      '        ssh: { ip: attr("host_ip"), port: Number(attr("host_port")), username: "root", auth_kind: "password", password: "pw" },',
      '        protected: { mgmt_nics: [attr("mgmt_nic")] },',
      '        test_resources: { data_nics: [attr("data_nic")] },',
      '      },',
      '    },',
      '  }',
      '}',
    ].join('\n'), 'utf8')

    // 2. Trainer mode over real stdio MCP server
    const mcp = createMcpClient(['mcp', '--store', storePath, '--pack', packDir, '--data-root', dataRoot])
    try {
      const initRes = await mcp.rpc('initialize', {})
      assert.equal(initRes.result.serverInfo.name, 'pangea-verify')

      const toolsRes = await mcp.rpc('tools/list', {})
      assert.ok(toolsRes.result.tools.length >= 15)

      const pyIdx = await mcp.callTool('code_index_python', { root_dir: legacyPyDir, topo_only: true })
      assert.equal(pyIdx.isError, false)
      assert.equal(pyIdx.data.matched_files, 1)

      const cliScan = await mcp.callTool('code_scan_cli', { root_dir: targetSrcDir, save_map_name: 'storage-core' })
      assert.equal(cliScan.isError, false)
      assert.equal(cliScan.data.total_entries, 1)

      const adapted = await mcp.callTool('topology_adapt', {
        adapter_path: adapterPath,
        raw_file_path: rawTopoXmlPath,
        save: true,
      })
      assert.equal(adapted.isError, false)
      assert.equal(adapted.data.saved, true)

      // Save parameterized draft card
      const draft = await mcp.callTool('knowledge_save_draft', {
        topology_id: 'lab-a',
        card: {
          id: 'mp.port.flap',
          title: '多路径业务口闪断',
          domain: 'multipath',
          intent: '拉低主机业务数据口触发路径切换并恢复',
          source_modules: ['src/multipath'],
          required_roles: ['host'],
          side_effect: 'mutating',
          precheck: 'ip -br link show ${node.host.data_nics[0]}',
          execute: 'ip link set ${node.host.data_nics[0]} down',
          verify_effect: 'ip -br link show ${node.host.data_nics[0]}',
          cleanup: 'ip link set ${node.host.data_nics[0]} up',
        },
      })
      assert.equal(draft.isError, false)

      // Live trial on Lab A through phase-gated MCP gateway
      const started = await mcp.callTool('session_start', { topology_id: 'lab-a' })
      assert.equal(started.isError, false)
      const sessionId = started.data.session_id
      assert.equal(started.data.phase, 'probe_readonly')

      const preCmd = await mcp.callTool('gateway_exec', { session_id: sessionId, target: 'host_0', command: 'ip -br link show ens4f0' })
      assert.equal(preCmd.isError, false)

      const regClean = await mcp.callTool('gateway_register_cleanup', {
        session_id: sessionId,
        target: 'host_0',
        command: 'ip link set ens4f0 up',
        description: 'restore ens4f0',
      })
      assert.equal(regClean.isError, false)
      assert.equal(regClean.data.phase, 'armed')

      const execCmd = await mcp.callTool('gateway_exec', { session_id: sessionId, target: 'host_0', command: 'ip link set ens4f0 down' })
      assert.equal(execCmd.isError, false)

      const cleaned = await mcp.callTool('gateway_run_cleanups', { session_id: sessionId })
      assert.equal(cleaned.isError, false)
      const cleanupCmdId = cleaned.data.steps[0].command_id

      // Promote draft -> verified using authentic transcript command_ids
      const promoted = await mcp.callTool('knowledge_promote_card', {
        card_id: 'mp.port.flap',
        session_id: sessionId,
        command_ids: [preCmd.data.command_id, execCmd.data.command_id, cleanupCmdId],
        firmware_hint: 'OS-5.0',
        topology_id: 'lab-a',
      })
      assert.equal(promoted.isError, false)
      assert.equal(promoted.data.status, 'verified')

      const closed = await mcp.callTool('session_close', { session_id: sessionId })
      assert.equal(closed.isError, false)
    } finally {
      await mcp.close()
    }

    // 3. Autonomous ACP batch verification on a BRAND-NEW topology B (different port & NIC name)
    const store = new TopologyStore(storePath, { platform: 'linux' })
    await store.save({
      id: 'lab-b-fresh',
      name: 'Brand New Lab B',
      nodes: {
        host_0: {
          role: 'host',
          ssh: { ip: '127.0.0.1', port: labB.port, username: 'root', auth_kind: 'password', password: 'pw' },
          protected: { mgmt_nics: ['eno1'] },
          test_resources: { data_nics: ['ens9f1'] },
        },
      },
    })

    const harness = new VerificationHarness({ topologies: store })
    let seenInputJson = null
    let repairTurnCount = 0

    const workerAdapter = createAcpWorkerAdapter({
      maxRepairTurns: 1,
      launchSession: async ({ inputPath, outputPath, gatewayUrl, gatewayToken }) => {
        seenInputJson = JSON.parse(await readFile(inputPath, 'utf8'))

        // Execute real gateway calls on Lab B
        const callGw = async (route, body) => {
          const r = await fetch(`${gatewayUrl}${route}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${gatewayToken}` },
            body: JSON.stringify(body),
          })
          return await r.json()
        }
        await callGw('/register-cleanup', { target: 'host_0', command: 'ip link set ens9f1 up', description: 'restore ens9f1' })
        const execOut = await callGw('/exec', { target: 'host_0', command: 'ip link set ens9f1 down' })

        // First write intentionally uses a forged command_id to test single-worker repair continuation
        await writeFile(outputPath, JSON.stringify({
          summary: 'draft bad',
          items: [{ target_key: 'CASE-MP-01', verdict: 'excluded', evidence_command_ids: ['cmd-9999'] }],
        }), 'utf8')

        return {
          result: Promise.resolve(),
          continuePrompt: async repairPrompt => {
            repairTurnCount += 1
            assert.match(repairPrompt, /cmd-9999/)
            await writeFile(outputPath, JSON.stringify({
              summary: 'Lab B 实测链路切换正常',
              items: [{
                target_key: 'CASE-MP-01',
                verdict: 'excluded',
                evidence_command_ids: [execOut.command_id],
                observed_behavior: 'ens9f1 闪断后多路径切换正常',
                cleanup_verified: true,
              }],
              card_feedback: [{
                card_id: 'mp.port.flap',
                command_id: execOut.command_id,
                error_summary: 'OS-6.0 requires extra 2s settle delay',
              }],
            }), 'utf8')
          },
          dispose: async () => {},
        }
      },
    })

    const { record, recorded_feedback } = await runAutonomousVerification({
      harness,
      packDir,
      workerAdapter,
      firmwareHint: 'OS-6.0',
      taskInput: {
        dataRoot,
        topology_id: 'lab-b-fresh',
        targets: [{
          target_key: 'CASE-MP-01',
          title: '多路径闪断容错核验',
          source_evidence: ['repo:src/multipath/switchover.c:88'],
        }],
      },
    })

    assert.equal(record.status, 'completed')
    assert.equal(repairTurnCount, 1)
    assert.equal(record.draft_verdicts[0].verdict, 'excluded')
    // Verify ACP worker automatically received the promoted card AND white-box CLI hints from code-maps
    assert.equal(seenInputJson.knowledge_catalog.cards.length, 1)
    assert.equal(seenInputJson.knowledge_catalog.cards[0].id, 'mp.port.flap')
    assert.equal(seenInputJson.knowledge_catalog.code_cli_hints.length, 1)
    assert.equal(seenInputJson.knowledge_catalog.code_cli_hints[0].command, 'mp show paths')
    // Verify Gate-4 feedback was recorded without mutating verified card
    assert.equal(recorded_feedback.length, 1)
    const pack = new KnowledgePack(packDir)
    const fb = await pack.readFeedback('mp.port.flap')
    assert.equal(fb.length, 1)
    assert.match(fb[0].error_summary, /settle delay/)
  } finally {
    await Promise.all([labA.close(), labB.close()])
    await rm(tempDir, { recursive: true, force: true })
  }
})
