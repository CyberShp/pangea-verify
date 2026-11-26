import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import ssh2 from 'ssh2'
import {
  KnowledgePack,
  normalizeTopology,
  resolveTopologySecrets,
  startGatewaySession,
} from '../src/index.js'

const { Server: SshServer } = ssh2

async function startSimpleSshServer() {
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
          if (info.command.includes('FAIL_ME')) {
            stream.stderr.write('command failed\n')
            stream.exit(2)
          } else {
            stream.write(`ok:${info.command}\n`)
            stream.exit(0)
          }
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

test('KnowledgePack enforces all 4 promotion gates: de-binding, cleanup pairing, live transcript proof, and read-only batch feedback', async () => {
  const tempDir = await mkdtemp(path.join(tmpdir(), 'pv-kp-'))
  const sshSrv = await startSimpleSshServer()
  try {
    const packDir = path.join(tempDir, 'knowledge-pack')
    const pack = new KnowledgePack(packDir)

    const rawTopo = await normalizeTopology({
      id: 'topo-san-lab',
      name: 'SAN Lab',
      nodes: {
        host_0: {
          role: 'host',
          ssh: { ip: '127.0.0.1', port: sshSrv.port, username: 'tester01', auth_kind: 'password', password: 'pw' },
          protected: { mgmt_ips: ['10.24.8.11'], mgmt_nics: ['eth0'], boot_disks: ['/dev/sda'] },
          test_resources: {
            data_nics: ['ens3f0'],
            data_ips: ['192.168.55.11'],
            block_devices: ['/dev/disk/by-id/wwn-0x600a0980001'],
            paths: ['/dev/shm'],
          },
        },
      },
    }, { keyDir: tempDir, platform: 'linux' })

    // Gate 1a: Rejects hardcoded topology IP (192.168.55.11 / 10.24.8.11)
    await assert.rejects(
      () => pack.saveDraft({
        id: 'san.iscsi.login',
        title: 'iSCSI 登录挂载',
        domain: 'san',
        intent: '主机侧发现并登录阵列目标器',
        required_roles: ['host'],
        side_effect: 'mutating',
        precheck: 'which iscsiadm',
        execute: 'iscsiadm -m discovery -t st -p 192.168.55.11:3260 --login',
        verify_effect: 'iscsiadm -m session',
        cleanup: 'iscsiadm -m node --logoutall=all',
      }, { topology: rawTopo }),
      err => err.code === 'HARDCODED_TOPOLOGY_LITERAL',
    )

    // Gate 1b: Rejects volatile bare disk (/dev/sdb)
    await assert.rejects(
      () => pack.saveDraft({
        id: 'io.fio.randwrite',
        title: 'FIO 随机写激励',
        domain: 'block_io',
        intent: '对目标测试盘下发带校验随机写',
        required_roles: ['host'],
        side_effect: 'mutating',
        precheck: 'which fio',
        execute: 'fio --name=job1 --filename=/dev/sdb --rw=randwrite --size=64M',
        verify_effect: 'echo ok',
        cleanup: 'pkill fio || true',
      }, { topology: rawTopo }),
      err => err.code === 'VOLATILE_DEVICE_LITERAL',
    )

    // Gate 2: Rejects mutating card without cleanup
    await assert.rejects(
      () => pack.saveDraft({
        id: 'fault.nic.flap',
        title: '业务网口闪断',
        domain: 'network_fault',
        intent: '拉低业务数据口触发多路径切换',
        required_roles: ['host'],
        side_effect: 'mutating',
        precheck: 'ip link show ${node.host.data_nics[0]}',
        execute: 'ip link set ${node.host.data_nics[0]} down',
        verify_effect: 'ip link show ${node.host.data_nics[0]}',
        cleanup: '',
      }, { topology: rawTopo }),
      /必须绑定非空 cleanup/,
    )

    // Valid parameterized draft passes Gate 1 & Gate 2, stays isolated from batch catalog
    await pack.saveDraft({
      id: 'fault.nic.flap',
      title: '业务网口闪断',
      domain: 'network_fault',
      intent: '拉低主机业务网口触发多路径切换并恢复',
      source_modules: ['src/multipath', 'src/iscsi'],
      required_roles: ['host'],
      side_effect: 'mutating',
      precheck: 'ip link show ${node.host.data_nics[0]}',
      execute: 'ip link set ${node.host.data_nics[0]} down',
      verify_effect: 'ip -br link show ${node.host.data_nics[0]}',
      cleanup: 'ip link set ${node.host.data_nics[0]} up',
    }, { topology: rawTopo })

    assert.equal((await pack.queryCatalog({ includeDrafts: false })).length, 0)
    assert.equal((await pack.queryCatalog({ includeDrafts: true })).length, 1)

    // Gate 3: Live trial via GatewaySession produces authentic transcript.jsonl
    const resolvedTopo = await resolveTopologySecrets(rawTopo, { keyDir: tempDir, platform: 'linux' })
    const transcriptPath = path.join(tempDir, 'trainer-session', 'transcript.jsonl')
    const gw = await startGatewaySession({
      sessionId: 'train-01',
      resolvedTopology: resolvedTopo,
      transcriptPath,
      actorPhaseLabel: 'trainer',
    })

    const callGw = async (route, payload) => {
      const r = await fetch(`${gw.gatewayUrl}${route}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${gw.token}` },
        body: JSON.stringify(payload),
      })
      return { status: r.status, body: await r.json() }
    }

    const pre = await callGw('/exec', { target: 'host_0', command: 'ip link show ens3f0' })
    assert.equal(pre.status, 200)

    const blockedBeforeArm = await callGw('/exec', { target: 'host_0', command: 'ip link set ens3f0 down' })
    assert.equal(blockedBeforeArm.status, 403)

    await callGw('/register-cleanup', { target: 'host_0', command: 'ip link set ens3f0 up', description: 'restore ens3f0' })
    const execRes = await callGw('/exec', { target: 'host_0', command: 'ip link set ens3f0 down' })
    assert.equal(execRes.status, 200)

    const failedCmd = await callGw('/exec', { target: 'host_0', command: 'echo FAIL_ME' })
    assert.equal(failedCmd.body.success, false)

    // Promoting BEFORE running cleanup must fail for a mutating card!
    await assert.rejects(
      () => pack.promoteCard({
        cardId: 'fault.nic.flap',
        transcriptPath,
        commandIds: [pre.body.command_id, execRes.body.command_id],
      }),
      /phase="cleanup"/,
    )

    // Promoting with a blocked or failed command_id must fail!
    const cleanupRun = await callGw('/run-cleanups', {})
    assert.equal(cleanupRun.body.ok, true)
    const cleanupCmdId = cleanupRun.body.steps[0].command_id
    await gw.close({ runCleanups: false })

    await assert.rejects(
      () => pack.promoteCard({
        cardId: 'fault.nic.flap',
        transcriptPath,
        commandIds: [blockedBeforeArm.body.command_id, cleanupCmdId],
      }),
      /被安全策略拦截/,
    )
    await assert.rejects(
      () => pack.promoteCard({
        cardId: 'fault.nic.flap',
        transcriptPath,
        commandIds: [failedCmd.body.command_id, cleanupCmdId],
      }),
      /未执行成功/,
    )

    // Promoting with authentic precheck + execute + cleanup command_ids succeeds!
    const promoted = await pack.promoteCard({
      cardId: 'fault.nic.flap',
      transcriptPath,
      commandIds: [pre.body.command_id, execRes.body.command_id, cleanupCmdId],
      firmwareHint: 'StorageOS 5.2',
      topology: rawTopo,
    })
    assert.equal(promoted.status, 'verified')
    assert.ok(promoted.proof.transcript_sha256.length === 64)

    // Verified card is now discoverable by module/role/keyword in batch catalog
    const matched = await pack.queryCatalog({ sourceModule: 'src/iscsi', role: 'host' })
    assert.equal(matched.length, 1)
    assert.equal(matched[0].id, 'fault.nic.flap')
    assert.equal(matched[0].mismatch_count, 0)

    // Gate 4: Batch mismatch records feedback without altering verified card content
    const verifiedBefore = await readFile(pack.cardPath('verified', 'fault.nic.flap'), 'utf8')
    await pack.recordFeedback({
      cardId: 'fault.nic.flap',
      sessionId: 'pv-batch-09',
      commandId: 'cmd-0004',
      errorSummary: 'Firmware 6.0 uses ip-netns isolated data plane',
      firmwareHint: 'StorageOS 6.0',
    })
    const verifiedAfter = await readFile(pack.cardPath('verified', 'fault.nic.flap'), 'utf8')
    assert.equal(verifiedAfter, verifiedBefore)

    const catalogAfterFeedback = await pack.queryCatalog({ keyword: '闪断' })
    assert.equal(catalogAfterFeedback[0].mismatch_count, 1)
    const feedbacks = await pack.readFeedback('fault.nic.flap')
    assert.equal(feedbacks.length, 1)
    assert.match(feedbacks[0].error_summary, /Firmware 6\.0/)
  } finally {
    await sshSrv.close()
    await rm(tempDir, { recursive: true, force: true })
  }
})

test('CLI supports kp-draft, kp-attest, kp-catalog, kp-card, and background SSH job lifecycle', async () => {
  const { execFile } = await import('node:child_process')
  const { fileURLToPath } = await import('node:url')
  const cliPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'cli.mjs')
  const execCli = args => new Promise((resolve, reject) => {
    execFile(process.execPath, [cliPath, ...args], { timeout: 15_000 }, (err, stdout, stderr) => {
      if (err) reject(new Error(stderr || err.message))
      else resolve(JSON.parse(stdout))
    })
  })

  const tempDir = await mkdtemp(path.join(tmpdir(), 'pv-cli-'))
  const sshSrv = await startSimpleSshServer()
  try {
    const packDir = path.join(tempDir, 'kp')
    const draftRes = await execCli([
      'kp-draft',
      '--pack', packDir,
      '--card', JSON.stringify({
        id: 'raid.rebuild.status',
        title: '查询 RAID 重构进度',
        domain: 'raid',
        intent: '只读查看阵列重构状态与百分比',
        required_roles: ['controller'],
        side_effect: 'readonly',
        execute: 'raid_cli show rebuild',
        verify_effect: 'grep -q rebuild_state',
      }),
    ])
    assert.equal(draftRes.status, 'draft')

    const attested = await execCli([
      'kp-attest',
      '--pack', packDir,
      '--id', 'raid.rebuild.status',
      '--by', 'senior-qa',
      '--reason', '只读查询命令已在离线手册核对',
    ])
    assert.equal(attested.status, 'human_attested')

    const catalog = await execCli(['kp-catalog', '--pack', packDir, '--domain', 'raid'])
    assert.equal(catalog.length, 1)
    assert.equal(catalog[0].id, 'raid.rebuild.status')

    const fullCard = await execCli(['kp-card', '--pack', packDir, '--id', 'raid.rebuild.status'])
    assert.equal(fullCard.execute[0], 'raid_cli show rebuild')

    // Test bg-start -> bg-read -> bg-stop over CLI gateway
    const rawTopo = await normalizeTopology({
      id: 'bg-topo',
      name: 'BG Lab',
      nodes: {
        host_0: {
          role: 'host',
          ssh: { ip: '127.0.0.1', port: sshSrv.port, username: 'root', auth_kind: 'password', password: 'pw' },
        },
      },
    }, { keyDir: tempDir, platform: 'linux' })
    const resolved = await resolveTopologySecrets(rawTopo, { keyDir: tempDir, platform: 'linux' })
    const cfgPath = path.join(tempDir, '.gw.json')
    const gw = await startGatewaySession({
      sessionId: 'bg-01',
      resolvedTopology: resolved,
      transcriptPath: path.join(tempDir, 'transcript.jsonl'),
      gatewayConfigPath: cfgPath,
    })
    try {
      const started = await execCli(['bg-start', '--config', cfgPath, '--target', 'host_0', '--cmd', 'iostat -x 1'])
      assert.ok(started.job_id)
      const readRes = await execCli(['bg-read', '--config', cfgPath, '--job-id', started.job_id, '--wait-ms', '100'])
      assert.match(readRes.stdout, /ok:iostat -x 1/)
      const stopped = await execCli(['bg-stop', '--config', cfgPath, '--job-id', started.job_id])
      assert.equal(stopped.running, false)
    } finally {
      await gw.close()
    }
  } finally {
    await sshSrv.close()
    await rm(tempDir, { recursive: true, force: true })
  }
})

