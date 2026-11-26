import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import {
  TopologyStore,
  adaptTopologyFile,
  evaluateCommandSafety,
  evaluateHttpSafety,
  normalizeTopology,
} from '../src/index.js'

function sampleTopologyInput() {
  return {
    id: 'san-dual-ctrl-01',
    name: '双控 SAN 靶场 01',
    vars: { iscsi_port: 3260 },
    nodes: {
      jump_0: {
        role: 'jump',
        ssh: { ip: '10.10.0.1', port: 22, username: 'jumper', auth_kind: 'password', password: 'jump-secret-value' },
        protected: { mgmt_nics: ['eth0'] },
      },
      host_0: {
        role: 'host',
        ssh: { ip: '10.10.1.11', port: 22, username: 'root', auth_kind: 'password', password: 'host-secret-value' },
        protected: { mgmt_nics: ['eno1'], boot_disks: ['/dev/sda'] },
        test_resources: {
          data_nics: ['ens2f0', 'ens2f1'],
          data_ips: ['192.168.100.11'],
          block_devices: ['/dev/disk/by-id/wwn-0x600507680c800001'],
          processes: ['multipathd'],
          paths: ['/dev/shm', '/tmp/pangea'],
        },
      },
      ctrl_a: {
        role: 'controller',
        jump_via: 'jump_0',
        ssh: { ip: '172.16.0.101', port: 22, username: 'root', auth_kind: 'password', password: 'ctrl-secret-value', default_process: 'san_tgt' },
        http: {
          base_url: 'https://10.10.2.101:8443',
          verify_tls: false,
          auth_kind: 'bearer',
          token: 'array-bearer-secret-token',
          allow_readonly_post_paths: ['/api/v1/graphql-query'],
        },
        protected: { mgmt_nics: ['mgmt0'] },
        test_resources: {
          data_nics: ['port_p0'],
          processes: ['san_tgt'],
          paths: ['/dev/shm'],
        },
      },
    },
  }
}

test('TopologyStore encrypts secrets at rest, redacts listings, and resolves secrets in memory', async () => {
  const tempDir = await mkdtemp(path.join(tmpdir(), 'pv-topo-'))
  try {
    const storeFile = path.join(tempDir, 'topologies.json')
    const store = new TopologyStore(storeFile, { platform: 'linux' })
    const saved = await store.save(sampleTopologyInput())

    assert.equal(saved.id, 'san-dual-ctrl-01')
    assert.equal(saved.nodes.host_0.ssh.has_password, true)
    assert.equal(saved.nodes.host_0.ssh.password, undefined)
    assert.equal(saved.nodes.ctrl_a.http.has_secret, true)
    assert.equal(saved.nodes.ctrl_a.http.secret, undefined)
    assert.ok(saved.nodes.ctrl_a.protected.mgmt_ips.includes('172.16.0.101'))
    assert.ok(saved.nodes.ctrl_a.protected.mgmt_ips.includes('10.10.2.101'))

    const rawOnDisk = await readFile(storeFile, 'utf8')
    assert.equal(rawOnDisk.includes('host-secret-value'), false)
    assert.equal(rawOnDisk.includes('array-bearer-secret-token'), false)

    const resolved = await store.getResolved('san-dual-ctrl-01')
    assert.equal(resolved.nodes.host_0.ssh.password, 'host-secret-value')
    assert.equal(resolved.nodes.ctrl_a.http.secret, 'array-bearer-secret-token')
  } finally {
    await rm(tempDir, { recursive: true, force: true })
  }
})

test('normalizeTopology rejects volatile bare disks, mgmt/test conflicts, and jump_via cycles', async () => {
  const tempDir = await mkdtemp(path.join(tmpdir(), 'pv-topo-invalid-'))
  try {
    const badDisk = sampleTopologyInput()
    badDisk.nodes.host_0.test_resources.block_devices = ['/dev/sdb']
    await assert.rejects(
      () => normalizeTopology(badDisk, { keyDir: tempDir, platform: 'linux' }),
      /不允许使用易漂移裸盘符/,
    )

    const nicConflict = sampleTopologyInput()
    nicConflict.nodes.host_0.test_resources.data_nics = ['eno1']
    await assert.rejects(
      () => normalizeTopology(nicConflict, { keyDir: tempDir, platform: 'linux' }),
      /与 protected\.mgmt_nics 管理网口冲突/,
    )

    const jumpCycle = sampleTopologyInput()
    jumpCycle.nodes.jump_0.jump_via = 'ctrl_a'
    await assert.rejects(
      () => normalizeTopology(jumpCycle, { keyDir: tempDir, platform: 'linux' }),
      /jump_via 跳板链路存在环路/,
    )
  } finally {
    await rm(tempDir, { recursive: true, force: true })
  }
})

test('adaptTopologyFile deterministically transforms legacy lab config with 0 LLM involvement', async () => {
  const tempDir = await mkdtemp(path.join(tmpdir(), 'pv-adapter-'))
  try {
    const adapterFile = path.join(tempDir, 'legacy-adapter.mjs')
    await writeFile(adapterFile, [
      'export function adaptTopology(raw) {',
      '  const data = JSON.parse(raw)',
      '  return {',
      '    id: data.envCode,',
      '    name: `Adapted ${data.envCode}`,',
      '    nodes: {',
      '      host_0: {',
      '        role: "host",',
      '        ssh: { ip: data.initiatorIp, username: "root", auth_kind: "password", password: data.pw },',
      '        protected: { mgmt_nics: [data.mgmtNic] },',
      '        test_resources: { data_nics: data.bizNics, block_devices: [data.lunById] },',
      '      },',
      '    },',
      '  }',
      '}',
    ].join('\n'), 'utf8')

    const adapted = await adaptTopologyFile(adapterFile, JSON.stringify({
      envCode: 'lab-09',
      initiatorIp: '10.90.1.5',
      pw: 'sec-09',
      mgmtNic: 'eth0',
      bizNics: ['eth2', 'eth3'],
      lunById: '/dev/disk/by-id/wwn-0x6000000000000009',
    }))
    const normalized = await normalizeTopology(adapted, { keyDir: tempDir, platform: 'linux' })
    assert.equal(normalized.id, 'lab-09')
    assert.deepEqual(normalized.nodes.host_0.test_resources.data_nics, ['eth2', 'eth3'])
  } finally {
    await rm(tempDir, { recursive: true, force: true })
  }
})

test('safety-policy enforces PROBE_READONLY physical lock and ARMED resource whitelists', async () => {
  const tempDir = await mkdtemp(path.join(tmpdir(), 'pv-safety-'))
  try {
    const topo = await normalizeTopology(sampleTopologyInput(), { keyDir: tempDir, platform: 'linux' })
    const hostNode = topo.nodes.host_0
    const ctrlNode = topo.nodes.ctrl_a

    // Safe read-only commands (including 2>/dev/null redirects) pass in probe_readonly
    assert.equal(evaluateCommandSafety('pidof san_tgt 2>/dev/null || pgrep -x san_tgt 2>/dev/null', { phase: 'probe_readonly', node: ctrlNode }).blocked, false)
    assert.equal(evaluateCommandSafety('multipath -ll && ip -br link show', { phase: 'probe_readonly', node: hostNode }).blocked, false)
    assert.equal(evaluateHttpSafety({ method: 'GET', path: '/api/v1/luns' }, { phase: 'probe_readonly', node: ctrlNode }).blocked, false)
    assert.equal(evaluateHttpSafety({ method: 'POST', path: '/api/v1/graphql-query' }, { phase: 'probe_readonly', node: ctrlNode }).blocked, false)

    // Mutating operations are physically locked in probe_readonly EVEN on whitelisted resources
    const roNic = evaluateCommandSafety('ip link set ens2f0 down', { phase: 'probe_readonly', node: hostNode })
    assert.equal(roNic.blocked, true)
    assert.equal(roNic.code, 'PHASE_READONLY_LOCKED')

    const roWrite = evaluateCommandSafety('echo 1 > /dev/shm/inject_once', { phase: 'probe_readonly', node: ctrlNode })
    assert.equal(roWrite.blocked, true)
    assert.equal(roWrite.code, 'PHASE_READONLY_LOCKED')

    const roHttp = evaluateHttpSafety({ method: 'POST', path: '/api/v1/luns' }, { phase: 'probe_readonly', node: ctrlNode })
    assert.equal(roHttp.blocked, true)
    assert.equal(roHttp.code, 'PHASE_READONLY_LOCKED')

    // Once ARMED, whitelisted data_nics, stable block_devices, scratch files, and HTTP POST are unlocked
    assert.equal(evaluateCommandSafety('ip link set ens2f0 down', { phase: 'armed', node: hostNode }).blocked, false)
    assert.equal(evaluateCommandSafety('dd if=/dev/zero of=/dev/disk/by-id/wwn-0x600507680c800001 bs=4k count=4 oflag=direct', { phase: 'armed', node: hostNode }).blocked, false)
    assert.equal(evaluateCommandSafety('echo 1 > /dev/shm/inject_once', { phase: 'armed', node: ctrlNode }).blocked, false)
    assert.equal(evaluateCommandSafety('pkill san_tgt', { phase: 'armed', node: ctrlNode }).blocked, false)
    assert.equal(evaluateHttpSafety({ method: 'POST', path: '/api/v1/luns' }, { phase: 'armed', node: ctrlNode }).blocked, false)

    // Protected management NICs, boot disks, non-whitelisted NICs/procs, and root wipe remain strictly blocked even when ARMED
    const mgmtNicRes = evaluateCommandSafety('ip link set eno1 down', { phase: 'armed', node: hostNode })
    assert.equal(mgmtNicRes.blocked, true)
    assert.equal(mgmtNicRes.code, 'PROTECTED_MGMT_NIC')

    const unknownNicRes = evaluateCommandSafety('ip link set eth9 down', { phase: 'armed', node: hostNode })
    assert.equal(unknownNicRes.blocked, true)
    assert.equal(unknownNicRes.code, 'NIC_NOT_IN_TEST_RESOURCES')

    const bootDiskRes = evaluateCommandSafety('dd if=/dev/zero of=/dev/sda bs=1M count=1', { phase: 'armed', node: hostNode })
    assert.equal(bootDiskRes.blocked, true)
    assert.equal(bootDiskRes.code, 'PROTECTED_BOOT_DISK')

    const unauthProc = evaluateCommandSafety('pkill NetworkManager', { phase: 'armed', node: hostNode })
    assert.equal(unauthProc.blocked, true)
    assert.equal(unauthProc.code, 'PROCESS_NOT_WHITELISTED')

    const rebootRes = evaluateCommandSafety('sudo reboot', { phase: 'armed', node: hostNode })
    assert.equal(rebootRes.blocked, true)
    assert.equal(rebootRes.code, 'REBOOT_NOT_AUTHORIZED')
  } finally {
    await rm(tempDir, { recursive: true, force: true })
  }
})
