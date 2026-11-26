import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import {
  indexPythonAutomation,
  lookupCodeCliHints,
  saveCodeMap,
  scanSourceCli,
} from '../src/index.js'

test('indexPythonAutomation extracts inheritance chains, command hints, and topo parsers without ever importing target code', async () => {
  const tempDir = await mkdtemp(path.join(tmpdir(), 'pv-py-ast-'))
  try {
    const legacyDir = path.join(tempDir, 'legacy_auto')
    await mkdir(path.join(legacyDir, 'core'), { recursive: true })
    await mkdir(path.join(legacyDir, 'suites'), { recursive: true })

    // Deliberately include top-level side effects that would explode if ever imported
    await writeFile(path.join(legacyDir, 'core', 'base_lab.py'), [
      'import nonexistent_internal_sdk_xyz',
      'raise RuntimeError("MUST NEVER BE IMPORTED OR EXECUTED")',
      '',
      'class BaseLab:',
      '    def run_cmd(self, cmd):',
      '        return self.ssh.exec_command(cmd)',
      '',
      'class SshLab(BaseLab):',
      '    DEFAULT_API = "/api/v1/storage/luns"',
      '    def flap_port(self, nic):',
      '        """Trigger NIC link down on host data port."""',
      '        return self.run_cmd(f"ip link set {nic} down")',
    ].join('\n'), 'utf8')

    await writeFile(path.join(legacyDir, 'core', 'topo_loader.py'), [
      'import xml.etree.ElementTree as ET',
      '',
      'def load_lab_xml(xml_path):',
      '    tree = ET.parse(xml_path)',
      '    return tree.getroot()',
    ].join('\n'), 'utf8')

    await writeFile(path.join(legacyDir, 'suites', 'san_suite.py'), [
      'class SanSuite(SshLab):',
      '    def login_iscsi(self, portal_ip):',
      '        cmd = f"iscsiadm -m discovery -t st -p {portal_ip}:3260 --login"',
      '        return self.run_cmd(cmd)',
    ].join('\n'), 'utf8')

    // Full index
    const full = await indexPythonAutomation(legacyDir)
    assert.equal(full.scanned_files, 3)
    assert.deepEqual(full.class_hierarchy.SanSuite.bases, ['SshLab'])
    assert.deepEqual(full.class_hierarchy.SshLab.bases, ['BaseLab'])

    const baseFile = full.files.find(f => f.file === 'core/base_lab.py')
    const sshLab = baseFile.classes.find(c => c.name === 'SshLab')
    assert.equal(sshLab.constants.DEFAULT_API, '/api/v1/storage/luns')
    assert.ok(sshLab.methods[0].command_hints.some(h => h.includes('ip link set {nic} down')))

    // Query filter for iscsiadm
    const filtered = await indexPythonAutomation(legacyDir, { query: 'iscsiadm' })
    assert.equal(filtered.matched_files, 1)
    assert.equal(filtered.files[0].file, 'suites/san_suite.py')

    // Topo-only filter locates XML parser immediately
    const topoFiles = await indexPythonAutomation(legacyDir, { topoOnly: true })
    assert.equal(topoFiles.matched_files, 1)
    assert.equal(topoFiles.files[0].file, 'core/topo_loader.py')
    assert.ok(topoFiles.files[0].parser_signals.includes('xml.etree.ElementTree'))
  } finally {
    await rm(tempDir, { recursive: true, force: true })
  }
})

test('scanSourceCli extracts CLI macros and inject points and maps them by source path', async () => {
  const tempDir = await mkdtemp(path.join(tmpdir(), 'pv-cli-scan-'))
  try {
    const srcRoot = path.join(tempDir, 'target_repo')
    const packDir = path.join(tempDir, 'knowledge-pack')
    await mkdir(path.join(srcRoot, 'src', 'raid'), { recursive: true })
    await mkdir(path.join(srcRoot, 'src', 'iscsi'), { recursive: true })

    await writeFile(path.join(srcRoot, 'src', 'raid', 'raid_cli.c'), [
      'REGISTER_CLI("raid show rebuild");',
      'INJECT_POINT("INJ_RAID_META_IO_ERR");',
    ].join('\n'), 'utf8')

    await writeFile(path.join(srcRoot, 'src', 'iscsi', 'session_cli.c'), [
      'DIAG_CMD("iscsi session list");',
    ].join('\n'), 'utf8')

    const scanned = await scanSourceCli(srcRoot)
    assert.equal(scanned.total_entries, 3)
    await saveCodeMap(packDir, 'target-storage', scanned)

    const raidHints = await lookupCodeCliHints(packDir, ['repoA:src/raid/rebuild.c:142'])
    assert.equal(raidHints.length, 2)
    assert.ok(raidHints.some(h => h.command === 'raid show rebuild' && h.kind === 'c_cli_macro'))
    assert.ok(raidHints.some(h => h.command === 'INJ_RAID_META_IO_ERR' && h.kind === 'c_inject_point'))

    const iscsiHints = await lookupCodeCliHints(packDir, ['src/iscsi/conn.c'])
    assert.equal(iscsiHints.length, 1)
    assert.equal(iscsiHints[0].command, 'iscsi session list')
  } finally {
    await rm(tempDir, { recursive: true, force: true })
  }
})
