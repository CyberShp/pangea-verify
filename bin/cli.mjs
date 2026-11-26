#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import { KnowledgePack } from '../src/knowledge.js'

function parseArgs(argv) {
  const [command, ...rest] = argv
  const flags = {}
  for (let i = 0; i < rest.length; i += 1) {
    const token = rest[i]
    if (!token.startsWith('--')) throw new Error(`unexpected argument: ${token}`)
    const key = token.slice(2)
    const next = rest[i + 1]
    if (next === undefined || next.startsWith('--')) {
      flags[key] = 'true'
    } else {
      flags[key] = next
      i += 1
    }
  }
  return { command, flags }
}

async function callGateway(endpoint, body, configPath) {
  let baseUrl = process.env.PANGEA_VERIFY_GATEWAY_URL
  let token = process.env.PANGEA_VERIFY_GATEWAY_TOKEN
  if (configPath) {
    const cfg = JSON.parse(await readFile(configPath, 'utf8'))
    baseUrl = cfg.url || baseUrl
    token = cfg.token || token
  }
  if (!baseUrl || !token) {
    throw new Error('missing gateway url or token (pass --config or set PANGEA_VERIFY_GATEWAY_URL/PANGEA_VERIFY_GATEWAY_TOKEN)')
  }
  const response = await fetch(`${baseUrl.replace(/\/$/, '')}${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  })
  const text = await response.text()
  let data
  try { data = JSON.parse(text) } catch { data = { error: text } }
  if (!response.ok) {
    const err = new Error(data?.error || `gateway HTTP ${response.status}`)
    err.payload = data
    throw err
  }
  return data
}

async function readCmdFlag(flags) {
  if (flags['cmd-file']) return (await readFile(flags['cmd-file'], 'utf8')).replace(/\r?\n$/, '')
  return flags.cmd
}

async function readJsonFlag(flags, fileKey, inlineKey) {
  if (flags[fileKey]) return JSON.parse(await readFile(flags[fileKey], 'utf8'))
  if (flags[inlineKey]) return JSON.parse(flags[inlineKey])
  return undefined
}

async function main() {
  const { command, flags } = parseArgs(process.argv.slice(2))
  if (!command) {
    throw new Error('usage: pangea-verify <status|exec|bg-start|bg-read|bg-stop|interactive|http|register-cleanup|run-cleanups|kp-catalog|kp-card|kp-draft|kp-promote|kp-attest|kp-feedback> ...')
  }

  const cfg = flags.config
  let result

  if (command === 'status') {
    result = await callGateway('/status', {}, cfg)
  } else if (command === 'exec') {
    result = await callGateway('/exec', {
      target: flags.target,
      command: await readCmdFlag(flags),
      ...(flags['timeout-ms'] ? { timeout_ms: Number(flags['timeout-ms']) } : {}),
    }, cfg)
  } else if (command === 'bg-start') {
    result = await callGateway('/bg-start', {
      target: flags.target,
      command: await readCmdFlag(flags),
    }, cfg)
  } else if (command === 'bg-read') {
    result = await callGateway('/bg-read', {
      job_id: flags['job-id'],
      ...(flags['wait-ms'] ? { wait_ms: Number(flags['wait-ms']) } : {}),
    }, cfg)
  } else if (command === 'bg-stop') {
    result = await callGateway('/bg-stop', { job_id: flags['job-id'] }, cfg)
  } else if (command === 'interactive') {
    const exchanges = await readJsonFlag(flags, 'exchanges-file', 'exchanges')
    result = await callGateway('/interactive', { target: flags.target, exchanges }, cfg)
  } else if (command === 'http') {
    const jsonPayload = await readJsonFlag(flags, 'json-file', 'json')
    const queryPayload = await readJsonFlag(flags, 'query-file', 'query')
    result = await callGateway('/http', {
      target: flags.target,
      method: flags.method || 'GET',
      path: flags.path || '/',
      ...(queryPayload !== undefined ? { query: queryPayload } : {}),
      ...(jsonPayload !== undefined ? { json: jsonPayload } : {}),
      ...(flags.body !== undefined ? { body: flags.body } : {}),
      ...(flags['timeout-ms'] ? { timeout_ms: Number(flags['timeout-ms']) } : {}),
    }, cfg)
  } else if (command === 'register-cleanup') {
    if (flags.kind === 'http') {
      const jsonPayload = await readJsonFlag(flags, 'json-file', 'json')
      result = await callGateway('/register-cleanup', {
        kind: 'http',
        target: flags.target,
        method: flags.method || 'DELETE',
        path: flags.path,
        ...(jsonPayload !== undefined ? { json: jsonPayload } : {}),
        description: flags.desc || '',
      }, cfg)
    } else {
      result = await callGateway('/register-cleanup', {
        kind: 'ssh',
        target: flags.target,
        command: await readCmdFlag(flags),
        description: flags.desc || '',
      }, cfg)
    }
  } else if (command === 'run-cleanups') {
    result = await callGateway('/run-cleanups', {}, cfg)
  } else if (command.startsWith('kp-')) {
    const pack = new KnowledgePack(flags.pack)
    if (command === 'kp-catalog') {
      result = await pack.queryCatalog({
        domain: flags.domain || '',
        sourceModule: flags.module || '',
        role: flags.role || '',
        keyword: flags.q || '',
        includeDrafts: flags['include-drafts'] === 'true',
      })
    } else if (command === 'kp-card') {
      result = await pack.getCard(flags.id, { allowDraft: flags['allow-draft'] === 'true' })
      if (!result) throw new Error(`未找到能力卡：${flags.id}`)
    } else if (command === 'kp-draft') {
      const card = await readJsonFlag(flags, 'card-file', 'card')
      const topology = await readJsonFlag(flags, 'topo-file', 'topo')
      result = await pack.saveDraft(card, { topology })
    } else if (command === 'kp-promote') {
      const topology = await readJsonFlag(flags, 'topo-file', 'topo')
      const commandIds = String(flags['command-ids'] || '').split(',').map(s => s.trim()).filter(Boolean)
      result = await pack.promoteCard({
        cardId: flags.id,
        transcriptPath: flags.transcript,
        commandIds,
        firmwareHint: flags.firmware || '',
        topology,
      })
    } else if (command === 'kp-attest') {
      const topology = await readJsonFlag(flags, 'topo-file', 'topo')
      result = await pack.attestCard({
        cardId: flags.id,
        attestedBy: flags.by,
        reason: flags.reason,
        firmwareHint: flags.firmware || '',
        topology,
      })
    } else if (command === 'kp-feedback') {
      result = await pack.recordFeedback({
        cardId: flags.id,
        sessionId: flags.session || '',
        commandId: flags['command-id'] || '',
        errorSummary: flags.summary,
        firmwareHint: flags.firmware || '',
      })
    } else {
      throw new Error(`unknown knowledge command: ${command}`)
    }
  } else {
    throw new Error(`unknown command: ${command}`)
  }

  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
}

main().catch(error => {
  process.stderr.write(`${JSON.stringify({
    ok: false,
    error: error instanceof Error ? error.message : String(error),
    ...(error?.payload ? { details: error.payload } : {}),
  })}\n`)
  process.exit(1)
})
