import { execFile } from 'node:child_process'
import { mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const PY_AST_SCRIPT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'tools', 'py_ast_index.py')

const SKIP_DIRS = new Set([
  '.git', '.hg', '.svn', 'node_modules', '__pycache__', '.venv', 'venv', 'build', 'dist', 'out', 'target',
])

const SOURCE_EXTS = new Set(['.c', '.cc', '.cpp', '.cxx', '.h', '.hpp', '.go', '.py', '.sh', '.bash'])

const DEFAULT_CLI_PATTERNS = [
  {
    kind: 'c_cli_macro',
    regex: /\b(?:REGISTER_CLI|REGISTER_CMD|CLI_CMD|DIAG_CMD|CMD_ENTRY|SHELL_CMD|DEFINE_CMD|ADD_CMD)\s*\(\s*"([^"]+)"/g,
  },
  {
    kind: 'c_inject_point',
    regex: /\b(?:INJECT_POINT|FAULT_INJECT|FI_POINT|PANGEA_INJECT)\s*\(\s*"([^"]+)"/g,
  },
  {
    kind: 'py_subparser',
    regex: /\.add_parser\(\s*['"]([^'"]+)['"]/g,
  },
  {
    kind: 'go_cobra_cmd',
    regex: /\bUse:\s*"([a-zA-Z0-9._-]+(?:\s+[^"]*)?)"/g,
  },
]

function runPythonScript(pythonBin, args, { timeoutMs = 30_000 } = {}) {
  return new Promise((resolve, reject) => {
    execFile(
      pythonBin,
      args,
      { timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024, windowsHide: true },
      (error, stdout, stderr) => {
        if (error) {
          const err = new Error((stderr || error.message || '').trim())
          err.code = error.code
          reject(err)
        } else {
          resolve(String(stdout || ''))
        }
      },
    )
  })
}

export async function indexPythonAutomation(rootDir, {
  query = '',
  maxFiles = 200,
  topoOnly = false,
  pythonBin = '',
} = {}) {
  if (!rootDir) throw new Error('rootDir 不能为空')
  const absRoot = path.resolve(rootDir)
  const scriptArgs = [PY_AST_SCRIPT, absRoot, '--max-files', String(maxFiles)]
  if (query) scriptArgs.push('--query', String(query))
  if (topoOnly) scriptArgs.push('--topo-only')

  const candidates = pythonBin ? [pythonBin] : ['python3', 'python']
  let lastError = null
  for (const bin of candidates) {
    try {
      const stdout = await runPythonScript(bin, scriptArgs)
      return JSON.parse(stdout)
    } catch (error) {
      lastError = error
      if (error?.code === 'ENOENT') continue
      throw error
    }
  }
  throw new Error(`无法启动 Python AST 探针（已尝试 ${candidates.join(', ')}）：${lastError?.message || 'not found'}`)
}

async function walkSourceFiles(rootDir, maxFiles) {
  const results = []
  let truncated = false
  async function visit(dir) {
    if (results.length >= maxFiles) {
      truncated = true
      return
    }
    const entries = await readdir(dir, { withFileTypes: true })
    entries.sort((a, b) => a.name.localeCompare(b.name))
    for (const entry of entries) {
      if (results.length >= maxFiles) {
        truncated = true
        return
      }
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue
        await visit(path.join(dir, entry.name))
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase()
        if (SOURCE_EXTS.has(ext)) {
          results.push(path.join(dir, entry.name))
        }
      }
    }
  }
  await visit(rootDir)
  return { files: results, truncated }
}

export async function scanSourceCli(rootDir, {
  maxFiles = 500,
  customPatterns = [],
} = {}) {
  if (!rootDir) throw new Error('rootDir 不能为空')
  const absRoot = path.resolve(rootDir)
  const patterns = [
    ...DEFAULT_CLI_PATTERNS,
    ...customPatterns.map((item, idx) => ({
      kind: item.kind || `custom_${idx}`,
      regex: item.regex instanceof RegExp ? new RegExp(item.regex.source, item.regex.flags.includes('g') ? item.regex.flags : `${item.regex.flags}g`) : new RegExp(String(item.pattern), 'g'),
    })),
  ]

  const { files, truncated } = await walkSourceFiles(absRoot, maxFiles)
  const modules = {}
  let totalEntries = 0

  for (const filePath of files) {
    const rel = path.relative(absRoot, filePath).replaceAll('\\', '/')
    const moduleDir = path.posix.dirname(rel)
    let text
    try {
      text = await readFile(filePath, 'utf8')
    } catch {
      continue
    }
    const lines = text.split(/\r?\n/)
    for (let i = 0; i < lines.length; i += 1) {
      const lineText = lines[i]
      for (const pat of patterns) {
        pat.regex.lastIndex = 0
        let match
        while ((match = pat.regex.exec(lineText)) !== null) {
          const symbol = (match[1] || '').trim()
          if (!symbol) continue
          if (!modules[moduleDir]) modules[moduleDir] = []
          modules[moduleDir].push({
            kind: pat.kind,
            command: symbol,
            file: rel,
            line: i + 1,
            snippet: lineText.trim().slice(0, 160),
          })
          totalEntries += 1
        }
      }
    }
  }

  return {
    schema_version: 1,
    root: absRoot,
    scanned_files: files.length,
    truncated,
    total_entries: totalEntries,
    modules,
  }
}

export async function saveCodeMap(packDir, mapName, data) {
  const safeName = String(mapName || '').trim().replace(/[^A-Za-z0-9._-]/g, '_')
  if (!safeName) throw new Error('mapName 不能为空')
  const target = path.join(path.resolve(packDir), 'code-maps', `${safeName}.json`)
  await mkdir(path.dirname(target), { recursive: true })
  const tmp = `${target}.${process.pid}.${randomUUID().slice(0, 8)}.tmp`
  await writeFile(tmp, `${JSON.stringify(data, null, 2)}\n`, 'utf8')
  await rename(tmp, target)
  return target
}

export async function lookupCodeCliHints(packDir, sourcePaths = []) {
  if (!packDir) return []
  const mapsDir = path.join(path.resolve(packDir), 'code-maps')
  let entries
  try {
    entries = await readdir(mapsDir, { withFileTypes: true })
  } catch (error) {
    if (error?.code === 'ENOENT') return []
    throw error
  }

  const normalizedTargets = (Array.isArray(sourcePaths) ? sourcePaths : [])
    .map(p => String(p || '').replaceAll('\\', '/').replace(/^[^:]+:/, '').replace(/:\d+$/, '').trim())
    .filter(Boolean)

  const hits = []
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith('.json')) continue
    let parsed
    try {
      parsed = JSON.parse(await readFile(path.join(mapsDir, entry.name), 'utf8'))
    } catch {
      continue
    }
    if (!parsed?.modules || typeof parsed.modules !== 'object') continue
    for (const [modDir, items] of Object.entries(parsed.modules)) {
      if (!Array.isArray(items)) continue
      const matched = normalizedTargets.length === 0 || normalizedTargets.some(target =>
        target.startsWith(`${modDir}/`) || target === modDir || modDir.startsWith(`${path.posix.dirname(target)}`),
      )
      if (matched) {
        for (const item of items) {
          hits.push({ map: entry.name.replace(/\.json$/, ''), module: modDir, ...item })
        }
      }
    }
  }
  return hits.slice(0, 60)
}
