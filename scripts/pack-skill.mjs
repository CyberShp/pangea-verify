#!/usr/bin/env node
import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const OUT_DIR = path.join(ROOT, 'dist', 'live-test-expert')

async function main() {
  await rm(OUT_DIR, { recursive: true, force: true })
  await mkdir(OUT_DIR, { recursive: true })

  // 1. Copy Skill instructions & references to package root
  await cp(path.join(ROOT, 'skills', 'live-test-expert', 'SKILL.md'), path.join(OUT_DIR, 'SKILL.md'))
  await cp(path.join(ROOT, 'skills', 'live-test-expert', 'references'), path.join(OUT_DIR, 'references'), { recursive: true })

  // 2. Copy clean-room engine runtime (bin, src, tools)
  await cp(path.join(ROOT, 'bin'), path.join(OUT_DIR, 'bin'), { recursive: true })
  await cp(path.join(ROOT, 'src'), path.join(OUT_DIR, 'src'), { recursive: true })
  await cp(path.join(ROOT, 'tools'), path.join(OUT_DIR, 'tools'), { recursive: true })

  // 3. Emit self-contained package.json (ESM + ssh2 only)
  const rootPkg = JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf8'))
  const skillPkg = {
    name: 'live-test-expert',
    version: rootPkg.version,
    description: 'Self-contained dual-mode live verification and self-evolving test expert Skill (powered by pangea-verify)',
    type: 'module',
    main: './src/index.js',
    bin: { 'live-test-expert': './bin/cli.mjs' },
    engines: rootPkg.engines,
    license: rootPkg.license,
    dependencies: rootPkg.dependencies,
  }
  await writeFile(path.join(OUT_DIR, 'package.json'), `${JSON.stringify(skillPkg, null, 2)}\n`, 'utf8')

  // 4. Bundle installed runtime node_modules when present so the package is zero-install offline ready
  const nmSrc = path.join(ROOT, 'node_modules')
  try {
    await cp(nmSrc, path.join(OUT_DIR, 'node_modules'), { recursive: true })
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error
  }

  console.log(`Packed self-contained Skill bundle -> ${OUT_DIR}`)
}

main().catch(err => {
  console.error(err instanceof Error ? err.message : String(err))
  process.exit(1)
})
