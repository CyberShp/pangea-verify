const HARD_BLOCK_RULES = [
  {
    code: 'ROOT_FS_WIPE',
    pattern: /(?:^|[;&|(\n]\s*)(?:sudo\s+)?rm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|--recursive\s+--force|--force\s+--recursive)\s+(?:--no-preserve-root\s+)?(?:\/(?:\s|$|[;&|])|\/(?:bin|boot|etc|lib|lib64|proc|root|sbin|sys|usr|var)(?:\/?\s|$|[;&|]))/i,
    reason: '禁止递归强删根目录或核心系统目录',
  },
  {
    code: 'FIRMWARE_MUTATION',
    pattern: /(?:^|[;&|(\n]\s*)(?:sudo\s+)?(?:sysupgrade|flashcp|fw_setenv|uboot_upgrade)\b/i,
    reason: '禁止设备刷包或底层引导参数改写命令',
  },
  {
    code: 'SYSRQ_CRASH',
    pattern: /\/proc\/sysrq-trigger\b/i,
    reason: '禁止写入 /proc/sysrq-trigger 触发内核强制崩溃或重启',
  },
  {
    code: 'PARTITION_TABLE_EDIT',
    pattern: /(?:^|[;&|(\n]\s*)(?:sudo\s+)?(?:fdisk|parted|gdisk|sfdisk)\b/i,
    reason: '禁止使用分区表改写工具（fdisk/parted/gdisk/sfdisk）',
  },
  {
    code: 'SSHD_OR_PID1_KILL',
    pattern: /(?:^|[;&|(\n]\s*)(?:sudo\s+)?(?:(?:pkill|killall)\b[^\n;&|]*\bsshd\b|systemctl\s+(?:stop|disable|mask)\s+sshd?\b|init\s+[06]\b|kill\s+(?:-[A-Z0-9]+\s+)*1(?:\s|$|[;&|]))/i,
    reason: '禁止终止 sshd 服务、PID 1 进程或切换 init 0/6',
  },
]

const REBOOT_RE = /(?:^|[;&|(\n]\s*)(?:sudo\s+)?(?:reboot|poweroff|halt|shutdown|systemctl\s+(?:reboot|poweroff|halt|kexec))\b/i
const IP_LINK_MUTATE_RE = /(?:^|[;&|(\n]\s*)(?:sudo\s+)?ip\s+(?:link|l)\s+set\s+(?:dev\s+)?([A-Za-z0-9._:@-]+)\s+[^\n;&|]*\b(down|up)\b/gi
const IFCONFIG_MUTATE_RE = /(?:^|[;&|(\n]\s*)(?:sudo\s+)?ifconfig\s+([A-Za-z0-9._:@-]+)\s+[^\n;&|]*\b(down|up)\b/gi
const IFDOWN_UP_RE = /(?:^|[;&|(\n]\s*)(?:sudo\s+)?(ifdown|ifup)\s+([A-Za-z0-9._:@-]+)\b/gi
const IP_ADDR_MUTATE_RE = /(?:^|[;&|(\n]\s*)(?:sudo\s+)?ip\s+(?:addr|address|a)\s+(?:add|del|flush)\b[^\n;&|]*\bdev\s+([A-Za-z0-9._:@-]+)\b/gi

const DD_OF_RE = /(?:^|[;&|(\n]\s*)(?:sudo\s+)?dd\b[^\n;&|]*\bof=([^\s;&|)'"]+)/gi
const DISK_WIPE_RE = /(?:^|[;&|(\n]\s*)(?:sudo\s+)?(?:mkfs(?:\.[a-z0-9_]+)?|wipefs|blkdiscard)\b([^\n;&|]*)/gi

const EPHEMERAL_TEST_TOOLS = new Set(['fio', 'iperf', 'iperf3', 'dd', 'tcpdump', 'ping', 'tail'])

const READONLY_MUTATION_PATTERNS = [
  { pattern: REBOOT_RE, reason: '整机重启/关机属于变更操作' },
  { pattern: /(?:^|[;&|(\n]\s*)(?:sudo\s+)?(?:kill|pkill|killall)\b/i, reason: '进程信号/终止属于变更操作' },
  { pattern: /(?:^|[;&|(\n]\s*)(?:sudo\s+)?(?:systemctl|service)\s+(?:start|stop|restart|reload|kill)\b/i, reason: '服务启停属于变更操作' },
  { pattern: /(?:^|[;&|(\n]\s*)(?:sudo\s+)?(?:rm|mv|cp|chmod|chown|touch|mkdir|rmdir|truncate|dd|mkfs|wipefs|blkdiscard)\b/i, reason: '文件或块设备修改属于变更操作' },
  { pattern: /(?:^|[;&|(\n]\s*)(?:sudo\s+)?(?:nvme\s+(?:connect|disconnect|disconnect-all|format|sanitize|reset|subsystem-reset)|iscsiadm\b[^\n;&|]*(?:\s-[lu]\b|--login|--logout))/i, reason: '存储会话挂载/断开/格式化属于变更操作' },
  { pattern: /(?:^|[;&|(\n]\s*)(?:sudo\s+)?fio\b[^\n;&|]*--rw=(?:write|randwrite|rw|randrw|trim|trimwrite)\b/i, reason: '写模式 fio 打流属于变更操作' },
]

function stripSafeRedirects(command) {
  return command
    .replace(/\b\d*>&\d+\b/g, ' ')
    .replace(/(?:\d*|&)>+\s*\/dev\/null\b/g, ' ')
}

function hasFileWriteRedirection(command) {
  const cleaned = stripSafeRedirects(command)
  if (/(?:^|[^0-9<>])>>?\s*[^\s>&|;)]/.test(cleaned)) return true
  if (/\|\s*(?:sudo\s+)?tee\b(?!\s+(?:-a\s+)?\/dev\/null\b)/i.test(cleaned)) return true
  return false
}

function normalizeNicName(raw) {
  return String(raw || '').trim().replace(/@.*$/, '')
}

function isAllowedScratchPath(targetPath, node) {
  if (targetPath === '/dev/null' || targetPath === '/dev/zero') return true
  const allowedPaths = node?.test_resources?.paths || []
  return allowedPaths.some(prefix => targetPath === prefix || targetPath.startsWith(`${prefix.replace(/\/$/, '')}/`))
}

function checkTargetWhitelists(text, node) {
  const mgmtNics = new Set(node?.protected?.mgmt_nics || [])
  const dataNics = new Set(node?.test_resources?.data_nics || [])
  const bootDisks = new Set(node?.protected?.boot_disks || [])
  const allowedBlockDevs = new Set(node?.test_resources?.block_devices || [])
  const allowedProcs = new Set(node?.test_resources?.processes || [])

  if (REBOOT_RE.test(text)) {
    if (node?.role === 'jump' || node?.test_resources?.allow_reboot !== true) {
      return {
        blocked: true,
        code: 'REBOOT_NOT_AUTHORIZED',
        reason: `禁止整机重启/关机命令（节点「${node?.id || 'unknown'}」未在 Topo test_resources.allow_reboot 中授权）`,
      }
    }
  }

  const nicChecks = [
    ...text.matchAll(IP_LINK_MUTATE_RE),
    ...text.matchAll(IFCONFIG_MUTATE_RE),
    ...text.matchAll(IP_ADDR_MUTATE_RE),
  ].map(m => normalizeNicName(m[1]))
  for (const m of text.matchAll(IFDOWN_UP_RE)) {
    nicChecks.push(normalizeNicName(m[2]))
  }

  for (const nic of nicChecks) {
    if (mgmtNics.has(nic)) {
      return {
        blocked: true,
        code: 'PROTECTED_MGMT_NIC',
        reason: `禁止操作受保护的管理网口「${nic}」（位于 protected.mgmt_nics）`,
      }
    }
    if (!dataNics.has(nic)) {
      return {
        blocked: true,
        code: 'NIC_NOT_IN_TEST_RESOURCES',
        reason: `网口「${nic}」未在节点「${node?.id || 'unknown'}」的 test_resources.data_nics 白名单中授权，禁止启停或改 IP`,
      }
    }
  }

  for (const ip of node?.protected?.mgmt_ips || []) {
    if (ip && new RegExp(`\\bip\\s+(?:addr|address|a|route)\\s+(?:del|flush)\\b[^\\n;&|]*\\b${ip.replace(/\./g, '\\.')}\\b`, 'i').test(text)) {
      return {
        blocked: true,
        code: 'PROTECTED_MGMT_IP',
        reason: `禁止删除或清空受保护管理面 IP「${ip}」`,
      }
    }
  }

  for (const m of text.matchAll(DD_OF_RE)) {
    const target = m[1]
    if (bootDisks.has(target)) {
      return { blocked: true, code: 'PROTECTED_BOOT_DISK', reason: `禁止 dd 覆写受保护系统盘「${target}」` }
    }
    if (target.startsWith('/dev/')) {
      if (!isAllowedScratchPath(target, node) && !allowedBlockDevs.has(target)) {
        return {
          blocked: true,
          code: 'BLOCK_DEV_NOT_WHITELISTED',
          reason: `块设备「${target}」未在节点「${node?.id || 'unknown'}」的 test_resources.block_devices 白名单中授权`,
        }
      }
    }
  }

  for (const m of text.matchAll(DISK_WIPE_RE)) {
    const args = String(m[1] || '').trim().split(/\s+/).filter(tok => tok.startsWith('/'))
    if (args.length === 0) {
      return { blocked: true, code: 'BLOCK_DEV_MISSING', reason: '磁盘擦除/格式化命令缺少明确受控设备路径' }
    }
    for (const dev of args) {
      if (bootDisks.has(dev) || !allowedBlockDevs.has(dev)) {
        return {
          blocked: true,
          code: 'BLOCK_DEV_NOT_WHITELISTED',
          reason: `目标设备「${dev}」不在 test_resources.block_devices 白名单中，禁止执行 mkfs/wipefs/blkdiscard`,
        }
      }
    }
  }

  for (const m of text.matchAll(/(?:^|[;&|(\n]\s*)(?:sudo\s+)?(?:pkill|killall)\s+(?:-[A-Za-z0-9]+\s+)*([A-Za-z0-9._-]+)\b/gi)) {
    const procName = m[1]
    if (!allowedProcs.has(procName) && !EPHEMERAL_TEST_TOOLS.has(procName)) {
      return {
        blocked: true,
        code: 'PROCESS_NOT_WHITELISTED',
        reason: `进程「${procName}」未在节点「${node?.id || 'unknown'}」的 test_resources.processes 白名单中授权终止`,
      }
    }
  }

  for (const m of text.matchAll(/(?:^|[;&|(\n]\s*)(?:sudo\s+)?systemctl\s+(?:stop|restart|kill)\s+([A-Za-z0-9._@-]+)\b/gi)) {
    const unit = m[1].replace(/\.service$/i, '')
    if (!allowedProcs.has(unit) && !allowedProcs.has(m[1])) {
      return {
        blocked: true,
        code: 'SERVICE_NOT_WHITELISTED',
        reason: `系统服务「${m[1]}」未在节点「${node?.id || 'unknown'}」的 test_resources.processes 白名单中授权重启/停止`,
      }
    }
  }

  return { blocked: false, code: 'OK', reason: '' }
}

export function evaluateCommandSafety(command, { phase = 'armed', node = null } = {}) {
  const text = String(command ?? '')
  for (const rule of HARD_BLOCK_RULES) {
    if (rule.pattern.test(text)) {
      return { blocked: true, code: rule.code, reason: rule.reason }
    }
  }

  const whitelistCheck = checkTargetWhitelists(text, node)
  if (whitelistCheck.blocked && phase !== 'probe_readonly') {
    return whitelistCheck
  }

  if (phase === 'probe_readonly') {
    if (whitelistCheck.blocked && ['PROTECTED_MGMT_NIC', 'PROTECTED_MGMT_IP', 'PROTECTED_BOOT_DISK'].includes(whitelistCheck.code)) {
      return whitelistCheck
    }
    const hasNicMutate = /(?:^|[;&|(\n]\s*)(?:sudo\s+)?(?:ip\s+(?:link|l)\s+set\s+(?:dev\s+)?\S+\s+[^\n;&|]*\b(?:down|up)\b|ifconfig\s+\S+\s+[^\n;&|]*\b(?:down|up)\b|(?:ifdown|ifup)\s+\S+\b|ip\s+(?:addr|address|a)\s+(?:add|del|flush)\b)/i.test(text)
    if (hasNicMutate) {
      return {
        blocked: true,
        code: 'PHASE_READONLY_LOCKED',
        reason: '当前处于 PROBE_READONLY 物理只读阶段，禁止修改网卡状态；请先调用 register-cleanup 登记对偶恢复命令解锁 ARMED 阶段',
      }
    }
    for (const item of READONLY_MUTATION_PATTERNS) {
      if (item.pattern.test(text)) {
        return {
          blocked: true,
          code: 'PHASE_READONLY_LOCKED',
          reason: `当前处于 PROBE_READONLY 物理只读阶段（${item.reason}）；请先调用 register-cleanup 登记对偶恢复命令解锁 ARMED 阶段`,
        }
      }
    }
    if (hasFileWriteRedirection(text)) {
      return {
        blocked: true,
        code: 'PHASE_READONLY_LOCKED',
        reason: '当前处于 PROBE_READONLY 物理只读阶段，禁止重定向写入远端文件；请先调用 register-cleanup 登记清理恢复命令解锁 ARMED 阶段',
      }
    }
  }

  return whitelistCheck
}

export function evaluateHttpSafety({ method = 'GET', path: reqPath = '/' } = {}, { phase = 'armed', node = null } = {}) {
  const verb = String(method || 'GET').trim().toUpperCase()
  const cleanPath = String(reqPath || '/').trim()
  if (/\/(?:factory[-_]?reset|system\/(?:reboot|shutdown|poweroff)|firmware\/upgrade)\b/i.test(cleanPath)) {
    return {
      blocked: true,
      code: 'HTTP_DESTRUCTIVE_ENDPOINT',
      reason: `禁止调用整机恢复出厂、固件升级或关机类高危管理接口（${cleanPath}）`,
    }
  }
  if (phase === 'probe_readonly') {
    if (['GET', 'HEAD', 'OPTIONS'].includes(verb)) return { blocked: false, code: 'OK', reason: '' }
    const readonlyPosts = node?.http?.allow_readonly_post_paths || []
    if (verb === 'POST' && readonlyPosts.some(prefix => cleanPath === prefix || cleanPath.startsWith(prefix))) {
      return { blocked: false, code: 'OK', reason: '' }
    }
    return {
      blocked: true,
      code: 'PHASE_READONLY_LOCKED',
      reason: `当前处于 PROBE_READONLY 物理只读阶段，HTTP 通道仅放行只读查询（拒绝 ${verb} ${cleanPath}）；请先调用 register-cleanup 登记恢复动作解锁 ARMED 阶段`,
    }
  }
  return { blocked: false, code: 'OK', reason: '' }
}
