import http from 'node:http'
import https from 'node:https'

const BODY_LIMIT = 2 * 1024 * 1024

function appendChunk(chunks, total, chunk) {
  const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
  const nextTotal = total + buf.length
  if (nextTotal <= BODY_LIMIT) {
    chunks.push(buf)
    return nextTotal
  }
  const allowed = BODY_LIMIT - total
  if (allowed > 0) chunks.push(buf.subarray(0, allowed))
  return BODY_LIMIT
}

export class HttpTransport {
  constructor(resolvedTopology) {
    this.topology = resolvedTopology
  }

  getNode(nodeId) {
    const node = this.topology?.nodes?.[nodeId]
    if (!node) throw new Error(`未知拓扑节点：${nodeId}`)
    if (!node.http) throw new Error(`节点「${nodeId}」未配置 HTTP/REST 通道`)
    return node
  }

  async request(nodeId, {
    method = 'GET',
    path: reqPath = '/',
    query = null,
    headers = {},
    json = undefined,
    body = undefined,
    expected_statuses: expectedStatuses = null,
    timeoutMs = 30_000,
    signal = null,
  } = {}) {
    if (signal?.aborted) {
      return { success: false, status_code: null, aborted: true, error: 'aborted', body: '', duration_ms: 0 }
    }
    const node = this.getNode(nodeId)
    const endpoint = node.http
    const verb = String(method || 'GET').trim().toUpperCase()
    const cleanRel = String(reqPath || '/').startsWith('/') ? String(reqPath || '/') : `/${reqPath}`
    const targetUrl = new URL(`${endpoint.base_url}${cleanRel}`)
    if (query && typeof query === 'object' && !Array.isArray(query)) {
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== null) targetUrl.searchParams.set(k, String(v))
      }
    }

    const reqHeaders = { Accept: 'application/json, text/plain, */*' }
    const protectedHeaderNames = new Set(['authorization'])
    if (endpoint.auth_kind === 'header') {
      protectedHeaderNames.add((endpoint.header_name || 'X-Auth-Token').toLowerCase())
    }
    if (headers && typeof headers === 'object') {
      for (const [k, v] of Object.entries(headers)) {
        if (!k || protectedHeaderNames.has(k.toLowerCase())) continue
        if (v !== undefined && v !== null) reqHeaders[k] = String(v)
      }
    }

    if (endpoint.auth_kind === 'bearer' && endpoint.secret) {
      reqHeaders.Authorization = `Bearer ${endpoint.secret}`
    } else if (endpoint.auth_kind === 'basic') {
      const encoded = Buffer.from(`${endpoint.username || ''}:${endpoint.secret || ''}`, 'utf8').toString('base64')
      reqHeaders.Authorization = `Basic ${encoded}`
    } else if (endpoint.auth_kind === 'header' && endpoint.secret) {
      reqHeaders[endpoint.header_name || 'X-Auth-Token'] = endpoint.secret
    }

    let payloadBuffer = null
    if (json !== undefined) {
      payloadBuffer = Buffer.from(JSON.stringify(json), 'utf8')
      if (!Object.keys(reqHeaders).some(k => k.toLowerCase() === 'content-type')) {
        reqHeaders['Content-Type'] = 'application/json; charset=utf-8'
      }
    } else if (body !== undefined && body !== null) {
      payloadBuffer = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8')
    }
    if (payloadBuffer) {
      reqHeaders['Content-Length'] = String(payloadBuffer.length)
    }

    const driver = targetUrl.protocol === 'https:' ? https : http
    const started = Date.now()

    return await new Promise(resolve => {
      let settled = false
      const finish = result => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        if (onAbort) signal?.removeEventListener('abort', onAbort)
        resolve({ ...result, duration_ms: Date.now() - started })
      }

      const req = driver.request(
        targetUrl,
        {
          method: verb,
          headers: reqHeaders,
          ...(targetUrl.protocol === 'https:' ? { rejectUnauthorized: Boolean(endpoint.verify_tls) } : {}),
        },
        res => {
          const chunks = []
          let total = 0
          res.on('data', chunk => { total = appendChunk(chunks, total, chunk) })
          res.once('end', () => {
            const rawBody = Buffer.concat(chunks).toString('utf8')
            const contentType = String(res.headers['content-type'] || '')
            let parsedJson
            if (contentType.includes('json') && rawBody.trim()) {
              try { parsedJson = JSON.parse(rawBody) } catch {}
            }
            const code = res.statusCode ?? 0
            const ok = Array.isArray(expectedStatuses) && expectedStatuses.length > 0
              ? expectedStatuses.includes(code)
              : (code >= 200 && code < 300)
            finish({
              success: ok,
              status_code: code,
              body: rawBody,
              ...(parsedJson !== undefined ? { json: parsedJson } : {}),
            })
          })
          res.once('error', err => finish({ success: false, status_code: res.statusCode ?? null, error: err.message, body: '' }))
        },
      )

      const onAbort = signal ? () => {
        req.destroy()
        finish({ success: false, status_code: null, aborted: true, error: 'aborted', body: '' })
      } : null
      if (onAbort) {
        if (signal.aborted) { onAbort(); return }
        signal.addEventListener('abort', onAbort, { once: true })
      }
      const timer = setTimeout(() => {
        req.destroy()
        finish({ success: false, status_code: null, timed_out: true, error: 'timeout', body: '' })
      }, timeoutMs)

      req.once('error', err => {
        if (settled) return
        finish({ success: false, status_code: null, error: err.message, body: '' })
      })

      if (payloadBuffer) req.write(payloadBuffer)
      req.end()
    })
  }
}
