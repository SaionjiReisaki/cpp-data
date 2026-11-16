// Mirrors files/ and versions/ into the COS bucket behind cpp.xivcdn.com/data.
//
// Replaces TencentCloud/cos-action, which uploaded every file one at a time with no retry and took
// minutes for a few megabytes. No dependencies: the COS XML API needs only signed fetch() calls.
//
// Env: COS_SECRET_ID, COS_SECRET_KEY, COS_BUCKET (name-appid), COS_REGION.
// Optional: COS_CONCURRENCY (default 32), COS_MAX_ATTEMPTS (default 8).

import { createHash, createHmac } from 'node:crypto'
import { readdir, readFile } from 'node:fs/promises'
import { join, relative, sep } from 'node:path'
import { pathToFileURL } from 'node:url'

// The frontend fetches a version first and then the file it names, so a file must be live before
// the version pointing at it. Deletion runs in reverse for the same reason.
const DIRS = [
  { local: 'files', remote: 'data/files/' },
  { local: 'versions', remote: 'data/versions/' },
]

// The values mime-types gave cos-action, so objects skipped as unchanged and objects re-uploaded
// carry the same Content-Type.
const CONTENT_TYPES = {
  '.json': 'application/json',
  '.ts': 'video/mp2t',
}

class CosError extends Error {
  constructor(message, { status, retryable }) {
    super(message)
    this.status = status
    this.retryable = retryable
  }
}

function cosEncode(s) {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase())
}

function signPart(entries) {
  const pairs = Object.entries(entries)
    .map(([k, v]) => [cosEncode(k.toLowerCase()), cosEncode(String(v))])
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  return { list: pairs.map(([k]) => k).join(';'), str: pairs.map(([k, v]) => `${k}=${v}`).join('&') }
}

// https://cloud.tencent.com/document/product/436/7778
export function authorization({ secretId, secretKey, method, pathname, query, headers, now = Date.now() }) {
  const start = Math.floor(now / 1000) - 60
  const keyTime = `${start};${start + 900}`
  const signKey = createHmac('sha1', secretKey).update(keyTime).digest('hex')
  const q = signPart(query)
  const h = signPart(headers)
  const httpString = `${method.toLowerCase()}\n${pathname}\n${q.str}\n${h.str}\n`
  const stringToSign = `sha1\n${keyTime}\n${createHash('sha1').update(httpString).digest('hex')}\n`
  const signature = createHmac('sha1', signKey).update(stringToSign).digest('hex')
  return [
    'q-sign-algorithm=sha1',
    `q-ak=${secretId}`,
    `q-sign-time=${keyTime}`,
    `q-key-time=${keyTime}`,
    `q-header-list=${h.list}`,
    `q-url-param-list=${q.list}`,
    `q-signature=${signature}`,
  ].join('&')
}

function xmlText(s) {
  return s
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
}

function xmlField(xml, tag) {
  const m = xml.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`))
  return m ? xmlText(m[1]) : undefined
}

function stripQuotes(etag) {
  return etag?.replace(/^"|"$/g, '')
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function mapPool(items, concurrency, fn) {
  const queue = [...items]
  const errors = []
  const workers = Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
    while (queue.length > 0) {
      const item = queue.shift()
      try {
        await fn(item)
      } catch (e) {
        errors.push(e)
      }
    }
  })
  await Promise.all(workers)
  if (errors.length > 0) {
    throw new AggregateError(errors, `${errors.length} of ${items.length} operations failed`)
  }
}

function makeClient({ secretId, secretKey, origin, maxAttempts }) {
  const host = new URL(origin).host

  async function attempt({ method, key, query = {}, headers = {}, body }) {
    const pathname = '/' + key
    const label = `${method} ${pathname}${query.prefix ? `?prefix=${query.prefix}` : ''}`
    const signedHeaders = { ...headers, host }
    const url = new URL(pathname.split('/').map(cosEncode).join('/'), origin)
    for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v)

    let res
    try {
      res = await fetch(url, {
        method,
        headers: {
          ...headers,
          Authorization: authorization({ secretId, secretKey, method, pathname, query, headers: signedHeaders }),
        },
        body,
        signal: AbortSignal.timeout(60_000),
      })
    } catch (e) {
      throw new CosError(`${label}: ${e.cause?.code ?? e.name}: ${e.message}`, { retryable: true })
    }
    const text = await res.text()
    if (!res.ok) {
      const detail = [xmlField(text, 'Code'), xmlField(text, 'Message'), xmlField(text, 'RequestId')]
        .filter(Boolean)
        .join(' ')
      throw new CosError(`${label}: HTTP ${res.status} ${detail}`, {
        status: res.status,
        retryable: res.status === 408 || res.status === 429 || res.status >= 500,
      })
    }
    return { res, text }
  }

  return async function request(op) {
    for (let n = 1; ; n++) {
      try {
        return await attempt(op)
      } catch (e) {
        if (!(e instanceof CosError) || !e.retryable || n >= maxAttempts) throw e
        const delay = Math.min(30_000, 500 * 2 ** (n - 1) * (0.5 + Math.random()))
        console.warn(`retry ${n}/${maxAttempts - 1} in ${Math.round(delay)}ms: ${e.message}`)
        await sleep(delay)
      }
    }
  }
}

async function listRemote(request, prefix) {
  const objects = new Map()
  let marker = ''
  for (;;) {
    const { text } = await request({
      method: 'GET',
      key: '',
      query: { prefix, 'max-keys': '1000', ...(marker && { marker }) },
    })
    for (const [, entry] of text.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)) {
      const key = xmlField(entry, 'Key')
      // A console-created folder shows up as an empty object named after the prefix itself.
      if (key !== prefix) objects.set(key, stripQuotes(xmlField(entry, 'ETag')))
    }
    if (xmlField(text, 'IsTruncated') !== 'true') return objects
    marker = xmlField(text, 'NextMarker')
    if (!marker) throw new Error(`listing ${prefix}: truncated without NextMarker`)
  }
}

async function listLocal(root, dir) {
  const base = join(root, dir.local)
  const entries = await readdir(base, { recursive: true, withFileTypes: true })
  const files = new Map()
  for (const entry of entries) {
    if (!entry.isFile()) continue
    const path = join(entry.parentPath, entry.name)
    files.set(dir.remote + relative(base, path).split(sep).join('/'), path)
  }
  // An empty checkout would otherwise turn the clean-up pass into deleting the whole bucket prefix.
  if (files.size === 0) throw new Error(`${base} has no files; refusing to sync`)
  return files
}

function contentType(key) {
  const ext = key.slice(key.lastIndexOf('.'))
  return CONTENT_TYPES[ext] ?? 'application/octet-stream'
}

export async function sync({ root, secretId, secretKey, bucket, region, origin, concurrency = 32, maxAttempts = 8 }) {
  origin ??= `https://${bucket}.cos.${region}.myqcloud.com`
  const request = makeClient({ secretId, secretKey, origin, maxAttempts })

  const locals = await Promise.all(DIRS.map((dir) => listLocal(root, dir)))
  const remotes = await Promise.all(DIRS.map((dir) => listRemote(request, dir.remote)))
  const plans = DIRS.map((dir, i) => ({ dir, local: locals[i], remote: remotes[i] }))

  const stats = { uploaded: 0, unchanged: 0, deleted: 0, bytes: 0 }

  for (const { dir, local, remote } of plans) {
    const changed = []
    for (const [key, path] of local) {
      const body = await readFile(path)
      const md5 = createHash('md5').update(body)
      const hex = md5.copy().digest('hex')
      if (remote.get(key) === hex) {
        stats.unchanged++
      } else {
        changed.push({ key, body, hex, base64: md5.digest('base64') })
      }
    }
    console.log(`${dir.local}/: ${changed.length} to upload, ${local.size - changed.length} unchanged`)
    await mapPool(changed, concurrency, async ({ key, body, hex, base64 }) => {
      const { res } = await request({
        method: 'PUT',
        key,
        headers: { 'content-type': contentType(key), 'content-md5': base64 },
        body,
      })
      const etag = stripQuotes(res.headers.get('etag'))
      if (etag !== hex) throw new Error(`PUT /${key}: ETag ${etag} does not match MD5 ${hex}`)
      stats.uploaded++
      stats.bytes += body.length
      console.log(`uploaded /${key} (${body.length} bytes)`)
    })
  }

  for (const { dir, local, remote } of plans.toReversed()) {
    const stale = [...remote.keys()].filter((key) => !local.has(key))
    if (stale.length === 0) continue
    console.log(`${dir.local}/: ${stale.length} to delete`)
    await mapPool(stale, concurrency, async (key) => {
      try {
        await request({ method: 'DELETE', key })
      } catch (e) {
        if (e.status !== 404) throw e
      }
      stats.deleted++
      console.log(`deleted /${key}`)
    })
  }

  return stats
}

function env(name) {
  const value = process.env[name]
  if (!value) throw new Error(`${name} is not set`)
  return value
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const started = Date.now()
  try {
    const stats = await sync({
      root: process.cwd(),
      secretId: env('COS_SECRET_ID'),
      secretKey: env('COS_SECRET_KEY'),
      bucket: env('COS_BUCKET'),
      region: env('COS_REGION'),
      concurrency: Number(process.env.COS_CONCURRENCY || 32),
      maxAttempts: Number(process.env.COS_MAX_ATTEMPTS || 8),
    })
    console.log(
      `done in ${((Date.now() - started) / 1000).toFixed(1)}s: ${stats.uploaded} uploaded (${stats.bytes} bytes), ` +
        `${stats.unchanged} unchanged, ${stats.deleted} deleted`,
    )
  } catch (e) {
    for (const err of e instanceof AggregateError ? e.errors : [e]) console.error(err.message ?? err)
    if (e instanceof AggregateError) console.error(e.message)
    process.exit(1)
  }
}
