// Mirrors files/ and versions/ into the COS bucket behind cpp.xivcdn.com/data.
//
// Replaces TencentCloud/cos-action, which uploaded every file one at a time with no retry and took
// minutes for a few megabytes. No dependencies: the COS XML API needs only signed fetch() calls.
//
// Env: COS_SECRET_ID, COS_SECRET_KEY, COS_BUCKET (name-appid), COS_REGION.
// Optional: COS_CONCURRENCY (default 32), COS_PART_CONCURRENCY (default 4), COS_MAX_ATTEMPTS
// (default 15).

import { createHash, createHmac } from 'node:crypto'
import { readdir, readFile } from 'node:fs/promises'
import { join, relative, sep } from 'node:path'
import { pathToFileURL } from 'node:url'

// The frontend fetches a version first and then the file it names, so a container's files must be
// live before its version. Deletion runs in reverse for the same reason. `suffix` is what a key adds
// to its container's name: files/<name>.json and files/<name>.ts go with versions/<name>.version.json.
const DIRS = [
  { local: 'files', remote: 'data/files/', suffix: /\.[^./]+$/ },
  { local: 'versions', remote: 'data/versions/', suffix: /\.version\.json$/ },
]

// A request is given up only after this long without progress: no body chunk taken by the socket
// and no response yet. A 60 s limit on the whole request failed all eight attempts at three 4 MB
// files on the runner's cross-border link to COS. After the last chunk the kernel still holds what
// it buffered, and the window also has to cover sending that: up to half a minute over an emulated
// 50 KB/s link.
const IDLE_TIMEOUT = 120_000
// authorization() signs for 14 minutes from the attempt's start. Stopping a slow attempt short of
// that retries it with a fresh signature instead of having COS reject it after the last byte.
const ATTEMPT_TIMEOUT = 600_000
const CHUNK = 64 * 1024

// COS refuses a request it finds too slow. On 2026-11-17 it refused 22 PUTs of 4 MB files, each
// between 205 and 318 seconds in, while no request that finished within 184 seconds was refused; the
// runner's link gave each upload 20-32 KiB/s. A file larger than this goes up in parts this big: a
// request a slow link finishes in under a minute, retried alone when it fails. COS takes no smaller
// part except the last.
const PART_SIZE = 1 << 20

// COS answers a client it finds too slow with 400 and one of these codes rather than with 408.
const SLOW_CLIENT_CODES = new Set(['RequestTimeout', 'UserNetworkTooSlow'])

// A file uploaded in parts gets an ETag that is not its MD5, so its MD5 also goes into this metadata.
const MD5_META = 'x-cos-meta-md5'
const PLAIN_MD5 = /^[0-9a-f]{32}$/

// Longer than the workflow's timeout-minutes, so an upload in parts open this long has no run left.
const ORPHAN_AGE = 2 * 3600_000

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

function md5(body) {
  const hash = createHash('md5').update(body)
  return { hex: hash.copy().digest('hex'), base64: hash.digest('base64') }
}

// cos-action only ever sent whole PUTs, so the workflow's key may lack what uploading in parts needs.
function needs(e) {
  return e.status === 403
    ? ' (the key needs cos:InitiateMultipartUpload, cos:UploadPart, cos:CompleteMultipartUpload, ' +
        'cos:AbortMultipartUpload, cos:ListMultipartUploads and cos:HeadObject)'
    : ''
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

// Runs at most `concurrency` of the functions handed to it at once, the rest in arrival order.
function limiter(concurrency) {
  let active = 0
  const waiting = []
  return async (fn) => {
    if (active < concurrency) active++
    else await new Promise((resolve) => waiting.push(resolve))
    try {
      return await fn()
    } finally {
      const next = waiting.shift()
      if (next) next()
      else active--
    }
  }
}

// Hands the body over a chunk at a time, so each chunk the socket takes counts as progress.
function bodyStream(body, onProgress) {
  let offset = 0
  return new ReadableStream({
    pull(controller) {
      onProgress()
      if (offset >= body.length) controller.close()
      else controller.enqueue(body.subarray(offset, (offset += CHUNK)))
    },
  })
}

function makeClient({ secretId, secretKey, origin, maxAttempts, idleTimeout, attemptTimeout }) {
  const host = new URL(origin).host

  async function attempt({ method, key, query = {}, headers = {}, body }) {
    const pathname = '/' + key
    const shown = Object.entries(query)
      .filter(([k]) => k !== 'max-keys' && k !== 'marker')
      .map(([k, v]) => (v && k !== 'uploadId' ? `${k}=${v}` : k))
    const label = `${method} ${pathname}${shown.length ? '?' + shown.join('&') : ''}`
    const signedHeaders = { ...headers, host }
    const url = new URL(pathname.split('/').map(cosEncode).join('/'), origin)
    // A flag such as ?uploads goes out bare, as the COS SDKs send it; the signature reads it as empty.
    url.search = Object.entries(query)
      .map(([k, v]) => cosEncode(k) + (v === '' ? '' : '=' + cosEncode(v)))
      .join('&')

    const controller = new AbortController()
    const abort = (reason) => controller.abort(new DOMException(reason, 'TimeoutError'))
    const deadline = setTimeout(abort, attemptTimeout, `still running after ${attemptTimeout / 1000}s`)
    let idle
    const progress = () => {
      clearTimeout(idle)
      idle = setTimeout(abort, idleTimeout, `no progress for ${idleTimeout / 1000}s`)
    }

    let res, text
    try {
      progress()
      res = await fetch(url, {
        method,
        headers: {
          ...headers,
          // A stream body would otherwise go out chunked.
          ...(body && { 'content-length': String(body.length) }),
          Authorization: authorization({ secretId, secretKey, method, pathname, query, headers: signedHeaders }),
        },
        ...(body && { body: bodyStream(body, progress), duplex: 'half' }),
        signal: controller.signal,
      })
      progress()
      text = await res.text()
    } catch (e) {
      throw new CosError(`${label}: ${e.cause?.code ?? e.name}: ${e.message}`, { retryable: true })
    } finally {
      clearTimeout(idle)
      clearTimeout(deadline)
    }
    // Completing an upload in parts answers 200 before the parts are merged, so a failed merge comes
    // back as an error document in that 200.
    if (!res.ok || /^\s*(<\?xml[^>]*>\s*)?<Error>/.test(text)) {
      const code = xmlField(text, 'Code')
      const detail = [code, xmlField(text, 'Message'), xmlField(text, 'RequestId')].filter(Boolean).join(' ')
      throw new CosError(`${label}: ${[`HTTP ${res.status}`, detail].filter(Boolean).join(' ')}`, {
        status: res.status,
        retryable:
          res.ok || res.status === 408 || res.status === 429 || res.status >= 500 || SLOW_CLIENT_CODES.has(code),
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

// The MD5 an object uploaded in parts was given in its metadata, or undefined to upload it again.
async function storedMd5(request, key) {
  try {
    const { res } = await request({ method: 'HEAD', key })
    return res.headers.get(MD5_META) ?? undefined
  } catch (e) {
    console.log(`::warning::uploading /${key} again, as its MD5 could not be read${needs(e)}: ${e.message}`)
    return undefined
  }
}

// A run killed halfway through an upload in parts leaves the parts behind, billed as storage until the
// upload is aborted. More than one listing's worth waits for the next run.
async function abortOrphans(request, prefix) {
  const cutoff = Date.now() - ORPHAN_AGE
  const { text } = await request({ method: 'GET', key: '', query: { uploads: '', prefix } })
  for (const [, entry] of text.matchAll(/<Upload>([\s\S]*?)<\/Upload>/g)) {
    const key = xmlField(entry, 'Key')
    const initiated = xmlField(entry, 'Initiated')
    // Written so that a time that does not parse keeps the upload.
    if (!(Date.parse(initiated) < cutoff)) continue
    await request({ method: 'DELETE', key, query: { uploadId: xmlField(entry, 'UploadId') } })
    console.log(`aborted an upload of /${key} left open since ${initiated}`)
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

function containerOf(dir, key) {
  return key.slice(dir.remote.length).replace(dir.suffix, '')
}

export async function sync({
  root,
  secretId,
  secretKey,
  bucket,
  region,
  origin,
  concurrency = 32,
  partConcurrency = 4,
  maxAttempts = 15,
  idleTimeout = IDLE_TIMEOUT,
  attemptTimeout = ATTEMPT_TIMEOUT,
}) {
  origin ??= `https://${bucket}.cos.${region}.myqcloud.com`
  const request = makeClient({ secretId, secretKey, origin, maxAttempts, idleTimeout, attemptTimeout })

  const locals = await Promise.all(DIRS.map((dir) => listLocal(root, dir)))
  const remotes = await Promise.all(DIRS.map((dir) => listRemote(request, dir.remote)))
  await Promise.all(
    DIRS.map((dir) =>
      abortOrphans(request, dir.remote).catch((e) =>
        console.log(`::warning::unfinished uploads in parts were left alone${needs(e)}: ${e.message}`),
      ),
    ),
  )
  const plans = DIRS.map((dir, i) => ({ dir, local: locals[i], remote: remotes[i] }))
  await Promise.all(
    plans.flatMap(({ local, remote }) =>
      [...remote]
        .filter(([key, etag]) => local.has(key) && !PLAIN_MD5.test(etag))
        .map(async ([key]) => remote.set(key, await storedMd5(request, key))),
    ),
  )

  const stats = { uploaded: 0, unchanged: 0, deleted: 0, held: 0, bytes: 0 }
  const errors = []
  // A container with a failed operation keeps the rest of its changes for the next run, so its
  // version never gets ahead of its files, while every other container still goes out.
  const failed = new Set()
  const small = limiter(concurrency)
  // Parts, and large files when they go up whole. On the runner's slow link to COS each of three
  // uploads running side by side still got 20-27 KiB/s, so parts sent together add up.
  const parts = limiter(partConcurrency)
  // Cleared once COS refuses to start an upload in parts, so the rest of the large files go up whole.
  let inParts = true

  // For each container, its changed objects in each of DIRS.
  const containers = new Map()
  for (const [i, { dir, local, remote }] of plans.entries()) {
    let changed = 0
    for (const [key, path] of local) {
      const body = await readFile(path)
      const { hex, base64 } = md5(body)
      if (remote.get(key) === hex) {
        stats.unchanged++
        continue
      }
      const name = containerOf(dir, key)
      let steps = containers.get(name)
      if (!steps) {
        steps = DIRS.map(() => [])
        containers.set(name, steps)
      }
      steps[i].push({ key, body, hex, base64 })
      changed++
    }
    console.log(`${dir.local}/: ${changed} to upload, ${local.size - changed} unchanged`)
  }

  async function put(object) {
    const { key, body } = object
    const uploadId = body.length > PART_SIZE && inParts && (await initiate(object))
    if (uploadId) await putParts(object, uploadId)
    else await putWhole(object)
    stats.uploaded++
    stats.bytes += body.length
    const count = Math.ceil(body.length / PART_SIZE)
    console.log(`uploaded /${key} (${body.length} bytes${uploadId ? ` in ${count} parts` : ''})`)
  }

  async function putWhole({ key, body, hex, base64 }) {
    const { res } = await (body.length > PART_SIZE ? parts : small)(() =>
      request({
        method: 'PUT',
        key,
        headers: { 'content-type': contentType(key), 'content-md5': base64 },
        body,
      }),
    )
    const etag = stripQuotes(res.headers.get('etag'))
    if (etag !== hex) throw new Error(`PUT /${key}: ETag ${etag} does not match MD5 ${hex}`)
  }

  async function initiate({ key, hex }) {
    try {
      const { text } = await request({
        method: 'POST',
        key,
        query: { uploads: '' },
        headers: { 'content-type': contentType(key), [MD5_META]: hex },
      })
      const uploadId = xmlField(text, 'UploadId')
      if (!uploadId) throw new Error(`POST /${key}?uploads: no UploadId in the response`)
      return uploadId
    } catch (e) {
      if (e.status !== 403) throw e
      if (inParts)
        console.log(`::warning::uploading large files whole, as COS refused one in parts${needs(e)}: ${e.message}`)
      inParts = false
    }
  }

  async function putPart(key, uploadId, partNumber, body) {
    const { hex, base64 } = md5(body)
    const { res } = await parts(() =>
      request({
        method: 'PUT',
        key,
        query: { partNumber: String(partNumber), uploadId },
        headers: { 'content-md5': base64 },
        body,
      }),
    )
    const etag = stripQuotes(res.headers.get('etag'))
    if (etag !== hex) throw new Error(`PUT /${key}?partNumber=${partNumber}: ETag ${etag} does not match MD5 ${hex}`)
    return etag
  }

  async function putParts({ key, body }, uploadId) {
    const results = await Promise.allSettled(
      Array.from({ length: Math.ceil(body.length / PART_SIZE) }, (_, i) =>
        putPart(key, uploadId, i + 1, body.subarray(i * PART_SIZE, (i + 1) * PART_SIZE)),
      ),
    )
    try {
      const failure = results.find((r) => r.status === 'rejected')
      if (failure) throw failure.reason
      const list = results.map((r, i) => `<Part><PartNumber>${i + 1}</PartNumber><ETag>"${r.value}"</ETag></Part>`)
      const xml = Buffer.from(`<CompleteMultipartUpload>${list.join('')}</CompleteMultipartUpload>`)
      await request({
        method: 'POST',
        key,
        query: { uploadId },
        headers: { 'content-type': 'application/xml', 'content-md5': md5(xml).base64 },
        body: xml,
      })
    } catch (e) {
      // The parts already uploaded are billed as storage until the upload is aborted.
      await request({ method: 'DELETE', key, query: { uploadId } }).catch((err) => console.warn(err.message))
      throw e
    }
  }

  // Containers do not wait for each other: a version goes up as soon as its own files are live.
  await Promise.all(
    [...containers].map(async ([name, steps]) => {
      for (const [i, objects] of steps.entries()) {
        const failures = (await Promise.allSettled(objects.map(put))).filter((r) => r.status === 'rejected')
        if (failures.length === 0) continue
        errors.push(...failures.map((r) => r.reason))
        failed.add(name)
        for (const { key } of steps.slice(i + 1).flat()) {
          stats.held++
          console.warn(`held back /${key}: ${name} has a failed upload`)
        }
        return
      }
    }),
  )

  for (const { dir, local, remote } of plans.toReversed()) {
    const stale = [...remote.keys()].filter((key) => !local.has(key))
    if (stale.length === 0) continue
    console.log(`${dir.local}/: ${stale.length} to delete`)
    await Promise.all(
      stale.map(async (key) => {
        const name = containerOf(dir, key)
        if (failed.has(name)) {
          stats.held++
          console.warn(`held back deleting /${key}: ${name} has a failed operation`)
          return
        }
        try {
          await small(() => request({ method: 'DELETE', key }))
        } catch (e) {
          if (e.status !== 404) {
            errors.push(e)
            failed.add(name)
            return
          }
        }
        stats.deleted++
        console.log(`deleted /${key}`)
      }),
    )
  }

  return { stats, errors }
}

function env(name) {
  const value = process.env[name]
  if (!value) throw new Error(`${name} is not set`)
  return value
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const started = Date.now()
  try {
    const { stats, errors } = await sync({
      root: process.cwd(),
      secretId: env('COS_SECRET_ID'),
      secretKey: env('COS_SECRET_KEY'),
      bucket: env('COS_BUCKET'),
      region: env('COS_REGION'),
      concurrency: Number(process.env.COS_CONCURRENCY || 32),
      partConcurrency: Number(process.env.COS_PART_CONCURRENCY || 4),
      maxAttempts: Number(process.env.COS_MAX_ATTEMPTS || 15),
    })
    console.log(
      `done in ${((Date.now() - started) / 1000).toFixed(1)}s: ${stats.uploaded} uploaded (${stats.bytes} bytes), ` +
        `${stats.unchanged} unchanged, ${stats.deleted} deleted, ${stats.held} held back`,
    )
    for (const err of errors) console.error(err.message ?? err)
    if (errors.length > 0) {
      console.error(`${errors.length} operations failed`)
      process.exit(1)
    }
  } catch (e) {
    console.error(e.message ?? e)
    process.exit(1)
  }
}
