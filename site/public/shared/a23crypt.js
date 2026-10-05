// a23crypt wire format, v1, in the browser.
//
// A byte-compatible port of src/a23crypt/core.py (compress_level=0 only).
// Ciphertexts produced here decrypt with the Python library and vice
// versa. Primitives come from the vendored, audited @noble packages.
//
// Every function also returns a trace of intermediate values so the
// landing pages can show what each layer actually did to the bytes.

import { gcm } from "./vendor/noble-ciphers/aes.js";
import { chacha20poly1305 } from "./vendor/noble-ciphers/chacha.js";
import { hkdf } from "./vendor/noble-hashes/hkdf.js";
import { sha256, sha512 } from "./vendor/noble-hashes/sha2.js";
import { sha3_512, shake256 } from "./vendor/noble-hashes/sha3.js";

export const KEY_SIZE_BYTES = 32;
export const SALT_SIZE_BYTES = 16;
export const NOISE_SEED_SIZE_BYTES = 16;
export const MAX_CHUNK_SIZE_BYTES = 64 * 1024;
export const CONTEXT_MAX_BYTES = 4 * 1024;
const MAX_FRAME_BODY_BYTES = 2 * MAX_CHUNK_SIZE_BYTES;

const VERSION_BYTE = 1;
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: false });
const INFO_SERVER = enc.encode("a23crypt-v1-server-stream");
const INFO_CLIENT = enc.encode("a23crypt-v1-client-stream");
const INFO_NOISE = enc.encode("a23crypt-v1-noise-seed");
const NONCE_DOMAIN_INNER = 0;
const NONCE_DOMAIN_OUTER = 1;

export class A23CryptError extends Error {
  constructor(message, detail) {
    super(message);
    this.name = this.constructor.name;
    // Which defense caught the failure. The Python library keeps
    // DecryptionError's message uniform on purpose; the demo surfaces
    // the layer so you can see the cascade working.
    this.detail = detail;
  }
}
export class IntegrityError extends A23CryptError {}
export class DecryptionError extends A23CryptError {}
export class InvalidKeyError extends A23CryptError {}

// ---------- byte helpers ----------

export const utf8 = (s) => enc.encode(s);
export const text = (b) => dec.decode(b);
export const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function hex(bytes, sep = "") {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(sep);
}

export function fromHex(s) {
  const clean = s.replace(/[^0-9a-fA-F]/g, "");
  if (clean.length % 2) throw new A23CryptError("hex string has an odd number of digits");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function toBase64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

const u32be = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
};
const u64be = (n) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), false);
  return b;
};
const readU32 = (b, o) => new DataView(b.buffer, b.byteOffset).getUint32(o, false);

// struct.pack(">Q?BI", chunk_index, is_final, flags, chunk_size)
const aadFor = (index, isFinal, flags, chunkSize) =>
  concat(u64be(index), Uint8Array.of(isFinal ? 1 : 0), Uint8Array.of(flags), u32be(chunkSize));

// struct.pack(">QI", chunk_index, domain)
const nonceFor = (index, domain) => concat(u64be(index), u32be(domain));

// ---------- key schedule ----------

function validate(serverKey, clientKey, recordKey) {
  if (serverKey.length !== KEY_SIZE_BYTES) throw new InvalidKeyError("server_key must be 32 bytes");
  if (clientKey.length !== KEY_SIZE_BYTES) throw new InvalidKeyError("client_key must be 32 bytes");
  if (recordKey.length === 0) throw new InvalidKeyError("record_key must not be empty");
  if (recordKey.length > CONTEXT_MAX_BYTES)
    throw new InvalidKeyError(`record_key must be ≤ ${CONTEXT_MAX_BYTES} bytes, got ${recordKey.length}`);
}

export function deriveSubkeys(serverKey, clientKey, recordKey, salt) {
  const hkdfSalt = concat(recordKey, salt);
  return {
    serverSub: hkdf(sha512, serverKey, hkdfSalt, INFO_SERVER, 32),
    clientSub: hkdf(sha3_512, clientKey, hkdfSalt, INFO_CLIENT, 32),
  };
}

export function deriveNoiseSeed(serverKey, clientKey, recordKey, salt, index) {
  return hkdf(
    sha256,
    concat(serverKey, clientKey),
    concat(recordKey, salt, u64be(index)),
    INFO_NOISE,
    NOISE_SEED_SIZE_BYTES,
  );
}

// ---------- noise layer (scalar reference, mirrors noise.py) ----------

export function addNoise(data, seed) {
  const stream = shake256(seed, { dkLen: 2 * (data.length + 64) });
  const out = [];
  const noiseAt = [];
  let pos = 0;
  let idx = 0;
  while (pos < data.length) {
    const take = Math.min(stream[2 * idx] & 0xf, data.length - pos);
    for (let i = 0; i < take; i++) out.push(data[pos + i]);
    pos += take;
    noiseAt.push(out.length);
    out.push(stream[2 * idx + 1]);
    idx++;
  }
  return { noisy: Uint8Array.from(out), noiseAt };
}

export function removeNoise(noisy, seed) {
  const stream = shake256(seed, { dkLen: 2 * (noisy.length + 64) });
  const out = [];
  let pos = 0;
  let idx = 0;
  while (pos < noisy.length) {
    const takeCount = stream[2 * idx] & 0xf;
    const take = Math.min(takeCount, Math.max(noisy.length - pos - 1, 0));
    for (let i = 0; i < take; i++) out.push(noisy[pos + i]);
    pos += take;
    if (pos < noisy.length) pos += 1;
    idx++;
  }
  return Uint8Array.from(out);
}

// ---------- encrypt ----------

// Returns { ciphertext, header, frames, spans }.
// `frames[i]` holds every intermediate value for chunk i.
// `spans` labels each byte range of the ciphertext for byte maps.
export function encrypt(plaintext, { serverKey, clientKey, recordKey, salt = randomBytes(SALT_SIZE_BYTES) }) {
  validate(serverKey, clientKey, recordKey);
  const flags = 0;
  const chunkSize = MAX_CHUNK_SIZE_BYTES;
  const { serverSub, clientSub } = deriveSubkeys(serverKey, clientKey, recordKey, salt);

  const header = concat(
    Uint8Array.of(VERSION_BYTE),
    Uint8Array.of(flags),
    u32be(chunkSize),
    u32be(recordKey.length),
    recordKey,
    salt,
  );
  const spans = [
    { field: "version", start: 0, end: 1 },
    { field: "flags", start: 1, end: 2 },
    { field: "chunk_size", start: 2, end: 6 },
    { field: "rk_len", start: 6, end: 10 },
    { field: "record_key", start: 10, end: 10 + recordKey.length },
    { field: "salt", start: 10 + recordKey.length, end: header.length },
  ];

  const chunks = [];
  if (plaintext.length === 0) chunks.push(new Uint8Array(0));
  for (let o = 0; o < plaintext.length; o += chunkSize) chunks.push(plaintext.subarray(o, o + chunkSize));

  const parts = [header];
  const frames = [];
  let offset = header.length;
  chunks.forEach((chunk, index) => {
    const isFinal = index === chunks.length - 1;
    const aad = aadFor(index, isFinal, flags, chunkSize);
    const innerCt = gcm(serverSub, nonceFor(index, NONCE_DOMAIN_INNER), aad).encrypt(chunk);
    const noiseSeed = deriveNoiseSeed(serverKey, clientKey, recordKey, salt, index);
    const { noisy, noiseAt } = addNoise(innerCt, noiseSeed);
    const outerCt = chacha20poly1305(clientSub, nonceFor(index, NONCE_DOMAIN_OUTER), aad).encrypt(noisy);
    const len = u32be(outerCt.length);
    parts.push(len, outerCt);
    spans.push(
      { field: "frame_len", frame: index, start: offset, end: offset + 4 },
      { field: "frame_body", frame: index, start: offset + 4, end: offset + 4 + outerCt.length - 16 },
      { field: "poly1305_tag", frame: index, start: offset + 4 + outerCt.length - 16, end: offset + 4 + outerCt.length },
    );
    offset += 4 + outerCt.length;
    frames.push({ index, isFinal, aad, chunk, innerCt, noiseSeed, noisy, noiseAt, outerCt });
  });

  return {
    ciphertext: concat(...parts),
    header: { flags, chunkSize, recordKey, salt, serverSub, clientSub },
    frames,
    spans,
  };
}

// ---------- decrypt ----------

export function decrypt(ciphertext, { serverKey, clientKey, recordKey }) {
  validate(serverKey, clientKey, recordKey);
  let pos = 0;
  const need = (n, what) => {
    if (pos + n > ciphertext.length) throw new IntegrityError(`truncated header (${what})`, "header parser");
    const out = ciphertext.subarray(pos, pos + n);
    pos += n;
    return out;
  };

  const version = need(1, "version")[0];
  if (version !== VERSION_BYTE)
    throw new IntegrityError(`unsupported format version: ${version}`, "version byte check");
  const flags = need(1, "flags")[0];
  const chunkSize = readU32(need(4, "chunk_size"), 0);
  const rkLen = readU32(need(4, "record_key length"), 0);
  if (rkLen > CONTEXT_MAX_BYTES)
    throw new IntegrityError(`record_key length ${rkLen} exceeds limit`, "header size cap");
  const storedRk = need(rkLen, "record_key body");
  if (storedRk.length !== recordKey.length || storedRk.some((b, i) => b !== recordKey[i]))
    throw new IntegrityError("record_key mismatch", "record_key binding");
  const salt = need(SALT_SIZE_BYTES, "salt");

  const { serverSub, clientSub } = deriveSubkeys(serverKey, clientKey, recordKey, salt);

  const frames = [];
  while (pos < ciphertext.length) {
    if (pos + 4 > ciphertext.length) throw new IntegrityError("truncated frame header", "frame parser");
    const length = readU32(ciphertext, pos);
    if (length > MAX_FRAME_BODY_BYTES)
      throw new IntegrityError(`frame length ${length} exceeds limit ${MAX_FRAME_BODY_BYTES}`, "frame size cap");
    if (pos + 4 + length > ciphertext.length) throw new IntegrityError("truncated frame body", "frame parser");
    frames.push(ciphertext.subarray(pos + 4, pos + 4 + length));
    pos += 4 + length;
  }

  const out = [];
  frames.forEach((frame, index) => {
    const isFinal = index === frames.length - 1;
    const aad = aadFor(index, isFinal, flags, chunkSize);
    let noisy;
    try {
      noisy = chacha20poly1305(clientSub, nonceFor(index, NONCE_DOMAIN_OUTER), aad).decrypt(frame);
    } catch {
      throw new DecryptionError("decryption failed", "outer ChaCha20-Poly1305 tag");
    }
    const noiseSeed = deriveNoiseSeed(serverKey, clientKey, recordKey, salt, index);
    const innerCt = removeNoise(noisy, noiseSeed);
    try {
      out.push(gcm(serverSub, nonceFor(index, NONCE_DOMAIN_INNER), aad).decrypt(innerCt));
    } catch {
      throw new DecryptionError("decryption failed", "inner AES-256-GCM tag");
    }
  });

  if (frames.length === 0)
    throw new IntegrityError("ciphertext contained no final chunk (possible truncation)", "final-chunk check");
  if (flags & 0x1f)
    throw new A23CryptError("this ciphertext is zstd-compressed; decrypt it with the Python library", "browser port");
  return concat(...out);
}

// Opens the first frame of an `encrypt` result one layer at a time,
// outside in, and reports how far it got. For visualising where a
// wrong key stops decryption; `decrypt` is the real entry point.
// Returns [{ layer, status, bytes }] with status "opened",
// "rejected", "scrambled" (noise removed at the wrong positions) or
// "unreached".
export function peel(sealed, { serverKey, clientKey, recordKey }) {
  const { salt, flags, chunkSize } = sealed.header;
  const f = sealed.frames[0];
  const aad = aadFor(f.index, f.isFinal, flags, chunkSize);
  const { serverSub, clientSub } = deriveSubkeys(serverKey, clientKey, recordKey, salt);
  const steps = [];
  const unreached = (...layers) => layers.forEach((layer) => steps.push({ layer, status: "unreached" }));

  let noisy;
  try {
    noisy = chacha20poly1305(clientSub, nonceFor(f.index, NONCE_DOMAIN_OUTER), aad).decrypt(f.outerCt);
    steps.push({ layer: "client", status: "opened", bytes: noisy });
  } catch {
    steps.push({ layer: "client", status: "rejected" });
    unreached("noise", "server");
    return steps;
  }

  const innerCt = removeNoise(noisy, deriveNoiseSeed(serverKey, clientKey, recordKey, salt, f.index));
  const clean = innerCt.length === f.innerCt.length && innerCt.every((b, i) => b === f.innerCt[i]);
  steps.push({ layer: "noise", status: clean ? "opened" : "scrambled", bytes: innerCt });

  try {
    const pt = gcm(serverSub, nonceFor(f.index, NONCE_DOMAIN_INNER), aad).decrypt(innerCt);
    steps.push({ layer: "server", status: "opened", bytes: pt });
  } catch {
    steps.push({ layer: "server", status: "rejected" });
  }
  return steps;
}

// Python script that decrypts a ciphertext produced on the page.
// `abbreviate` shortens long hex for display; copy the full version.
export function pythonSnippet({ ciphertext, serverKey, clientKey, recordKey }, { abbreviate = false } = {}) {
  const h = (b) => {
    const s = hex(b);
    return abbreviate && s.length > 16 ? `${s.slice(0, 8)}…${s.slice(-6)}` : s;
  };
  const rk = text(recordKey);
  const rkLiteral = /^[\x20-\x7e]*$/.test(rk) && !/["\\]/.test(rk) ? `b"${rk}"` : `bytes.fromhex("${hex(recordKey)}")`;
  return [
    "import a23crypt",
    "",
    `sealed = bytes.fromhex("${h(ciphertext)}")`,
    "print(a23crypt.decrypt(",
    "    sealed,",
    `    server_key=bytes.fromhex("${h(serverKey)}"),`,
    `    client_key=bytes.fromhex("${h(clientKey)}"),`,
    `    record_key=${rkLiteral},`,
    ").decode())",
  ].join("\n");
}

// The same script as a terminal command that needs only uv installed.
export function uvCommand(sealed, opts) {
  return `uv run --python 3.14 --with a23crypt python - <<'EOF'\n${pythonSnippet(sealed, opts)}\nEOF`;
}
