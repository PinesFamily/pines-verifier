import { requireThat, reject } from "./errors.ts";

// Bounded gunzip for an authenticated response body (RFC 1951 / RFC 1952).
//
// Pure JavaScript and synchronous on purpose. It is the ONE decoder that both the
// browser worker and the enclave's Node run, so no runtime API can make them differ,
// and the output buffer is sized from the encoded length and the schema's decoded
// cap BEFORE any inflation, so a ratio bomb cannot allocate. `DecompressionStream`
// exists in both runtimes but is asynchronous, and the single decode point
// (`parseHttp`) is reached from synchronous callers.
//
// Everything about the member is strict: the 10-byte header with no flags, exactly
// one member, no trailing bytes, and both trailer fields checked. A provider that
// serves anything else is refused rather than guessed at.
export const MAX_DECODED_RATIO = 20;
const HEADER_BYTES = 10;
const TRAILER_BYTES = 8;
const MAX_BITS = 15;

const CRC_TABLE = /* @__PURE__ */ (() => {
  const table = new Int32Array(256);
  for (let index = 0; index < 256; index++) {
    let value = index;
    for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    table[index] = value;
  }
  return table;
})();
export function crc32(bytes: Uint8Array): number {
  let crc = ~0;
  for (let index = 0; index < bytes.length; index++) crc = CRC_TABLE[(crc ^ bytes[index]!) & 0xff]! ^ (crc >>> 8);
  return ~crc >>> 0;
}

// RFC 1951 §3.2.5 and §3.2.6.
const LENGTH_BASE = /* @__PURE__ */ Uint16Array.of(3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258);
const LENGTH_EXTRA = /* @__PURE__ */ Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0);
const DISTANCE_BASE = /* @__PURE__ */ Uint16Array.of(1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577);
const DISTANCE_EXTRA = /* @__PURE__ */ Uint8Array.of(0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13);
const CODE_LENGTH_ORDER = /* @__PURE__ */ Uint8Array.of(16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15);

type Huffman = Readonly<{ counts: Uint16Array; symbols: Uint16Array; left: number; maxLength: number }>;

// Canonical Huffman tables, built from code lengths exactly as RFC 1951 §3.2.2
// describes. An over-subscribed or incomplete set is refused, never repaired.
function huffman(lengths: Uint8Array): Huffman {
  const counts = new Uint16Array(MAX_BITS + 1);
  for (const length of lengths) counts[length]! += 1;
  counts[0] = 0;
  let left = 1, maxLength = 0;
  for (let length = 1; length <= MAX_BITS; length++) {
    left = (left << 1) - counts[length]!;
    requireThat(left >= 0, "ENCODED_BODY_INVALID");
    if (counts[length]) maxLength = length;
  }
  // `left` is the unused code space at MAX_BITS: 0 for a complete set. Callers decide
  // whether an incomplete one is admitted (zlib's inflate_table rules).
  const offsets = new Uint16Array(MAX_BITS + 2);
  for (let length = 1; length <= MAX_BITS; length++) offsets[length + 1] = offsets[length]! + counts[length]!;
  const symbols = new Uint16Array(lengths.length);
  for (let symbol = 0; symbol < lengths.length; symbol++) {
    const length = lengths[symbol]!;
    if (length) symbols[offsets[length]!++] = symbol;
  }
  return { counts, symbols, left, maxLength };
}

const FIXED_LITERALS = /* @__PURE__ */ (() => {
  const lengths = new Uint8Array(288);
  lengths.fill(8, 0, 144); lengths.fill(9, 144, 256); lengths.fill(7, 256, 280); lengths.fill(8, 280, 288);
  return huffman(lengths);
})();
const FIXED_DISTANCES = /* @__PURE__ */ huffman(new Uint8Array(30).fill(5));

/**
 * Inflate a raw deflate stream into at most `limit` bytes. The whole input must be
 * consumed by the member's blocks: a stream that ends early leaves trailing bytes,
 * which the caller refuses.
 */
function inflateRaw(data: Uint8Array, limit: number): Uint8Array {
  // One allocation, bounded before the first block is read. `limit + 1` lets the
  // decoder notice that the output would exceed the cap without ever growing.
  const output = new Uint8Array(limit + 1);
  let written = 0;
  let position = 0;
  let bitBuffer = 0;
  let bitCount = 0;

  const bits = (need: number): number => {
    while (bitCount < need) {
      requireThat(position < data.length, "ENCODED_BODY_INVALID");
      bitBuffer |= data[position++]! << bitCount;
      bitCount += 8;
    }
    const value = bitBuffer & ((1 << need) - 1);
    bitBuffer >>>= need;
    bitCount -= need;
    return value;
  };
  const symbol = (table: Huffman): number => {
    let code = 0, first = 0, index = 0;
    for (let length = 1; length <= MAX_BITS; length++) {
      code |= bits(1);
      const count = table.counts[length]!;
      if (code - first < count) return table.symbols[index + (code - first)]!;
      index += count;
      first = (first + count) << 1;
      code <<= 1;
    }
    return reject("ENCODED_BODY_INVALID");
  };
  const put = (byte: number): void => {
    requireThat(written < output.length, "LIMIT_EXCEEDED");
    output[written++] = byte;
  };

  for (;;) {
    const final = bits(1);
    const type = bits(2);
    if (type === 0) {
      // Stored: discard the rest of the partial byte, then read whole bytes. Any
      // byte already buffered stays unread rather than being thrown away.
      const partial = bitCount % 8;
      bitBuffer >>>= partial;
      bitCount -= partial;
      position -= bitCount / 8;
      bitBuffer = 0;
      bitCount = 0;
      requireThat(position + 4 <= data.length, "ENCODED_BODY_INVALID");
      const length = data[position]! | (data[position + 1]! << 8);
      const complement = data[position + 2]! | (data[position + 3]! << 8);
      requireThat((length ^ 0xffff) === complement, "ENCODED_BODY_INVALID");
      position += 4;
      requireThat(position + length <= data.length, "ENCODED_BODY_INVALID");
      requireThat(written + length <= output.length, "LIMIT_EXCEEDED");
      output.set(data.subarray(position, position + length), written);
      written += length;
      position += length;
    } else if (type === 1 || type === 2) {
      let literals = FIXED_LITERALS, distances = FIXED_DISTANCES;
      if (type === 2) {
        const literalCount = bits(5) + 257, distanceCount = bits(5) + 1, codeCount = bits(4) + 4;
        requireThat(literalCount <= 286 && distanceCount <= 30, "ENCODED_BODY_INVALID");
        const codeLengths = new Uint8Array(19);
        for (let index = 0; index < codeCount; index++) codeLengths[CODE_LENGTH_ORDER[index]!] = bits(3);
        const codes = huffman(codeLengths);
        requireThat(codes.left === 0, "ENCODED_BODY_INVALID");
        const lengths = new Uint8Array(literalCount + distanceCount);
        for (let index = 0; index < lengths.length;) {
          const code = symbol(codes);
          if (code < 16) lengths[index++] = code;
          else {
            let repeat: number, value = 0;
            if (code === 16) {
              requireThat(index > 0, "ENCODED_BODY_INVALID");
              value = lengths[index - 1]!;
              repeat = 3 + bits(2);
            } else repeat = code === 17 ? 3 + bits(3) : 11 + bits(7);
            requireThat(index + repeat <= lengths.length, "ENCODED_BODY_INVALID");
            while (repeat--) lengths[index++] = value;
          }
        }
        requireThat(lengths[256] !== 0, "ENCODED_BODY_INVALID");
        literals = huffman(lengths.subarray(0, literalCount));
        distances = huffman(lengths.subarray(literalCount));
        // As zlib: an incomplete literal/length or distance set is admitted only when it is a
        // single code of length 1 (and a distance set may be empty); anything else refuses.
        requireThat(literals.left === 0 || literals.maxLength === 1, "ENCODED_BODY_INVALID");
        requireThat(distances.left === 0 || distances.maxLength <= 1, "ENCODED_BODY_INVALID");
      }
      for (;;) {
        const code = symbol(literals);
        if (code === 256) break;
        if (code < 256) { put(code); continue; }
        const lengthIndex = code - 257;
        requireThat(lengthIndex < LENGTH_BASE.length, "ENCODED_BODY_INVALID");
        const length = LENGTH_BASE[lengthIndex]! + bits(LENGTH_EXTRA[lengthIndex]!);
        const distanceIndex = symbol(distances);
        requireThat(distanceIndex < DISTANCE_BASE.length, "ENCODED_BODY_INVALID");
        const distance = DISTANCE_BASE[distanceIndex]! + bits(DISTANCE_EXTRA[distanceIndex]!);
        requireThat(distance <= written, "ENCODED_BODY_INVALID");
        requireThat(written + length <= output.length, "LIMIT_EXCEEDED");
        for (let index = 0; index < length; index++) output[written + index] = output[written + index - distance]!;
        written += length;
      }
    } else return reject("ENCODED_BODY_INVALID");
    if (final) break;
  }
  // The member's deflate data must be exactly what the blocks consumed: a shorter
  // stream means trailing bytes, which could be a second member or padding.
  requireThat(position === data.length && bitCount < 8, "ENCODED_BODY_INVALID");
  requireThat(written <= limit, "LIMIT_EXCEEDED");
  return output.subarray(0, written);
}

/**
 * Decode exactly one gzip member into at most `maxDecodedBytes` bytes.
 *
 * Strict by design: ID1/ID2/CM fixed, FLG zero (so no FEXTRA, FNAME, FCOMMENT or
 * FHCRC), MTIME/XFL/OS unconstrained, one member, no trailing bytes, CRC32 and
 * ISIZE both checked, and the decoded/encoded ratio bounded. The output buffer is
 * sized from the smaller of the schema's cap and the ratio bound before inflating.
 */
export function gunzip(encoded: Uint8Array, maxDecodedBytes: number): Uint8Array {
  requireThat(encoded instanceof Uint8Array, "ENCODED_BODY_INVALID");
  requireThat(Number.isSafeInteger(maxDecodedBytes) && maxDecodedBytes > 0, "INVALID_SCHEMA");
  requireThat(encoded.length > HEADER_BYTES + TRAILER_BYTES, "ENCODED_BODY_INVALID");
  requireThat(encoded[0] === 0x1f && encoded[1] === 0x8b && encoded[2] === 8 && encoded[3] === 0, "ENCODED_BODY_INVALID");
  const limit = Math.min(maxDecodedBytes, encoded.length * MAX_DECODED_RATIO);
  const decoded = inflateRaw(encoded.subarray(HEADER_BYTES, encoded.length - TRAILER_BYTES), limit);
  const trailer = encoded.subarray(encoded.length - TRAILER_BYTES);
  const declared = (trailer[0]! | (trailer[1]! << 8) | (trailer[2]! << 16) | (trailer[3]! << 24)) >>> 0;
  const size = (trailer[4]! | (trailer[5]! << 8) | (trailer[6]! << 16) | (trailer[7]! << 24)) >>> 0;
  requireThat(crc32(decoded) === declared, "ENCODED_BODY_INVALID");
  requireThat(size === decoded.length, "ENCODED_BODY_INVALID");
  requireThat(decoded.length <= maxDecodedBytes, "LIMIT_EXCEEDED");
  return decoded;
}
