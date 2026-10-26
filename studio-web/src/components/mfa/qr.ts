// Minimal QR Code encoder: byte mode, error correction level M, versions 1-40.
// Follows the structure of Project Nayuki's QR Code generator (MIT licence).
// Enough for an otpauth:// enrollment URI; no dependency.

const ECC_PER_BLOCK_M = [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28]
const NUM_BLOCKS_M = [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49]
const FORMAT_BITS_M = 0

function rawDataModules(ver: number): number {
  let result = (16 * ver + 128) * ver + 64
  if (ver >= 2) {
    const numAlign = Math.floor(ver / 7) + 2
    result -= (25 * numAlign - 10) * numAlign - 55
    if (ver >= 7) result -= 36
  }
  return result
}

function dataCodewords(ver: number): number {
  return Math.floor(rawDataModules(ver) / 8) - ECC_PER_BLOCK_M[ver] * NUM_BLOCKS_M[ver]
}

function gfMul(x: number, y: number): number {
  let z = 0
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d)
    z ^= ((y >>> i) & 1) * x
  }
  return z
}

function rsDivisor(degree: number): number[] {
  const result = new Array<number>(degree).fill(0)
  result[degree - 1] = 1
  let root = 1
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < result.length; j++) {
      result[j] = gfMul(result[j], root)
      if (j + 1 < result.length) result[j] ^= result[j + 1]
    }
    root = gfMul(root, 0x02)
  }
  return result
}

function rsRemainder(data: number[], divisor: number[]): number[] {
  const result = divisor.map(() => 0)
  for (const b of data) {
    const factor = b ^ (result.shift() as number)
    result.push(0)
    divisor.forEach((coef, i) => { result[i] ^= gfMul(coef, factor) })
  }
  return result
}

const bit = (x: number, i: number) => ((x >>> i) & 1) !== 0

export function encodeQr(text: string): boolean[][] {
  const bytes = Array.from(new TextEncoder().encode(text))
  let ver = 1
  for (; ; ver++) {
    if (ver > 40) throw new Error('Data too long for a QR code')
    const ccBits = ver <= 9 ? 8 : 16
    if (4 + ccBits + bytes.length * 8 <= dataCodewords(ver) * 8) break
  }
  const ccBits = ver <= 9 ? 8 : 16
  const bits: number[] = []
  const append = (val: number, len: number) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1) }
  append(0x4, 4)
  append(bytes.length, ccBits)
  for (const b of bytes) append(b, 8)
  const capBits = dataCodewords(ver) * 8
  append(0, Math.min(4, capBits - bits.length))
  append(0, (8 - (bits.length % 8)) % 8)
  for (let pad = 0xec; bits.length < capBits; pad ^= 0xec ^ 0x11) append(pad, 8)
  const data: number[] = []
  for (let i = 0; i < bits.length; i += 8) {
    let v = 0
    for (let j = 0; j < 8; j++) v = (v << 1) | bits[i + j]
    data.push(v)
  }

  const size = ver * 4 + 17
  const modules: boolean[][] = Array.from({ length: size }, () => new Array<boolean>(size).fill(false))
  const isFn: boolean[][] = Array.from({ length: size }, () => new Array<boolean>(size).fill(false))
  const setFn = (x: number, y: number, dark: boolean) => { modules[y][x] = dark; isFn[y][x] = true }

  for (let i = 0; i < size; i++) { setFn(6, i, i % 2 === 0); setFn(i, 6, i % 2 === 0) }
  const finder = (x: number, y: number) => {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const d = Math.max(Math.abs(dx), Math.abs(dy))
      const xx = x + dx, yy = y + dy
      if (xx >= 0 && xx < size && yy >= 0 && yy < size) setFn(xx, yy, d !== 2 && d !== 4)
    }
  }
  finder(3, 3); finder(size - 4, 3); finder(3, size - 4)

  const align: number[] = []
  if (ver > 1) {
    const numAlign = Math.floor(ver / 7) + 2
    const step = Math.floor((ver * 8 + numAlign * 3 + 5) / (numAlign * 4 - 4)) * 2
    for (let pos = size - 7; align.length < numAlign - 1; pos -= step) align.splice(0, 0, pos)
    align.splice(0, 0, 6)
  }
  for (let i = 0; i < align.length; i++) for (let j = 0; j < align.length; j++) {
    if ((i === 0 && j === 0) || (i === 0 && j === align.length - 1) || (i === align.length - 1 && j === 0)) continue
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) {
      setFn(align[i] + dx, align[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1)
    }
  }

  const drawFormat = (mask: number) => {
    const d = (FORMAT_BITS_M << 3) | mask
    let rem = d
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537)
    const b = ((d << 10) | rem) ^ 0x5412
    for (let i = 0; i <= 5; i++) setFn(8, i, bit(b, i))
    setFn(8, 7, bit(b, 6)); setFn(8, 8, bit(b, 7)); setFn(7, 8, bit(b, 8))
    for (let i = 9; i < 15; i++) setFn(14 - i, 8, bit(b, i))
    for (let i = 0; i < 8; i++) setFn(size - 1 - i, 8, bit(b, i))
    for (let i = 8; i < 15; i++) setFn(8, size - 15 + i, bit(b, i))
    setFn(8, size - 8, true)
  }
  drawFormat(0)
  if (ver >= 7) {
    let rem = ver
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25)
    const b = (ver << 12) | rem
    for (let i = 0; i < 18; i++) {
      const a = size - 11 + (i % 3), c = Math.floor(i / 3)
      setFn(a, c, bit(b, i)); setFn(c, a, bit(b, i))
    }
  }

  const numBlocks = NUM_BLOCKS_M[ver], eccLen = ECC_PER_BLOCK_M[ver]
  const rawCodewords = Math.floor(rawDataModules(ver) / 8)
  const numShort = numBlocks - (rawCodewords % numBlocks)
  const shortLen = Math.floor(rawCodewords / numBlocks)
  const div = rsDivisor(eccLen)
  const blocks: number[][] = []
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const dat = data.slice(k, k + shortLen - eccLen + (i < numShort ? 0 : 1))
    k += dat.length
    const ecc = rsRemainder(dat, div)
    if (i < numShort) dat.push(0)
    blocks.push(dat.concat(ecc))
  }
  const all: number[] = []
  for (let i = 0; i < blocks[0].length; i++) {
    blocks.forEach((blk, j) => { if (i !== shortLen - eccLen || j >= numShort) all.push(blk[i]) })
  }

  let idx = 0
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5
    for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) {
      const x = right - j
      const y = ((right + 1) & 2) === 0 ? size - 1 - vert : vert
      if (!isFn[y][x] && idx < all.length * 8) {
        modules[y][x] = bit(all[idx >>> 3], 7 - (idx & 7))
        idx++
      }
    }
  }

  const masked = (mask: number, x: number, y: number) => {
    switch (mask) {
      case 0: return (x + y) % 2 === 0
      case 1: return y % 2 === 0
      case 2: return x % 3 === 0
      case 3: return (x + y) % 3 === 0
      case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0
      case 5: return (x * y) % 2 + (x * y) % 3 === 0
      case 6: return ((x * y) % 2 + (x * y) % 3) % 2 === 0
      default: return ((x + y) % 2 + (x * y) % 3) % 2 === 0
    }
  }
  const applyMask = (mask: number) => {
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
      if (!isFn[y][x] && masked(mask, x, y)) modules[y][x] = !modules[y][x]
    }
  }
  // Penalty rules 1, 2 and 4 of ISO 18004 (rule 3 omitted; any mask decodes).
  const penalty = () => {
    let p = 0, dark = 0
    for (let a = 0; a < size; a++) {
      for (const horiz of [true, false]) {
        let run = 1
        for (let b = 1; b <= size; b++) {
          const same = b < size && (horiz ? modules[a][b] === modules[a][b - 1] : modules[b][a] === modules[b - 1][a])
          if (same) run++
          else { if (run >= 5) p += 3 + (run - 5); run = 1 }
        }
      }
    }
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
      if (modules[y][x]) dark++
      if (x < size - 1 && y < size - 1) {
        const c = modules[y][x]
        if (c === modules[y][x + 1] && c === modules[y + 1][x] && c === modules[y + 1][x + 1]) p += 3
      }
    }
    const total = size * size
    p += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10
    return p
  }
  let best = 0, bestScore = Infinity
  for (let m = 0; m < 8; m++) {
    applyMask(m); drawFormat(m)
    const s = penalty()
    if (s < bestScore) { best = m; bestScore = s }
    applyMask(m)
  }
  applyMask(best); drawFormat(best)
  return modules
}

/** SVG path data for the dark modules, offset by a 4-module quiet zone. */
export function qrPath(modules: boolean[][]): { d: string; size: number } {
  const n = modules.length
  let d = ''
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (modules[y][x]) d += `M${x + 4},${y + 4}h1v1h-1z`
  return { d, size: n + 8 }
}
