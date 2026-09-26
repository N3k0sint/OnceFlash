/**
 * OnceFlash — Zero-Leak Client-Side QR Code Generator (qrcode.js)
 * 
 * 100% Client-Side SVG generation running purely in browser memory.
 * NEVER makes third-party HTTP requests (preserves Zero-Knowledge guarantees).
 * Based on the compact QR Code matrix generation standard (ISO/IEC 18004).
 */

(function (global, factory) {
  if (typeof exports === 'object' && typeof module !== 'undefined') {
    module.exports = factory();
  } else if (typeof define === 'function' && define.amd) {
    define(factory);
  } else {
    global.QRCodeGenerator = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Galois Field GF(256) tables
  const EXP_TABLE = new Uint8Array(256);
  const LOG_TABLE = new Uint8Array(256);
  for (let i = 0, x = 1; i < 256; i++) {
    EXP_TABLE[i] = x;
    LOG_TABLE[x] = i;
    x = (x << 1) ^ (x & 128 ? 0x11d : 0);
  }

  function gfMul(x, y) {
    if (x === 0 || y === 0) return 0;
    return EXP_TABLE[(LOG_TABLE[x] + LOG_TABLE[y]) % 255];
  }

  function polyMul(p, q) {
    const r = new Uint8Array(p.length + q.length - 1);
    for (let i = 0; i < p.length; i++) {
      for (let j = 0; j < q.length; j++) {
        r[i + j] ^= gfMul(p[i], q[j]);
      }
    }
    return r;
  }

  function polyRemainder(div, poly) {
    const out = new Uint8Array(div);
    for (let i = 0; i <= out.length - poly.length; i++) {
      const coef = out[i];
      if (coef !== 0) {
        for (let j = 0; j < poly.length; j++) {
          out[i + j] ^= gfMul(poly[j], coef);
        }
      }
    }
    return out.subarray(out.length - poly.length + 1);
  }

  function getGenerator(deg) {
    let poly = new Uint8Array([1]);
    for (let i = 0; i < deg; i++) {
      poly = polyMul(poly, new Uint8Array([1, EXP_TABLE[i]]));
    }
    return poly;
  }

  // Capacity table for Byte Mode (L level)
  const CAPACITIES_L = [
    0, 17, 32, 53, 78, 106, 134, 154, 192, 230, 271, 321, 367, 425, 458, 520, 586, 644, 718, 792, 858
  ];

  // Total codeword counts per version
  const TOTAL_CODEWORDS = [
    0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346, 404, 466, 532, 581, 655, 733, 815, 901, 991, 1085
  ];

  // EC Codewords per version for Level L
  const EC_CODEWORDS_L = [
    0, 7, 10, 15, 20, 26, 36, 40, 48, 60, 72, 80, 96, 104, 120, 132, 144, 168, 180, 196, 224
  ];

  // Number of EC blocks per version (Level L)
  const NUM_BLOCKS_L = [
    0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8
  ];

  // Alignment pattern locations
  const ALIGNMENT_PATTERNS = [
    [], [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
    [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
    [6, 30, 54], [6, 32, 58], [6, 34, 62], [6, 26, 46, 66],
    [6, 26, 48, 70], [6, 26, 50, 74], [6, 30, 54, 78],
    [6, 30, 56, 82], [6, 30, 58, 86], [6, 34, 62, 90]
  ];

  function getVersion(dataLen) {
    for (let v = 1; v < CAPACITIES_L.length; v++) {
      if (dataLen <= CAPACITIES_L[v]) return v;
    }
    throw new Error("Data too large for QR Code generator (max ~850 bytes)");
  }

  function encodeData(dataStr, version) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(dataStr);
    const dataLen = bytes.length;
    const totalDataBytes = TOTAL_CODEWORDS[version] - EC_CODEWORDS_L[version];

    const bits = [];
    function appendBits(val, len) {
      for (let i = len - 1; i >= 0; i--) {
        bits.push((val >> i) & 1);
      }
    }

    // Byte mode indicator: 0100
    appendBits(4, 4);
    // Character count indicator
    const countBits = version < 10 ? 8 : 16;
    appendBits(dataLen, countBits);

    // Data bits
    for (let i = 0; i < dataLen; i++) {
      appendBits(bytes[i], 8);
    }

    // Terminator (up to 4 zeroes)
    const capacityBits = totalDataBytes * 8;
    const termLen = Math.min(4, capacityBits - bits.length);
    for (let i = 0; i < termLen; i++) bits.push(0);

    // Pad to 8-bit boundary
    while (bits.length % 8 !== 0) bits.push(0);

    // Pad bytes 0xEC, 0x11
    const padBytes = [0xec, 0x11];
    let padIdx = 0;
    while (bits.length < capacityBits) {
      appendBits(padBytes[padIdx % 2], 8);
      padIdx++;
    }

    // Convert bits to byte array
    const dataBytes = new Uint8Array(totalDataBytes);
    for (let i = 0; i < totalDataBytes; i++) {
      let b = 0;
      for (let j = 0; j < 8; j++) {
        b = (b << 1) | bits[i * 8 + j];
      }
      dataBytes[i] = b;
    }

    return dataBytes;
  }

  function createBlocks(dataBytes, version) {
    const totalCodewords = TOTAL_CODEWORDS[version];
    const ecTotal = EC_CODEWORDS_L[version];
    const numBlocks = NUM_BLOCKS_L[version];
    const dataTotal = totalCodewords - ecTotal;

    const ecPerBlock = ecTotal / numBlocks;
    const dataShort = Math.floor(dataTotal / numBlocks);
    const numLongBlocks = dataTotal % numBlocks;

    const dataBlocks = [];
    const ecBlocks = [];
    const gen = getGenerator(ecPerBlock);

    let offset = 0;
    for (let i = 0; i < numBlocks; i++) {
      const len = i >= (numBlocks - numLongBlocks) ? dataShort + 1 : dataShort;
      const blockData = dataBytes.subarray(offset, offset + len);
      offset += len;
      dataBlocks.push(blockData);

      // Compute EC for block
      const toDiv = new Uint8Array(blockData.length + ecPerBlock);
      toDiv.set(blockData);
      const remainder = polyRemainder(toDiv, gen);
      ecBlocks.push(remainder);
    }

    // Interleave data codewords
    const interleaved = new Uint8Array(totalCodewords);
    let idx = 0;
    const maxDataLen = dataShort + (numLongBlocks > 0 ? 1 : 0);

    for (let j = 0; j < maxDataLen; j++) {
      for (let b = 0; b < numBlocks; b++) {
        if (j < dataBlocks[b].length) {
          interleaved[idx++] = dataBlocks[b][j];
        }
      }
    }

    // Interleave EC codewords
    for (let j = 0; j < ecPerBlock; j++) {
      for (let b = 0; b < numBlocks; b++) {
        interleaved[idx++] = ecBlocks[b][j];
      }
    }

    return interleaved;
  }

  function createMatrix(version) {
    const size = 17 + 4 * version;
    const matrix = [];
    const isReserved = [];
    for (let r = 0; r < size; r++) {
      matrix.push(new Uint8Array(size));
      isReserved.push(new Uint8Array(size));
    }

    function setFinder(r, c) {
      for (let y = -1; y <= 7; y++) {
        for (let x = -1; x <= 7; x++) {
          const cy = r + y, cx = c + x;
          if (cy >= 0 && cy < size && cx >= 0 && cx < size) {
            isReserved[cy][cx] = 1;
            if (y >= 0 && y <= 6 && x >= 0 && x <= 6) {
              const on = (y === 0 || y === 6 || x === 0 || x === 6 || (y >= 2 && y <= 4 && x >= 2 && x <= 4));
              matrix[cy][cx] = on ? 1 : 0;
            } else {
              matrix[cy][cx] = 0; // Separator
            }
          }
        }
      }
    }

    // Finder patterns
    setFinder(0, 0);
    setFinder(0, size - 7);
    setFinder(size - 7, 0);

    // Timing patterns
    for (let i = 8; i < size - 8; i++) {
      const val = (i % 2 === 0) ? 1 : 0;
      if (!isReserved[6][i]) {
        matrix[6][i] = val;
        isReserved[6][i] = 1;
      }
      if (!isReserved[i][6]) {
        matrix[i][6] = val;
        isReserved[i][6] = 1;
      }
    }

    // Alignment patterns
    const alignCoords = ALIGNMENT_PATTERNS[version] || [];
    for (let i = 0; i < alignCoords.length; i++) {
      for (let j = 0; j < alignCoords.length; j++) {
        const cy = alignCoords[i], cx = alignCoords[j];
        if (isReserved[cy][cx]) continue;
        for (let y = -2; y <= 2; y++) {
          for (let x = -2; x <= 2; x++) {
            const on = (Math.abs(y) === 2 || Math.abs(x) === 2 || (y === 0 && x === 0));
            matrix[cy + y][cx + x] = on ? 1 : 0;
            isReserved[cy + y][cx + x] = 1;
          }
        }
      }
    }

    // Dark module
    matrix[size - 8][8] = 1;
    isReserved[size - 8][8] = 1;

    // Reserve format information areas
    for (let i = 0; i < 9; i++) {
      if (i !== 6) {
        isReserved[8][i] = 1;
        isReserved[i][8] = 1;
      }
    }
    for (let i = 0; i < 8; i++) {
      isReserved[8][size - 1 - i] = 1;
      isReserved[size - 1 - i][8] = 1;
    }

    return { matrix, isReserved, size };
  }

  function placeData(matObj, codewords, maskPattern = 0) {
    const { matrix, isReserved, size } = matObj;
    let bitIdx = 0;
    const totalBits = codewords.length * 8;

    let dir = -1; // Going up
    let c = size - 1;
    while (c > 0) {
      if (c === 6) c--; // Skip vertical timing column
      const rStart = dir === -1 ? size - 1 : 0;
      const rEnd = dir === -1 ? -1 : size;
      const rStep = dir;

      for (let r = rStart; r !== rEnd; r += rStep) {
        for (let colOffset = 0; colOffset < 2; colOffset++) {
          const col = c - colOffset;
          if (!isReserved[r][col]) {
            let bit = 0;
            if (bitIdx < totalBits) {
              const byteVal = codewords[Math.floor(bitIdx / 8)];
              bit = (byteVal >> (7 - (bitIdx % 8))) & 1;
              bitIdx++;
            }
            // Mask 0: (r + col) % 2 === 0
            const mask = ((r + col) % 2 === 0) ? 1 : 0;
            matrix[r][col] = bit ^ mask;
          }
        }
      }
      dir = -dir;
      c -= 2;
    }
  }

  // Format bits for Level L, Mask 0: 0x77c4 -> bits: 1 1 1 0 1 1 1 1 1 0 0 0 1 0 0
  const FORMAT_BITS_L0 = [1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0];

  function placeFormat(matObj) {
    const { matrix, size } = matObj;
    const fb = FORMAT_BITS_L0;

    // Top-left
    matrix[8][0] = fb[0];
    matrix[8][1] = fb[1];
    matrix[8][2] = fb[2];
    matrix[8][3] = fb[3];
    matrix[8][4] = fb[4];
    matrix[8][5] = fb[5];
    matrix[8][7] = fb[6];
    matrix[8][8] = fb[7];
    matrix[7][8] = fb[8];
    matrix[5][8] = fb[9];
    matrix[4][8] = fb[10];
    matrix[3][8] = fb[11];
    matrix[2][8] = fb[12];
    matrix[1][8] = fb[13];
    matrix[0][8] = fb[14];

    // Top-right and bottom-left
    for (let i = 0; i < 8; i++) {
      matrix[8][size - 1 - i] = fb[i];
    }
    for (let i = 0; i < 7; i++) {
      matrix[size - 7 + i][8] = fb[8 + i];
    }
  }

  /**
   * Generates a pristine, scalable SVG string of the QR Code.
   * @param {string} text The text/URL to encode.
   * @param {number} margin Quiet zone modules (default 4).
   * @returns {string} SVG markup string.
   */
  function generateSVG(text, margin = 4) {
    const version = getVersion(text.length);
    const dataBytes = encodeData(text, version);
    const codewords = createBlocks(dataBytes, version);
    const matObj = createMatrix(version);
    placeData(matObj, codewords, 0);
    placeFormat(matObj);

    const { matrix, size } = matObj;
    const totalSize = size + margin * 2;
    let path = "";

    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (matrix[r][c]) {
          const x = c + margin;
          const y = r + margin;
          path += `M${x} ${y}h1v1h-1z `;
        }
      }
    }

    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${totalSize} ${totalSize}" shape-rendering="crispEdges" width="100%" height="100%"><rect width="${totalSize}" height="${totalSize}" fill="#ffffff"/><path d="${path}" fill="#0a0c10"/></svg>`;
  }

  return {
    generateSVG: generateSVG,
  };
});
