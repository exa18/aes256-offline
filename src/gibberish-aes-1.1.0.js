/**
 * Gibberish-AES v1.1.0 (Deobfuscated & Modernized)
 * 
 * Changelog v1.1.0:
 * - Added PBKDF2 key derivation compatible with OpenSSL `-pbkdf2` (default 10000 iterations, SHA-256).
 * - Added HMAC-SHA1 and HMAC-SHA256 implementations.
 * - Maintained full backward compatibility with legacy EVP_BytesToKey ('md5', 'sha1', 'sha256').
 */
/**
 * Supported Key Derivation & Hashing Modes for GibberishAES.enc() / GibberishAES.dec()
 *
 * Signature:
 *   GibberishAES.enc(data, pass, [hashType], [iterations])
 *   GibberishAES.dec(data, pass, [hashType], [iterations])
 *
 * +-----------------+-------------------------+------------------------------------------+----------------------------+
 * | hashType (3rd)  | iterations (4th)        | Equivalent OpenSSL CLI Flags             | OpenSSL Status             |
 * +-----------------+-------------------------+------------------------------------------+----------------------------+
 * | 'pbkdf2'        | Optional (default 10000)| -pbkdf2 (or -pbkdf2 -iter N)             | Recommended (No warnings)  |
 * | 'pbkdf2-sha256' | Optional (default 10000)| -pbkdf2 -md sha256 (or -iter N)          | Recommended (No warnings)  |
 * | 'pbkdf2-sha1'   | Optional (default 10000)| -pbkdf2 -md sha1 (or -iter N)            | Accepted (No warnings)     |
 * | 'sha256'        | Ignored                 | -md sha256                               | Deprecated (Shows WARNING) |
 * | 'sha1'          | Ignored                 | -md sha1                                 | Deprecated (Shows WARNING) |
 * | 'md5' or ''     | Ignored                 | -md md5                                  | Deprecated (Shows WARNING) |
 * +-----------------+-------------------------+------------------------------------------+----------------------------+
 *
 * Bash / OpenSSL Decryption Examples:
 *   # Recommended (PBKDF2-SHA256, 10000 iterations):
 *   echo "<CIPHERTEXT>" | openssl enc -d -aes-256-cbc -pbkdf2 -a -k "<PASSWORD>"
 *
 *   # Custom iterations (e.g., 50000):
 *   echo "<CIPHERTEXT>" | openssl enc -d -aes-256-cbc -pbkdf2 -md sha256 -iter 50000 -a -k "<PASSWORD>"
 *
 *   # Legacy default (MD5, backward-compatible with v1.0.0):
 *   echo "<CIPHERTEXT>" | openssl enc -d -aes-256-cbc -md md5 -a -k "<PASSWORD>"
 *
 * Notes:
 *   - Add the '-A' flag to OpenSSL if <CIPHERTEXT> is passed as a single line without line breaks.
 *   - Default cipher is AES-256-CBC; adjust to -aes-128-cbc or -aes-192-cbc if GibberishAES.size() is changed.
 */
(function(root, factory) {
    if (typeof exports === "object") {
        module.exports = factory();
    } else if (typeof define === "function" && define.amd) {
        define(factory);
    } else {
        root.GibberishAES = factory();
    }
}(this, function() {
    "use strict";

    // Default AES-256 configuration (Nr = 14 rounds, Nk = 8 32-bit words)
    var Nr = 14;
    var Nk = 8;
    var Decrypt = false;

    // --- UTF-8 & String/Array Helpers ---

    var utf8Encode = function(str) {
        try {
            return unescape(encodeURIComponent(str));
        } catch (err) {
            throw "Error on UTF-8 encode";
        }
    };

    var utf8Decode = function(str) {
        try {
            return decodeURIComponent(escape(str));
        } catch (err) {
            return "Error: bad password!?";
        }
    };

    var padBlock = function(block) {
        var padVal, i, padded = [];
        if (block.length < 16) {
            padVal = 16 - block.length;
            padded = [
                padVal, padVal, padVal, padVal,
                padVal, padVal, padVal, padVal,
                padVal, padVal, padVal, padVal,
                padVal, padVal, padVal, padVal
            ];
        }
        for (i = 0; i < block.length; i++) {
            padded[i] = block[i];
        }
        return padded;
    };

    var decBytes = function(block, removePadding) {
        var padVal, i, str = "";
        if (removePadding) {
            padVal = block[15];
            if (padVal > 16) {
                return "Error: bad password!?";
            }
            if (padVal === 16) {
                return "";
            }
            for (i = 0; i < 16 - padVal; i++) {
                str += String.fromCharCode(block[i]);
            }
        } else {
            for (i = 0; i < 16; i++) {
                str += String.fromCharCode(block[i]);
            }
        }
        return str;
    };

    var a2h = function(arr) {
        var i, hex = "";
        for (i = 0; i < arr.length; i++) {
            hex += (arr[i] < 16 ? "0" : "") + arr[i].toString(16);
        }
        return hex;
    };

    var h2a = function(hex) {
        var arr = [];
        hex.replace(/(..)/g, function(pair) {
            arr.push(parseInt(pair, 16));
        });
        return arr;
    };

    var s2a = function(str, binary) {
        var i, arr = [];
        if (!binary) {
            str = utf8Encode(str);
        }
        for (i = 0; i < str.length; i++) {
            arr[i] = str.charCodeAt(i);
        }
        return arr;
    };

    var size = function(bits) {
        switch (bits) {
            case 128:
                Nr = 10;
                Nk = 4;
                break;
            case 192:
                Nr = 12;
                Nk = 6;
                break;
            case 256:
                Nr = 14;
                Nk = 8;
                break;
            default:
                throw "Invalid Key Size Specified:" + bits;
        }
    };

    var createSalt = function(len) {
        var i, salt = [];
        for (i = 0; i < len; i++) {
            salt = salt.concat(Math.floor(256 * Math.random()));
        }
        return salt;
    };

    var hexToWords = function(hex, wordSize) {
        var i, arr = [];
        for (i = 0; i < hex.length; i += wordSize) {
            arr[i / wordSize] = parseInt(hex.substr(i, wordSize), 16);
        }
        return arr;
    };

    // --- Hash Functions (MD5, SHA-1, SHA-256) ---

    var md5 = function(data) {
        function rotl(x, n) { return (x << n) | (x >>> (32 - n)); }
        function addUnsigned(x, y) {
            var x4, y4, x8, y8, res;
            x8 = 2147483648 & x;
            y8 = 2147483648 & y;
            x4 = 1073741824 & x;
            y4 = 1073741824 & y;
            res = (1073741823 & x) + (1073741823 & y);
            if (x4 & y4) return 2147483648 ^ res ^ x8 ^ y8;
            if (x4 | y4) {
                return (1073741824 & res) ? (3221225472 ^ res ^ x8 ^ y8) : (1073741824 ^ res ^ x8 ^ y8);
            }
            return res ^ x8 ^ y8;
        }
        function F(x, y, z) { return (x & y) | ((~x) & z); }
        function G(x, y, z) { return (x & z) | (y & (~z)); }
        function H(x, y, z) { return x ^ y ^ z; }
        function I(x, y, z) { return y ^ (x | (~z)); }
        function FF(a, b, c, d, x, s, ac) {
            a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));
            return addUnsigned(rotl(a, s), b);
        }
        function GG(a, b, c, d, x, s, ac) {
            a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));
            return addUnsigned(rotl(a, s), b);
        }
        function HH(a, b, c, d, x, s, ac) {
            a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));
            return addUnsigned(rotl(a, s), b);
        }
        function II(a, b, c, d, x, s, ac) {
            a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));
            return addUnsigned(rotl(a, s), b);
        }
        function convertToWordArray(bytes) {
            var wordIdx, len = bytes.length, temp1 = len + 8, temp2 = (temp1 - (temp1 % 64)) / 64,
                numWords = 16 * (temp2 + 1), words = [], bytePos = 0, byteCount = 0;
            while (byteCount < len) {
                wordIdx = (byteCount - (byteCount % 4)) / 4;
                bytePos = 8 * (byteCount % 4);
                words[wordIdx] = words[wordIdx] | (bytes[byteCount] << bytePos);
                byteCount++;
            }
            wordIdx = (byteCount - (byteCount % 4)) / 4;
            bytePos = 8 * (byteCount % 4);
            words[wordIdx] = words[wordIdx] | (128 << bytePos);
            words[numWords - 2] = len << 3;
            words[numWords - 1] = len >>> 29;
            return words;
        }
        function wordToBytes(val) {
            var byteVal, i, out = [];
            for (i = 0; i <= 3; i++) {
                byteVal = 255 & (val >>> (8 * i));
                out = out.concat(byteVal);
            }
            return out;
        }

        var k, AA, BB, CC, DD, a, b, c, d, x = [],
            T = hexToWords("67452301efcdab8998badcfe10325476d76aa478e8c7b756242070dbc1bdceeef57c0faf4787c62aa8304613fd469501698098d88b44f7afffff5bb1895cd7be6b901122fd987193a679438e49b40821f61e2562c040b340265e5a51e9b6c7aad62f105d02441453d8a1e681e7d3fbc821e1cde6c33707d6f4d50d87455a14eda9e3e905fcefa3f8676f02d98d2a4c8afffa39428771f6816d9d6122fde5380ca4beea444bdecfa9f6bb4b60bebfbc70289b7ec6eaa127fad4ef308504881d05d9d4d039e6db99e51fa27cf8c4ac5665f4292244432aff97ab9423a7fc93a039655b59c38f0ccc92ffeff47d85845dd16fa87e4ffe2ce6e0a30143144e0811a1f7537e82bd3af2352ad7d2bbeb86d391", 8);

        x = convertToWordArray(data);
        a = T[0]; b = T[1]; c = T[2]; d = T[3];

        for (k = 0; k < x.length; k += 16) {
            AA = a; BB = b; CC = c; DD = d;
            a = FF(a, b, c, d, x[k + 0], 7, T[4]);   d = FF(d, a, b, c, x[k + 1], 12, T[5]);
            c = FF(c, d, a, b, x[k + 2], 17, T[6]);  b = FF(b, c, d, a, x[k + 3], 22, T[7]);
            a = FF(a, b, c, d, x[k + 4], 7, T[8]);   d = FF(d, a, b, c, x[k + 5], 12, T[9]);
            c = FF(c, d, a, b, x[k + 6], 17, T[10]); b = FF(b, c, d, a, x[k + 7], 22, T[11]);
            a = FF(a, b, c, d, x[k + 8], 7, T[12]);  d = FF(d, a, b, c, x[k + 9], 12, T[13]);
            c = FF(c, d, a, b, x[k + 10], 17, T[14]);b = FF(b, c, d, a, x[k + 11], 22, T[15]);
            a = FF(a, b, c, d, x[k + 12], 7, T[16]); d = FF(d, a, b, c, x[k + 13], 12, T[17]);
            c = FF(c, d, a, b, x[k + 14], 17, T[18]);b = FF(b, c, d, a, x[k + 15], 22, T[19]);

            a = GG(a, b, c, d, x[k + 1], 5, T[20]);  d = GG(d, a, b, c, x[k + 6], 9, T[21]);
            c = GG(c, d, a, b, x[k + 11], 14, T[22]);b = GG(b, c, d, a, x[k + 0], 20, T[23]);
            a = GG(a, b, c, d, x[k + 5], 5, T[24]);  d = GG(d, a, b, c, x[k + 10], 9, T[25]);
            c = GG(c, d, a, b, x[k + 15], 14, T[26]);b = GG(b, c, d, a, x[k + 4], 20, T[27]);
            a = GG(a, b, c, d, x[k + 9], 5, T[28]);  d = GG(d, a, b, c, x[k + 14], 9, T[29]);
            c = GG(c, d, a, b, x[k + 3], 14, T[30]); b = GG(b, c, d, a, x[k + 8], 20, T[31]);
            a = GG(a, b, c, d, x[k + 13], 5, T[32]); d = GG(d, a, b, c, x[k + 2], 9, T[33]);
            c = GG(c, d, a, b, x[k + 7], 14, T[34]); b = GG(b, c, d, a, x[k + 12], 20, T[35]);

            a = HH(a, b, c, d, x[k + 5], 4, T[36]);  d = HH(d, a, b, c, x[k + 8], 11, T[37]);
            c = HH(c, d, a, b, x[k + 11], 16, T[38]);b = HH(b, c, d, a, x[k + 14], 23, T[39]);
            a = HH(a, b, c, d, x[k + 1], 4, T[40]);  d = HH(d, a, b, c, x[k + 4], 11, T[41]);
            c = HH(c, d, a, b, x[k + 7], 16, T[42]); b = HH(b, c, d, a, x[k + 10], 23, T[43]);
            a = HH(a, b, c, d, x[k + 13], 4, T[44]); d = HH(d, a, b, c, x[k + 0], 11, T[45]);
            c = HH(c, d, a, b, x[k + 3], 16, T[46]); b = HH(b, c, d, a, x[k + 6], 23, T[47]);
            a = HH(a, b, c, d, x[k + 9], 4, T[48]);  d = HH(d, a, b, c, x[k + 12], 11, T[49]);
            c = HH(c, d, a, b, x[k + 15], 16, T[50]);b = HH(b, c, d, a, x[k + 2], 23, T[51]);

            a = II(a, b, c, d, x[k + 0], 6, T[52]);  d = II(d, a, b, c, x[k + 7], 10, T[53]);
            c = II(c, d, a, b, x[k + 14], 15, T[54]);b = II(b, c, d, a, x[k + 5], 21, T[55]);
            a = II(a, b, c, d, x[k + 12], 6, T[56]); d = II(d, a, b, c, x[k + 3], 10, T[57]);
            c = II(c, d, a, b, x[k + 10], 15, T[58]);b = II(b, c, d, a, x[k + 1], 21, T[59]);
            a = II(a, b, c, d, x[k + 8], 6, T[60]);  d = II(d, a, b, c, x[k + 15], 10, T[61]);
            c = II(c, d, a, b, x[k + 6], 15, T[62]); b = II(b, c, d, a, x[k + 13], 21, T[63]);
            a = II(a, b, c, d, x[k + 4], 6, T[64]);  d = II(d, a, b, c, x[k + 11], 10, T[65]);
            c = II(c, d, a, b, x[k + 2], 15, T[66]); b = II(b, c, d, a, x[k + 9], 21, T[67]);

            a = addUnsigned(a, AA);
            b = addUnsigned(b, BB);
            c = addUnsigned(c, CC);
            d = addUnsigned(d, DD);
        }
        return wordToBytes(a).concat(wordToBytes(b), wordToBytes(c), wordToBytes(d));
    };

    var sha1 = function(bytes) {
        var H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
        var w = new Array(80);
        var len = bytes.length;
        var msg = bytes.slice();
        var i, j, a, b, c, d, e, f, k, temp;
        var rotl = function(x, n) { return (x << n) | (x >>> (32 - n)); };

        msg.push(0x80);
        while ((msg.length % 64) !== 56) {
            msg.push(0);
        }
        var bits = len * 8;
        for (i = 7; i >= 0; i--) {
            msg.push(i >= 4 ? (Math.floor(bits / Math.pow(2, i * 8)) & 255) : ((bits >>> (i * 8)) & 255));
        }

        for (i = 0; i < msg.length; i += 64) {
            for (j = 0; j < 16; j++) {
                w[j] = (msg[i + j * 4] << 24) | (msg[i + j * 4 + 1] << 16) | (msg[i + j * 4 + 2] << 8) | msg[i + j * 4 + 3];
            }
            for (j = 16; j < 80; j++) {
                w[j] = rotl(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
            }
            a = H[0]; b = H[1]; c = H[2]; d = H[3]; e = H[4];
            for (j = 0; j < 80; j++) {
                if (j < 20) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5a827999;
                } else if (j < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ed9eba1;
                } else if (j < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8f1bbcdc;
                } else {
                    f = b ^ c ^ d;
                    k = 0xca62c1d6;
                }
                temp = (rotl(a, 5) + f + e + k + w[j]) | 0;
                e = d; d = c; c = rotl(b, 30); b = a; a = temp;
            }
            H[0] = (H[0] + a) | 0;
            H[1] = (H[1] + b) | 0;
            H[2] = (H[2] + c) | 0;
            H[3] = (H[3] + d) | 0;
            H[4] = (H[4] + e) | 0;
        }
        var out = [];
        for (i = 0; i < 5; i++) {
            out.push((H[i] >>> 24) & 255, (H[i] >>> 16) & 255, (H[i] >>> 8) & 255, H[i] & 255);
        }
        return out;
    };

    var sha256 = function(bytes) {
        var K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ];
        var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        var w = new Array(64);
        var len = bytes.length;
        var msg = bytes.slice();
        var i, j, a, b, c, d, e, f, g, h, t1, t2, S0, S1, ch, maj, s0, s1;
        var rotr = function(x, n) { return (x >>> n) | (x << (32 - n)); };

        msg.push(0x80);
        while ((msg.length % 64) !== 56) {
            msg.push(0);
        }
        var bits = len * 8;
        for (i = 7; i >= 0; i--) {
            msg.push(i >= 4 ? (Math.floor(bits / Math.pow(2, i * 8)) & 255) : ((bits >>> (i * 8)) & 255));
        }

        for (i = 0; i < msg.length; i += 64) {
            for (j = 0; j < 16; j++) {
                w[j] = (msg[i + j * 4] << 24) | (msg[i + j * 4 + 1] << 16) | (msg[i + j * 4 + 2] << 8) | msg[i + j * 4 + 3];
            }
            for (j = 16; j < 64; j++) {
                s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >>> 3);
                s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >>> 10);
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
            }
            a = H[0]; b = H[1]; c = H[2]; d = H[3];
            e = H[4]; f = H[5]; g = H[6]; h = H[7];

            for (j = 0; j < 64; j++) {
                S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                ch = (e & f) ^ ((~e) & g);
                t1 = (h + S1 + ch + K[j] + w[j]) | 0;
                S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                maj = (a & b) ^ (a & c) ^ (b & c);
                t2 = (S0 + maj) | 0;

                h = g; g = f; f = e; e = (d + t1) | 0;
                d = c; c = b; b = a; a = (t1 + t2) | 0;
            }
            H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0;
            H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
            H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0;
            H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
        }
        var out = [];
        for (i = 0; i < 8; i++) {
            out.push((H[i] >>> 24) & 255, (H[i] >>> 16) & 255, (H[i] >>> 8) & 255, H[i] & 255);
        }
        return out;
    };

    // --- HMAC & PBKDF2 (RFC 2898 / OpenSSL -pbkdf2 compatible) ---

    var hmac = function(hashFn, blockSize, key, message) {
        var i, oKeyPad = [], iKeyPad = [];
        if (key.length > blockSize) {
            key = hashFn(key);
        }
        for (i = 0; i < blockSize; i++) {
            var kByte = i < key.length ? key[i] : 0;
            oKeyPad[i] = kByte ^ 0x5c;
            iKeyPad[i] = kByte ^ 0x36;
        }
        return hashFn(oKeyPad.concat(hashFn(iKeyPad.concat(message))));
    };

    var pbkdf2 = function(passwordArr, saltArr, iterations, keyLen, hashAlg) {
        var hashFn = (hashAlg === "sha1") ? sha1 : sha256;
        var hLen = (hashAlg === "sha1") ? 20 : 32;
        var blockSize = 64;
        var numBlocks = Math.ceil(keyLen / hLen);
        var derivedKey = [];
        var i, j, k;

        for (i = 1; i <= numBlocks; i++) {
            var blockIdx = [
                (i >>> 24) & 255,
                (i >>> 16) & 255,
                (i >>> 8) & 255,
                i & 255
            ];
            var u = hmac(hashFn, blockSize, passwordArr, saltArr.concat(blockIdx));
            var t = u.slice();

            for (j = 1; j < iterations; j++) {
                u = hmac(hashFn, blockSize, passwordArr, u);
                for (k = 0; k < hLen; k++) {
                    t[k] ^= u[k];
                }
            }
            derivedKey = derivedKey.concat(t);
        }
        return derivedKey.slice(0, keyLen);
    };

    /**
     * Key & IV derivation (OpenSSL EVP_BytesToKey & PBKDF2)
     * 
     * @param {Array} passwordArr - Password as byte array
     * @param {Array} saltArr - 8-byte salt array
     * @param {String} hashType - 'md5' (default legacy), 'sha1', 'sha256', 'pbkdf2' (SHA-256), 'pbkdf2-sha1'
     * @param {Number} iterations - Iteration count for PBKDF2 (default: 10000, matching OpenSSL default)
     */
    var openSSLKey = function(passwordArr, saltArr, hashType, iterations) {
        hashType = (hashType || "md5").toLowerCase();
        var keyLen = 4 * Nk;
        var ivLen = 16;

        // Modern PBKDF2 mode (eliminates OpenSSL deprecated key derivation warning)
        if (hashType === "pbkdf2" || hashType === "pbkdf2-sha256" || hashType === "pbkdf2-sha1") {
            var iter = iterations || 10000;
            var alg = (hashType === "pbkdf2-sha1") ? "sha1" : "sha256";
            var derived = pbkdf2(passwordArr, saltArr, iter, keyLen + ivLen, alg);
            return {
                key: derived.slice(0, keyLen),
                iv: derived.slice(keyLen, keyLen + ivLen)
            };
        }

        // Legacy EVP_BytesToKey mode
        var rounds = Nr >= 12 ? 3 : 2;
        var key = [], iv = [], hashes = [], result = [];
        var data00 = passwordArr.concat(saltArr);
        var i;

        if (hashType === "sha256") {
            var h1 = sha256(data00);
            var h2 = sha256(h1.concat(data00));
            result = h1.concat(h2);
            return {
                key: result.slice(0, keyLen),
                iv: result.slice(keyLen, keyLen + ivLen)
            };
        }

        if (hashType === "sha1") {
            hashes[0] = sha1(data00);
            result = hashes[0];
            while (result.length < keyLen + ivLen) {
                hashes.push(sha1(hashes[hashes.length - 1].concat(data00)));
                result = result.concat(hashes[hashes.length - 1]);
            }
            return {
                key: result.slice(0, keyLen),
                iv: result.slice(keyLen, keyLen + ivLen)
            };
        }

        // Default: MD5
        hashes[0] = md5(data00);
        result = hashes[0];
        for (i = 1; i < rounds; i++) {
            hashes[i] = md5(hashes[i - 1].concat(data00));
            result = result.concat(hashes[i]);
        }
        key = result.slice(0, keyLen);
        iv = result.slice(keyLen, keyLen + ivLen);
        return {
            key: key,
            iv: iv
        };
    };

    // --- AES Core Tables & Operations ---

    var invArray = function(arr) {
        var i, inv = [];
        for (i = 0; i < arr.length; i++) {
            inv[arr[i]] = i;
        }
        return inv;
    };

    var gmul = function(a, b) {
        var i, p;
        for (p = 0, i = 0; i < 8; i++) {
            p = (1 === (1 & b)) ? (p ^ a) : p;
            a = (a > 127) ? (283 ^ (a << 1)) : (a << 1);
            b >>>= 1;
        }
        return p;
    };

    var buildGmulTable = function(mult) {
        var i, table = [];
        for (i = 0; i < 256; i++) {
            table[i] = gmul(mult, i);
        }
        return table;
    };

    var SBOX = hexToWords("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16", 2);
    var INV_SBOX = invArray(SBOX);
    var RCON = hexToWords("01020408102040801b366cd8ab4d9a2f5ebc63c697356ad4b37dfaefc591", 2);
    var GMUL_2 = buildGmulTable(2);
    var GMUL_3 = buildGmulTable(3);
    var GMUL_9 = buildGmulTable(9);
    var GMUL_11 = buildGmulTable(11);
    var GMUL_13 = buildGmulTable(13);
    var GMUL_14 = buildGmulTable(14);

    var subWord = function(word) {
        for (var i = 0; i < 4; i++) {
            word[i] = SBOX[word[i]];
        }
        return word;
    };

    var rotWord = function(word) {
        var i, tmp = word[0];
        for (i = 0; i < 4; i++) {
            word[i] = word[i + 1];
        }
        word[3] = tmp;
        return word;
    };

    var expandKey = function(key) {
        var i, j, k, c, w = [], temp = [], schedule = [];
        for (i = 0; i < Nk; i++) {
            c = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
            w[i] = c;
        }
        for (i = Nk; i < 4 * (Nr + 1); i++) {
            w[i] = [];
            for (j = 0; j < 4; j++) {
                temp[j] = w[i - 1][j];
            }
            if (0 === i % Nk) {
                temp = subWord(rotWord(temp));
                temp[0] ^= RCON[i / Nk - 1];
            } else if (Nk > 6 && 4 === i % Nk) {
                temp = subWord(temp);
            }
            for (j = 0; j < 4; j++) {
                w[i][j] = w[i - Nk][j] ^ temp[j];
            }
        }
        for (i = 0; i < Nr + 1; i++) {
            schedule[i] = [];
            for (k = 0; k < 4; k++) {
                schedule[i].push(w[4 * i + k][0], w[4 * i + k][1], w[4 * i + k][2], w[4 * i + k][3]);
            }
        }
        return schedule;
    };

    var addRoundKey = function(state, schedule, round) {
        var i, out = [];
        for (i = 0; i < 16; i++) {
            out[i] = state[i] ^ schedule[round][i];
        }
        return out;
    };

    var xorBlocks = function(a, b) {
        var i, out = [];
        for (i = 0; i < 16; i++) {
            out[i] = a[i] ^ b[i];
        }
        return out;
    };

    var subBytes = function(state) {
        var i, box = Decrypt ? INV_SBOX : SBOX, out = [];
        for (i = 0; i < 16; i++) {
            out[i] = box[state[i]];
        }
        return out;
    };

    var shiftRows = function(state) {
        var i, out = [],
            map = Decrypt ? [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
                          : [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
        for (i = 0; i < 16; i++) {
            out[i] = state[map[i]];
        }
        return out;
    };

    var mixColumns = function(state) {
        var i, out = [];
        if (Decrypt) {
            for (i = 0; i < 4; i++) {
                out[4 * i]     = GMUL_14[state[4 * i]] ^ GMUL_11[state[1 + 4 * i]] ^ GMUL_13[state[2 + 4 * i]] ^ GMUL_9[state[3 + 4 * i]];
                out[1 + 4 * i] = GMUL_9[state[4 * i]]  ^ GMUL_14[state[1 + 4 * i]] ^ GMUL_11[state[2 + 4 * i]] ^ GMUL_13[state[3 + 4 * i]];
                out[2 + 4 * i] = GMUL_13[state[4 * i]] ^ GMUL_9[state[1 + 4 * i]]  ^ GMUL_14[state[2 + 4 * i]] ^ GMUL_11[state[3 + 4 * i]];
                out[3 + 4 * i] = GMUL_11[state[4 * i]] ^ GMUL_13[state[1 + 4 * i]] ^ GMUL_9[state[2 + 4 * i]]  ^ GMUL_14[state[3 + 4 * i]];
            }
        } else {
            for (i = 0; i < 4; i++) {
                out[4 * i]     = GMUL_2[state[4 * i]] ^ GMUL_3[state[1 + 4 * i]] ^ state[2 + 4 * i] ^ state[3 + 4 * i];
                out[1 + 4 * i] = state[4 * i] ^ GMUL_2[state[1 + 4 * i]] ^ GMUL_3[state[2 + 4 * i]] ^ state[3 + 4 * i];
                out[2 + 4 * i] = state[4 * i] ^ state[1 + 4 * i] ^ GMUL_2[state[2 + 4 * i]] ^ GMUL_3[state[3 + 4 * i]];
                out[3 + 4 * i] = GMUL_3[state[4 * i]] ^ state[1 + 4 * i] ^ state[2 + 4 * i] ^ GMUL_2[state[3 + 4 * i]];
            }
        }
        return out;
    };

    var encryptBlock = function(block, schedule) {
        Decrypt = false;
        var round, state = addRoundKey(block, schedule, 0);
        for (round = 1; round < Nr + 1; round++) {
            state = subBytes(state);
            state = shiftRows(state);
            if (round < Nr) {
                state = mixColumns(state);
            }
            state = addRoundKey(state, schedule, round);
        }
        return state;
    };

    var decryptBlock = function(block, schedule) {
        Decrypt = true;
        var round, state = addRoundKey(block, schedule, Nr);
        for (round = Nr - 1; round > -1; round--) {
            state = shiftRows(state);
            state = subBytes(state);
            state = addRoundKey(state, schedule, round);
            if (round > 0) {
                state = mixColumns(state);
            }
        }
        return state;
    };

    var rawEncrypt = function(plainBytes, key, iv) {
        var schedule = expandKey(key);
        var i, numBlocks = Math.ceil(plainBytes.length / 16), blocks = [], cipherBlocks = [];
        for (i = 0; i < numBlocks; i++) {
            blocks[i] = padBlock(plainBytes.slice(16 * i, 16 * i + 16));
        }
        if (0 === plainBytes.length % 16) {
            blocks.push([16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]);
            numBlocks++;
        }
        for (i = 0; i < blocks.length; i++) {
            blocks[i] = (0 === i) ? xorBlocks(blocks[i], iv) : xorBlocks(blocks[i], cipherBlocks[i - 1]);
            cipherBlocks[i] = encryptBlock(blocks[i], schedule);
        }
        return cipherBlocks;
    };

    var rawDecrypt = function(cipherBytes, key, iv, binary) {
        var schedule = expandKey(key);
        var i, numBlocks = cipherBytes.length / 16, blocks = [], plainBlocks = [], result = "";
        for (i = 0; i < numBlocks; i++) {
            blocks.push(cipherBytes.slice(16 * i, 16 * (i + 1)));
        }
        for (i = blocks.length - 1; i >= 0; i--) {
            plainBlocks[i] = decryptBlock(blocks[i], schedule);
            plainBlocks[i] = (0 === i) ? xorBlocks(plainBlocks[i], iv) : xorBlocks(plainBlocks[i], blocks[i - 1]);
        }
        for (i = 0; i < numBlocks - 1; i++) {
            result += decBytes(plainBlocks[i]);
        }
        result += decBytes(plainBlocks[i], true);
        return binary ? result : utf8Decode(result);
    };

    // --- Custom Block-Oriented Base64 Encoder/Decoder ---

    var Base64 = (function() {
        var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var alphabetArr = alphabet.split("");

        var encode = function(blocks) {
            var i, formatted, flat = [], rawB64 = "";
            for (i = 0; i < 16 * blocks.length; i++) {
                flat.push(blocks[Math.floor(i / 16)][i % 16]);
            }
            for (i = 0; i < flat.length; i += 3) {
                rawB64 += alphabetArr[flat[i] >> 2];
                rawB64 += alphabetArr[((3 & flat[i]) << 4) | (flat[i + 1] >> 4)];
                rawB64 += (undefined !== flat[i + 1]) ? alphabetArr[((15 & flat[i + 1]) << 2) | (flat[i + 2] >> 6)] : "=";
                rawB64 += (undefined !== flat[i + 2]) ? alphabetArr[63 & flat[i + 2]] : "=";
            }
            formatted = rawB64.slice(0, 64) + "\n";
            for (i = 1; i < Math.ceil(rawB64.length / 64); i++) {
                formatted += rawB64.slice(64 * i, 64 * i + 64) + (Math.ceil(rawB64.length / 64) === i + 1 ? "" : "\n");
            }
            return formatted;
        };

        var decode = function(str) {
            str = str.replace(/\n/g, "");
            var i, out = [], c = [], b = [];
            for (i = 0; i < str.length; i += 4) {
                c[0] = alphabet.indexOf(str.charAt(i));
                c[1] = alphabet.indexOf(str.charAt(i + 1));
                c[2] = alphabet.indexOf(str.charAt(i + 2));
                c[3] = alphabet.indexOf(str.charAt(i + 3));
                b[0] = (c[0] << 2) | (c[1] >> 4);
                b[1] = ((15 & c[1]) << 4) | (c[2] >> 2);
                b[2] = ((3 & c[2]) << 6) | c[3];
                out.push(b[0], b[1], b[2]);
            }
            return out.slice(0, out.length - (out.length % 16));
        };

        if (typeof Array.indexOf === "function") {
            alphabet = alphabetArr;
        }

        return {
            encode: encode,
            decode: decode
        };
    }());

    // --- Public Encrypt / Decrypt Methods ---

    /**
     * Encrypts plaintext using AES-CBC with OpenSSL-compatible Salted__ header.
     * 
     * @param {String} plainText - Text to encrypt
     * @param {String} password - Password string
     * @param {Boolean|String} binaryOrHash - Optional boolean (binary mode) or hashType string ('md5', 'sha1', 'sha256', 'pbkdf2')
     * @param {String|Number} hashTypeOrIter - Optional hashType string or PBKDF2 iterations count
     * @param {Number} iterations - Optional PBKDF2 iterations count (default: 10000)
     */
    var enc = function(plainText, password, binaryOrHash, hashTypeOrIter, iterations) {
        var binary = false;
        var hashType = "md5";
        var iter = 10000;

        if (typeof binaryOrHash === "string") {
            hashType = binaryOrHash;
            if (typeof hashTypeOrIter === "number") {
                iter = hashTypeOrIter;
            }
        } else {
            binary = !!binaryOrHash;
            if (typeof hashTypeOrIter === "string") {
                hashType = hashTypeOrIter;
            }
            if (typeof iterations === "number") {
                iter = iterations;
            }
        }

        var salt = createSalt(8);
        var keyIv = openSSLKey(s2a(password, binary), salt, hashType, iter);
        var header = [[83, 97, 108, 116, 101, 100, 95, 95].concat(salt)]; // "Salted__" + salt
        var plainBytes = s2a(plainText, binary);
        var cipherBlocks = rawEncrypt(plainBytes, keyIv.key, keyIv.iv);
        cipherBlocks = header.concat(cipherBlocks);
        return Base64.encode(cipherBlocks);
    };

    /**
     * Decrypts OpenSSL-compatible Base64 ciphertext.
     * 
     * @param {String} cipherText - Base64 encoded ciphertext
     * @param {String} password - Password string
     * @param {Boolean|String} binaryOrHash - Optional boolean (binary mode) or hashType string ('md5', 'sha1', 'sha256', 'pbkdf2')
     * @param {String|Number} hashTypeOrIter - Optional hashType string or PBKDF2 iterations count
     * @param {Number} iterations - Optional PBKDF2 iterations count (default: 10000)
     */
    var dec = function(cipherText, password, binaryOrHash, hashTypeOrIter, iterations) {
        var binary = false;
        var hashType = "md5";
        var iter = 10000;

        if (typeof binaryOrHash === "string") {
            hashType = binaryOrHash;
            if (typeof hashTypeOrIter === "number") {
                iter = hashTypeOrIter;
            }
        } else {
            binary = !!binaryOrHash;
            if (typeof hashTypeOrIter === "string") {
                hashType = hashTypeOrIter;
            }
            if (typeof iterations === "number") {
                iter = iterations;
            }
        }

        var decoded = Base64.decode(cipherText);
        var salt = decoded.slice(8, 16);
        var keyIv = openSSLKey(s2a(password, binary), salt, hashType, iter);
        var payload = decoded.slice(16, decoded.length);
        return rawDecrypt(payload, keyIv.key, keyIv.iv, binary);
    };

    return {
        version: "1.1.0",
        size: size,
        h2a: h2a,
        expandKey: expandKey,
        encryptBlock: encryptBlock,
        decryptBlock: decryptBlock,
        Decrypt: Decrypt,
        s2a: s2a,
        rawEncrypt: rawEncrypt,
        rawDecrypt: rawDecrypt,
        dec: dec,
        openSSLKey: openSSLKey,
        a2h: a2h,
        enc: enc,
        pbkdf2: pbkdf2,
        Hash: {
            MD5: md5,
            SHA1: sha1,
            SHA256: sha256,
            HMAC: hmac
        },
        Base64: Base64
    };
}));
