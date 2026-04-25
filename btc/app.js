// Base58 alphabet used by Bitcoin
var BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Decode(str) {
    var bytes = [0];
    for (var i = 0; i < str.length; i++) {
        var c = str[i];
        var charIndex = BASE58_ALPHABET.indexOf(c);
        if (charIndex < 0) return null;
        var carry = charIndex;
        for (var j = 0; j < bytes.length; j++) {
            var x = bytes[j] * 58 + carry;
            bytes[j] = x & 0xff;
            carry = x >> 8;
        }
        while (carry > 0) {
            bytes.push(carry & 0xff);
            carry = carry >> 8;
        }
    }
    var leadingZeroCount = 0;
    for (var k = 0; k < str.length && str[k] === "1"; k++) leadingZeroCount++;
    for (var z = 0; z < leadingZeroCount; z++) bytes.push(0);
    bytes.reverse();
    return new Uint8Array(bytes);
}

function base58Encode(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
    var zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
    var digits = [0];
    for (var i = zeros; i < bytes.length; i++) {
        var carry = bytes[i];
        for (var j = 0; j < digits.length; j++) {
            var x = digits[j] * 256 + carry;
            digits[j] = x % 58;
            carry = (x / 58) | 0;
        }
        while (carry > 0) {
            digits.push(carry % 58);
            carry = (carry / 58) | 0;
        }
    }
    var result = "";
    for (var i = 0; i < zeros; i++) result += "1";
    for (var i = digits.length - 1; i >= 0; i--) result += BASE58_ALPHABET[digits[i]];
    return result;
}

function concatBytes(a, b) {
    var c = new Uint8Array(a.length + b.length);
    c.set(a, 0);
    c.set(b, a.length);
    return c;
}

function bytesToWordArray(bytes) {
    var words = [];
    for (var i = 0; i < bytes.length; i++) {
        words[(i / 4) | 0] |= bytes[i] << (24 - 8 * (i % 4));
    }
    return CryptoJS.lib.WordArray.create(words, bytes.length);
}

function wordArrayToBytes(wordArray) {
    var words = wordArray.words;
    var sigBytes = wordArray.sigBytes;
    var bytes = new Uint8Array(sigBytes);
    for (var i = 0; i < sigBytes; i++) {
        bytes[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    }
    return bytes;
}

function doubleSHA256(bytes) {
    var wa = bytesToWordArray(bytes);
    var first = CryptoJS.SHA256(wa);
    var second = CryptoJS.SHA256(first);
    return wordArrayToBytes(second);
}

function hash160(bytes) {
    var wa = bytesToWordArray(bytes);
    var sha = CryptoJS.SHA256(wa);
    var ripemd = CryptoJS.RIPEMD160(sha);
    return wordArrayToBytes(ripemd);
}

function base58CheckEncode(payload) {
    var checksumFull = doubleSHA256(payload);
    var checksum = checksumFull.slice(0, 4);
    var full = concatBytes(payload, checksum);
    return base58Encode(full);
}

function decodeWIF(wif) {
    var decoded = base58Decode(wif.trim());
    if (!decoded || decoded.length < 37) return null;
    var payload = decoded.slice(0, decoded.length - 4);
    var checksum = decoded.slice(decoded.length - 4);
    var check = doubleSHA256(payload).slice(0, 4);
    for (var i = 0; i < 4; i++) if (check[i] !== checksum[i]) return null;
    if (payload[0] !== 0x80) return null;
    var compressed = false;
    var privBytes;
    if (payload.length === 34 && payload[payload.length - 1] === 0x01) {
        compressed = true;
        privBytes = payload.slice(1, 33);
    } else {
        privBytes = payload.slice(1, 33);
    }
    return { privateKey: privBytes, compressed: compressed };
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function wifToLegacyAddress(wif) {
    var decoded = decodeWIF(wif);
    if (!decoded) return null;
    var privHex = bytesToHex(decoded.privateKey);
    var ec = new elliptic.ec("secp256k1");
    var keyPair = ec.keyFromPrivate(privHex, "hex");
    var pubPoint = keyPair.getPublic();
    var pubBytes;
    if (decoded.compressed) {
        var xHex = pubPoint.getX().toString(16).padStart(64, "0");
        var prefix = pubPoint.getY().isEven() ? 0x02 : 0x03;
        pubBytes = new Uint8Array([prefix].concat(
            xHex.match(/.{2}/g).map(h => parseInt(h, 16))
        ));
    } else {
        return null;
    }
    var pubKeyHash = hash160(pubBytes);
    var versioned = concatBytes(new Uint8Array([0x00]), pubKeyHash);
    return base58CheckEncode(versioned);
}

document.getElementById("convertBtn").onclick = function () {
    var input = document.getElementById("wifInput").value.trim();
    if (!input) {
        alert("请输入至少一行 WIF。");
        return;
    }

    var lines = input.split("\n").map(l => l.trim()).filter(l => l !== "");
    if (lines.length > 5000) {
        alert("每次最多只能处理 5000 条 WIF。");
        return;
    }

    var results = [];

    for (var i = 0; i < lines.length; i++) {
        var addr = wifToLegacyAddress(lines[i]);
        results.push(addr ? addr : "");
    }

    document.getElementById("resultBox").value = results.join("\n");
};
