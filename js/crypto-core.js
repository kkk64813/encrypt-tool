/*
 * crypto-core.js —— 双端共用的密码学核心（浏览器 / Node / 自解密文件均使用同一份代码）
 *
 * 算法：
 *   密钥派生  PBKDF2(SHA-256, 310000 次迭代)
 *   数据加密  AES-256-GCM（带完整性认证，密文含 16 字节认证标签）
 *
 * 使用方式（浏览器）：页面加载本文件后通过 window.CryptoCore 调用
 * 使用方式（Node）  ：const CryptoCore = require('./crypto-core.js')
 * 自解密文件       ：本文件源码会原文内嵌进自解密 HTML，保证两端逻辑完全一致
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.CryptoCore = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var PBKDF2_ITERATIONS = 310000;
  var VERSION = 1;

  /* ---------- 基础工具 ---------- */

  var B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  function utf8Encode(str) {
    return new TextEncoder().encode(str);
  }

  function utf8Decode(bytes) {
    return new TextDecoder('utf-8').decode(bytes);
  }

  // 字节 -> base64（兼容浏览器 / Node / Cloudflare Worker）
  function bytesToB64(bytes) {
    var u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (typeof btoa === 'function') {
      var CHUNK = 0x8000;
      var bin = '';
      for (var i = 0; i < u8.length; i += CHUNK) {
        bin += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
      }
      return btoa(bin);
    }
    // 纯 JS 兜底（Worker 环境无 btoa / Buffer）
    var out = '';
    for (var j = 0; j < u8.length; j += 3) {
      var b0 = u8[j];
      var b1 = j + 1 < u8.length ? u8[j + 1] : -1;
      var b2 = j + 2 < u8.length ? u8[j + 2] : -1;
      out += B64_CHARS[b0 >> 2];
      out += B64_CHARS[((b0 & 3) << 4) | (b1 < 0 ? 0 : b1 >> 4)];
      if (b1 < 0) { out += '=='; break; }
      out += B64_CHARS[((b1 & 15) << 2) | (b2 < 0 ? 0 : b2 >> 6)];
      if (b2 < 0) { out += '='; break; }
      out += B64_CHARS[b2 & 63];
    }
    return out;
  }

  // base64 -> 字节
  function b64ToBytes(b64) {
    if (typeof atob === 'function') {
      var bin = atob(b64);
      var out = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    // 纯 JS 兜底
    var clean = b64.replace(/=+$/, '');
    var res = new Uint8Array(Math.floor((clean.length * 3) / 4));
    var o = 0;
    var buf = 0;
    var bits = 0;
    for (var k = 0; k < clean.length; k++) {
      var c = B64_CHARS.indexOf(clean[k]);
      if (c < 0) continue;
      buf = (buf << 6) | c;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        res[o++] = (buf >> bits) & 0xff;
      }
    }
    return res;
  }

  function randomBytes(n) {
    var out = new Uint8Array(n);
    var MAX_CHUNK = 65536; // getRandomValues 单次上限
    for (var i = 0; i < n; i += MAX_CHUNK) {
      var chunk = new Uint8Array(Math.min(MAX_CHUNK, n - i));
      crypto.getRandomValues(chunk);
      out.set(chunk, i);
    }
    return out;
  }

  // 生成指定长度的随机 base64 字符串（用于销毁时覆盖内存密文）
  function randomBase64(len) {
    var bytes = randomBytes(Math.ceil((len * 3) / 4));
    var b64 = bytesToB64(bytes);
    return b64.slice(0, len);
  }

  function b64urlSafe(s) {
    return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  /* ---------- 密钥派生 ---------- */

  // 由口令派生 AES-256-GCM 密钥
  function deriveKey(password, saltB64) {
    var salt = b64ToBytes(saltB64);
    return crypto.subtle
      .importKey('raw', utf8Encode(password), 'PBKDF2', false, ['deriveKey'])
      .then(function (baseKey) {
        return crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
          baseKey,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        );
      });
  }

  // 用于服务器下载校验的口令摘要：SHA-256(UTF-8 口令) 的 base64。
  // 服务器只存这个摘要，无法反推口令。真实解密仍走 PBKDF2 31 万次迭代
  //（在对方浏览器本地执行），因此离线破解密文成本不变；
  // 服务端仅用它做下载口令比对（免费 Worker CPU 限额内可快速完成）。
  // 注意：口令必须使用高强度密钥（随机乱码 / 随机汉字），自定义弱口令
  // 会同时削弱密文与摘要两者的抗暴力能力。
  function passwordDigest(password) {
    return crypto.subtle
      .digest('SHA-256', utf8Encode(password))
      .then(function (digest) {
        return bytesToB64(new Uint8Array(digest));
      });
  }

  /* ---------- 加密 / 解密 ---------- */

  // 加密任意字节数据，返回容器 JSON 字符串：
  // { v:1, salt, iv, data }，data 为 base64 密文（含 GCM 认证标签）
  // 明文内容（文字 / 文件名 / 类型 / 文件字节）全部加密，服务器不可见。
  function encryptBytes(password, dataBytes) {
    var salt = randomBytes(16);
    var iv = randomBytes(12);
    var saltB64 = bytesToB64(salt);
    return deriveKey(password, saltB64)
      .then(function (key) {
        return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, dataBytes);
      })
      .then(function (cipher) {
        return JSON.stringify({
          v: VERSION,
          salt: saltB64,
          iv: bytesToB64(iv),
          data: bytesToB64(new Uint8Array(cipher))
        });
      });
  }

  // 解密容器 JSON 字符串，返回明文 Uint8Array。
  // 口令错误 / 数据被篡改时抛出异常（GCM 认证失败）。
  function decryptBytes(password, containerJson) {
    var c;
    try {
      c = JSON.parse(containerJson);
    } catch (e) {
      return Promise.reject(new Error('container_invalid'));
    }
    if (!c || c.v !== VERSION || !c.salt || !c.iv || !c.data) {
      return Promise.reject(new Error('container_invalid'));
    }
    return deriveKey(password, c.salt).then(function (key) {
      return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(c.iv) }, key, b64ToBytes(c.data));
    }).then(function (plain) {
      return new Uint8Array(plain);
    });
  }

  /* ---------- 常用汉字表（约 1000 高频字，供随机汉字密钥使用） ---------- */
  var COMMON_CHARS =
    '的一是在不了有和人这中大为上个国我以要他时来用们生到作地于出就分对成会可主发年动同工也能下过子说产种面而方后多定行学法所民得经十三之进着等部度家电力里如水化高自二理起小物现实加量都两体制机当使点从业本去把性好应开它合还因由其些然前外天政四日那社义事平形相全表间样与关各重新线内数正心反你明看原又么利比或但质气第向道命此变条只没结解问意建月公无系军很情者最立代想已通并提直题党程展五果料象员革位入常文总次品式活设及管特件长求老头基资边流路级少图山统接知较将组见计别她手角期根论运农指几九区强放决西被干做必战先回则任取据处队南给色光门即保治北造百规热领七海口东导器压志世金增争济阶油思术极交受联什认六共权收证改清己美再采转更单风切打白教速花带安场身车例真务具万每目至达走积示议声报斗完类八离华名确才科张信马节话米整空元况今集温传土许步群广石记需段研界拉林律叫且究观越织装影算低持音众书布复容儿须际商非验连断深难近矿千周委素技备半办青省列习响约支般史感劳便团往酸历市克何除消构府称太准精值号率族维划选标写存候毛亲快效斯院查江型眼王按格养易置派层片始却专状育厂京识适属圆包火住调满县局照参红细引听该铁价严龙飞';

  /* ---------- 密钥生成 ---------- */

  // 随机乱码密钥（16 位，字符集约 74 个，熵约 99 bit）
  function generateRandomKey(len) {
    var alphabet =
      'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*()-_=+';
    var n = len || 16;
    var bytes = randomBytes(n);
    var out = '';
    for (var i = 0; i < n; i++) {
      out += alphabet[bytes[i] % alphabet.length];
    }
    return out;
  }

  // 随机汉字密钥（5 个常用字，熵约 50+ bit，中文用户输入友好）
  function generateChineseKey(count) {
    var n = count || 5;
    var bytes = randomBytes(n);
    var out = '';
    for (var i = 0; i < n; i++) {
      out += COMMON_CHARS[bytes[i] % COMMON_CHARS.length];
    }
    return out;
  }

  return {
    VERSION: VERSION,
    PBKDF2_ITERATIONS: PBKDF2_ITERATIONS,
    utf8Encode: utf8Encode,
    utf8Decode: utf8Decode,
    bytesToB64: bytesToB64,
    b64ToBytes: b64ToBytes,
    randomBytes: randomBytes,
    randomBase64: randomBase64,
    b64urlSafe: b64urlSafe,
    deriveKey: deriveKey,
    passwordDigest: passwordDigest,
    encryptBytes: encryptBytes,
    decryptBytes: decryptBytes,
    generateRandomKey: generateRandomKey,
    generateChineseKey: generateChineseKey,
    COMMON_CHARS: COMMON_CHARS
  };
});
