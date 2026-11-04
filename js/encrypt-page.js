/*
 * encrypt-page.js —— 加密页逻辑
 *
 * 部署时只需修改 WORKER_BASE 为你的 Cloudflare Worker 地址。
 */
(function () {
  'use strict';

  /* ========== 部署配置：替换为你的 Worker 地址 ========== */
  var WORKER_BASE = 'https://crypto-box.mgjack13.workers.dev';
  /* ==================================================== */

  var MAX_FILE_BYTES = 10 * 1024 * 1024; // 10MB

  var mode = 'text';
  var selectedFile = null;

  var $ = function (id) { return document.getElementById(id); };

  var segType = $('segType');
  var panelText = $('panelText');
  var panelFile = $('panelFile');
  var txtInput = $('txtInput');
  var dropZone = $('dropZone');
  var fileInput = $('fileInput');
  var fileInfo = $('fileInfo');
  var fileName = $('fileName');
  var fileSize = $('fileSize');
  var btnClearFile = $('btnClearFile');

  /* ---------- 模式切换 ---------- */
  segType.addEventListener('click', function (e) {
    var btn = e.target.closest('.seg-btn');
    if (!btn) return;
    mode = btn.dataset.mode;
    segType.querySelectorAll('.seg-btn').forEach(function (b) { b.classList.remove('active'); });
    btn.classList.add('active');
    panelText.classList.toggle('hidden', mode !== 'text');
    panelFile.classList.toggle('hidden', mode !== 'file');
  });

  /* ---------- 文件选择 / 拖放 ---------- */
  dropZone.addEventListener('click', function () { fileInput.click(); });
  fileInput.addEventListener('change', function () {
    if (fileInput.files && fileInput.files[0]) setFile(fileInput.files[0]);
  });
  ['dragover', 'dragenter'].forEach(function (ev) {
    dropZone.addEventListener(ev, function (e) { e.preventDefault(); dropZone.classList.add('over'); });
  });
  ['dragleave', 'drop'].forEach(function (ev) {
    dropZone.addEventListener(ev, function (e) { e.preventDefault(); dropZone.classList.remove('over'); });
  });
  dropZone.addEventListener('drop', function (e) {
    var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) setFile(f);
  });
  btnClearFile.addEventListener('click', function () {
    selectedFile = null;
    fileInput.value = '';
    fileInfo.classList.add('hidden');
  });

  function setFile(f) {
    if (f.size > MAX_FILE_BYTES) {
      showStatus('error', '文件超过 10MB 上限，请压缩后再试。');
      return;
    }
    selectedFile = f;
    fileName.textContent = f.name;
    fileSize.textContent = formatSize(f.size);
    fileInfo.classList.remove('hidden');
  }

  function formatSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(2) + ' MB';
  }

  /* ---------- 密钥 ---------- */
  var keyInput = $('keyInput');
  var btnCopyKey = $('btnCopyKey');

  $('btnGenRandom').addEventListener('click', function () {
    keyInput.value = CryptoCore.generateRandomKey(16);
  });
  $('btnGenChinese').addEventListener('click', function () {
    keyInput.value = CryptoCore.generateChineseKey(5);
  });
  btnCopyKey.addEventListener('click', function () {
    copyText(keyInput.value, btnCopyKey);
  });

  /* ---------- 复制工具 ---------- */
  function copyText(text, btn) {
    if (!text) return;
    var done = function () {
      var old = btn.textContent;
      btn.textContent = '✓ 已复制';
      setTimeout(function () { btn.textContent = old; }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
    } else {
      fallbackCopy(text);
      done();
    }
  }
  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
  }

  /* ---------- 状态 ---------- */
  var statusBox = $('statusBox');
  function showStatus(kind, msg) {
    statusBox.className = 'status ' + kind;
    statusBox.textContent = msg;
    statusBox.classList.remove('hidden');
  }
  function hideStatus() { statusBox.classList.add('hidden'); }

  /* ---------- 加密并上传 ---------- */
  var btnEncrypt = $('btnEncrypt');

  btnEncrypt.addEventListener('click', async function () {
    hideStatus();
    var password = keyInput.value.trim();
    if (!password) {
      showStatus('error', '请先生成或输入解密密钥（步骤 2）。');
      return;
    }
    if (password.length < 4) {
      showStatus('error', '密钥太短（至少 4 个字符），容易被破解。');
      return;
    }

    // 组装明文负载
    var payload;
    if (mode === 'text') {
      var text = txtInput.value;
      if (!text.trim()) {
        showStatus('error', '请输入要加密的文字。');
        return;
      }
      payload = JSON.stringify({ kind: 'text', text: text });
    } else {
      if (!selectedFile) {
        showStatus('error', '请先选择要加密的图片或档案。');
        return;
      }
      var bytes = new Uint8Array(await selectedFile.arrayBuffer());
      payload = JSON.stringify({
        kind: 'file',
        name: selectedFile.name,
        mime: selectedFile.type || 'application/octet-stream',
        bytes: CryptoCore.bytesToB64(bytes)
      });
    }

    btnEncrypt.disabled = true;
    btnEncrypt.textContent = '加密中……';
    try {
      // 浏览器本地加密
      showStatus('info', '正在浏览器本地加密（AES-256-GCM）……');
      var payloadBytes = CryptoCore.utf8Encode(payload);
      var container = await CryptoCore.encryptBytes(password, payloadBytes);
      var keyHash = await CryptoCore.passwordDigest(password);

      // 上传密文（明文从未离开本机）
      showStatus('info', '加密完成，正在上传密文……');
      var resp = await fetch(WORKER_BASE + '/api/upload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ container: container, keyHash: keyHash })
      });
      var data = await resp.json();

      if (!resp.ok) {
        showStatus('error', '上传失败：' + (data.error || resp.status));
        return;
      }

      // 展示结果
      $('outUrl').value = WORKER_BASE + '/f/' + data.id;
      $('outKey').value = password;
      $('resultBox').classList.remove('hidden');
      showStatus('info', '链接已生成，请将「链接」与「密钥」分开发送给对方。');
    } catch (err) {
      console.error(err);
      showStatus('error', '操作失败：' + (err && err.message ? err.message : '未知错误'));
    } finally {
      btnEncrypt.disabled = false;
      btnEncrypt.textContent = '加密并生成链接';
    }
  });

  /* ---------- 结果复制 ---------- */
  $('btnCopyUrl').addEventListener('click', function () {
    copyText($('outUrl').value, $('btnCopyUrl'));
  });
  $('btnCopyOutKey').addEventListener('click', function () {
    copyText($('outKey').value, $('btnCopyOutKey'));
  });

  /* ---------- 初始化 ---------- */
  keyInput.focus();
})();
