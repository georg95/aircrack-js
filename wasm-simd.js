async function pbkdf2_eapol_wasm({ authenticatorMIC, essidBuf, ptkBuf, eapolData, }) {
    const SHA1_WASM = await fetch('pbkdf2_eapol.wasm').then(r => r.arrayBuffer())
    const {instance: { exports: {
        SSID_BUF1: { value: SSID_BUF1 },
        SSID_BUF2: { value: SSID_BUF2 },
        PTK_HASHDATA: { value: PTK_HASHDATA },
        EAPOL_HASHDATA: { value: EAPOL_HASHDATA },
        EAPOL_HASHDATA_LEN: { value: EAPOL_HASHDATA_LEN },
        EXPECTED_MIC: { value: EXPECTED_MIC },
        password1: { value: password1 },
        password2: { value: password2 },
        pbkdf1_eapol, memory: {buffer} } }} =
    await WebAssembly.instantiate(SHA1_WASM)
    new Uint32Array(buffer, SSID_BUF1, 16).set(essidBuf[0])
    new Uint32Array(buffer, SSID_BUF2, 16).set(essidBuf[1])
    new Uint32Array(buffer, PTK_HASHDATA, 32).set(ptkBuf[0])
    new Uint32Array(buffer, PTK_HASHDATA, 32).set(ptkBuf[1], 16)
    const EAPOL_HASHDATA_BUF = new Uint32Array(buffer, EAPOL_HASHDATA, 64)
    for (var i = 0; i < eapolData.length; i++) {
        EAPOL_HASHDATA_BUF.set(eapolData[i], i * 16)
    }
    const eapol_data_len = new Uint32Array(buffer, EAPOL_HASHDATA_LEN, 1)
    eapol_data_len[0] = eapolData.length
    new Uint32Array(buffer, EXPECTED_MIC, 5).set(authenticatorMIC)

    const password1b = new Uint8Array(buffer, password1, 64);
    const password2b = new Uint8Array(buffer, password2, 64);

    return function hash(pass1, pass2) {
        password1b.set(pass1)
        password2b.set(pass2)
        return pbkdf1_eapol(pass1.length, pass2.length)
    }
}

async function startWasmWorker(wasm, handshakeData, requestWork, onEnd, id) {
    const workerCode = `
    async function pbkdf2_eapol_wasm(WASM_CODE, { authenticatorMIC, essidBuf, ptkBuf, eapolData, }) {
        const {instance: { exports: {
            SSID_BUF1: { value: SSID_BUF1 },
            SSID_BUF2: { value: SSID_BUF2 },
            PTK_HASHDATA: { value: PTK_HASHDATA },
            EAPOL_HASHDATA: { value: EAPOL_HASHDATA },
            EAPOL_HASHDATA_LEN: { value: EAPOL_HASHDATA_LEN },
            EXPECTED_MIC: { value: EXPECTED_MIC },
            password1: { value: password1 },
            password2: { value: password2 },
            pbkdf1_eapol, memory: {buffer} } }} =
        await WebAssembly.instantiate(WASM_CODE)
        new Uint32Array(buffer, SSID_BUF1, 16).set(essidBuf[0])
        new Uint32Array(buffer, SSID_BUF2, 16).set(essidBuf[1])
        new Uint32Array(buffer, PTK_HASHDATA, 32).set(ptkBuf[0])
        new Uint32Array(buffer, PTK_HASHDATA, 32).set(ptkBuf[1], 16)
        const EAPOL_HASHDATA_BUF = new Uint32Array(buffer, EAPOL_HASHDATA, 64)
        for (var i = 0; i < eapolData.length; i++) {
            EAPOL_HASHDATA_BUF.set(eapolData[i], i * 16)
        }
        const eapol_data_len = new Uint32Array(buffer, EAPOL_HASHDATA_LEN, 1)
        eapol_data_len[0] = eapolData.length
        new Uint32Array(buffer, EXPECTED_MIC, 5).set(authenticatorMIC)

        const password1b = new Uint8Array(buffer, password1, 64);
        const password2b = new Uint8Array(buffer, password2, 64);

        return function hash(pass1, pass2) {
            password1b.set(pass1)
            password2b.set(pass2)
            return pbkdf1_eapol(pass1.length, pass2.length)
        }
    }
    let pbkdf2_eapol = null
    const WORKER_NUM = ${id}
    self.onmessage = async function(e) {
        const { message, passwords, wasm, handshakeData } = e.data
        if (message === 'init') {
            pbkdf2_eapol = await pbkdf2_eapol_wasm(wasm, handshakeData)
            self.postMessage({ message: 'work', id: WORKER_NUM, hashrate: 0 })
        }
        if (message === 'work') {
            brute(passwords)
        }
    }
    let INDEX = 0
    async function brute({ buf, count }) {
        const start = performance.now()
        const offsets = new Uint32Array(buf.buffer, buf.byteOffset, count)
        for (var i = 0; i < count; i+=2) {
            const pass1 = buf.subarray(offsets[i], buf.indexOf(10, offsets[i]))
            const pass2 = i+1 >= count ? pass1 : buf.subarray(offsets[i + 1], buf.indexOf(10, offsets[i + 1]))
            const res = pbkdf2_eapol(pass1, pass2)
            if (res !== -1) {
                self.postMessage({ message: 'found', id: WORKER_NUM, password: new TextDecoder().decode(res === 0 ? pass1 : pass2) })
                return
            }
        }
        self.postMessage({ message: 'work', id: WORKER_NUM, hashrate: count / (performance.now() - start) * 1000 | 0 })
    }
    `;
    const blob = new Blob([workerCode], { type: "application/javascript" })
    const worker = new Worker(URL.createObjectURL(blob))

    async function sendNewWork(data) {
        const passwords = await currentChunk
        if (!passwords) { onEnd(null); return }
        worker.postMessage({ message: 'work', passwords })
        currentChunk = requestWork(data)
    }
    worker.onmessage = async ({ data }) => {
        if (data.message === 'work') {
            sendNewWork(data);
        }
        if (data.message === 'found') {
            onEnd(data);
        }
    };
    worker.postMessage({ message: 'init', wasm, handshakeData })
    let currentChunk = requestWork({ hashrate: 0, id })
}

async function bruteCpu(hc22000line, passwordStream, progress, THREADS=navigator.hardwareConcurrency || 4) {
    let avgHashrate = 0
    let curFile = ''
    let curProgress = 0
    const update = setInterval(() => progress({ THREADS, file: curFile, progress: curProgress, avgHashrate }), 200)
    const password = await new Promise(async (resolve, reject) => { try {
        const handshakeData = parseHashcat22000(hc22000line)
        const wasm = await fetch('pbkdf2_eapol.wasm').then(r => r.arrayBuffer())
        let running = THREADS
        let ended = false
        function onEnd(res) {
            if (res) { ended = true; resolve(res.password) }
            if (--running === 0) { ended = true; resolve(null) }
        }
        const lastHashrates = Array(THREADS)
        async function requestWork({ hashrate, id }) {
            if (ended) { return null }
            lastHashrates[id] = hashrate;
            avgHashrate = lastHashrates.reduce((a, b) => a+b, 0)
            const chunk = await passwordStream()
            curFile = chunk?.name || curFile
            curProgress = chunk?.progress || curProgress
            return chunk
        }
        for (var i = 0; i < THREADS; i++) {
            startWasmWorker(wasm, handshakeData, requestWork, onEnd, i)
        }} catch(e) { reject(e) }
    }).catch(err => console.error(err))
    clearInterval(update)
    return password
}

function numericPasswords(startFrom, count, characters=8) {    
    let curPassword = new TextEncoder().encode(startFrom.toString(10).padStart(characters, '0') + '\n')
    const passLen = curPassword.length
    const passwordsBuf = new Uint8Array(count * (4 + passLen))
    const offsets = new Uint32Array(passwordsBuf.buffer, passwordsBuf.byteOffset, Math.ceil(passwordsBuf.length / 4))
    let curOffset = count * 4
    for (var i = 0; i < count; i++) {
        offsets[i] = curOffset
        passwordsBuf.set(curPassword, curOffset)
        var j = passLen - 2
        while (j >= 0 && curPassword[j] === 57) {
            curPassword[j] = 48
            j--
        }
        if (j < 0) { // reached 99_999_999, loop over
            curOffset += passLen
            continue
        }
        curPassword[j]++
        curOffset += passLen
    }
    return { buf: passwordsBuf, buf32: offsets, count }
}
function numericPasswords8_stream(from=0, to=100_000_000) {
    var CUR_OFFSET = from
    return {
        async next(BATCH_SIZE) {
            assert(BATCH_SIZE, 'specify batch size when stream passwords')
            if (CUR_OFFSET >= to) { return null }
            return numericPasswords((CUR_OFFSET += BATCH_SIZE) - BATCH_SIZE, BATCH_SIZE, 8)
        },
        stop() { CUR_OFFSET = to },
    }
}

function log(text, clear=false) {
    if (clear) window.output.innerHTML = ''
    window.output.innerHTML += text + '\n'
}

function assert(cond, text) {
    if (!cond) {
        const err = new Error(text || 'unknown error')
        window.errlog.innerHTML += `❌ ${text || 'unknown error'}\n`
        err.stack = err.stack.split('\n').filter(x => !x.includes('at assert')).join('\n')
        throw err
    }
}

function bufUint32LESwap(buf) {
    for (let i = 0; i + 3 < buf.length; i += 4) {
        const a = buf[i]
        const b = buf[i + 1]
        const c = buf[i + 2]
        const d = buf[i + 3]

        buf[i] = d
        buf[i + 1] = c
        buf[i + 2] = b
        buf[i + 3] = a
    }
}

function hmacSha1blocks(data) {
  let u32blocks = []
  let totalLen = 64 + data.length
  let offset = 0
  let block = new Uint32Array(16)
  let view = new Uint8Array(block.buffer)
  while (data.length - offset >= 64) {
    view.set(data.subarray(offset, offset + 64))
    bufUint32LESwap(view)
    u32blocks.push(block.slice())
    offset += 64
  }
  let remaining = data.length - offset
  let tmp = new Uint8Array(128)
  tmp.set(data.subarray(offset))
  tmp[remaining] = 0x80
  let totalBits = totalLen * 8
  let padLen = (remaining + 1 + 8 <= 64) ? 64 : 128
  tmp[padLen - 2] = (totalBits >>> 8) & 0xff
  tmp[padLen - 1] = (totalBits >>> 0) & 0xff
  for (let i = 0; i < padLen; i += 64) {
    view.set(tmp.subarray(i, i + 64))
    bufUint32LESwap(view)
    u32blocks.push(block.slice())
  }
  return u32blocks
}
function initSaltBuffer(ssid, blockNum) {
  var salt_buf = new Uint32Array(16)
  var s8 = new Uint8Array(salt_buf.buffer, salt_buf.byteOffset, salt_buf.byteLength)
  s8.set(new TextEncoder().encode(ssid))
  s8[ssid.length + 3] = blockNum
  s8[ssid.length + 4] = 0x80
  bufUint32LESwap(s8)
  salt_buf[15] = (68 + ssid.length) * 8
  return salt_buf
}
function hexToString(hex) {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
}
function hexToUint8Array(hexString) {
    const bytes = [];
    for (let i = 0; i < hexString.length; i += 2) {
        bytes.push(parseInt(hexString.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
}

function arrayCmp(a, b) { for (let i = 0; i < a.length && i < b.length; i++) { if (a[i] < b[i]) return -1; if (a[i] > b[i]) return 1; } return 0; }

function parseHashcat22000(line) {
    const parts = line.split('*')
    assert(parts.length >= 8 && parts[0] === 'WPA' && (parts[1] === '02' || parts[1] === '01'), 'Invalid hashcat 22000 format')
    if (parts[1] === '01') {
        return {
            version: 1,
            pmkid: hexToUint8Array(parts[2]),
            APmac: hexToUint8Array(parts[3]),
            Clientmac: hexToUint8Array(parts[4]),
            ssid: hexToString(parts[5]),
        };
    }
    const eapolData = hexToUint8Array(parts[7])

    assert((eapolData[6] & 0x07) !== 0x01, 'md5 not supported')
    assert(eapolData[0] === 0x01 && eapolData[1] === 0x03, 'eapolData should start with 0x0103')
    const ANonce = hexToUint8Array(parts[6])
    const SNonce = eapolData.subarray(17, 49)
    const APmac = hexToUint8Array(parts[3])
    const Clientmac = hexToUint8Array(parts[4])
    const ptkBuf = new Uint8Array([
        ...new TextEncoder().encode("Pairwise key expansion"),
        0x00,
        ...(arrayCmp(APmac, Clientmac) < 0 ? new Uint8Array([...APmac, ...Clientmac]) : new Uint8Array([...Clientmac, ...APmac])),
        ...(arrayCmp(ANonce, SNonce) < 0 ? new Uint8Array([...ANonce, ...SNonce]) : new Uint8Array([...SNonce, ...ANonce])),
        0x00,
    ])
    eapolData.fill(0x00, 81, 81 + 16)
    const authMic = hexToUint8Array(parts[2])
    bufUint32LESwap(authMic)
    const authenticatorMIC = new Uint32Array(authMic.buffer, authMic.byteOffset, authMic.byteLength / 4)
    const ssid = hexToString(parts[5])
    return {
        version: 2,
        authenticatorMIC,
        essidBuf: [initSaltBuffer(ssid, 1), initSaltBuffer(ssid, 2)],
        ptkBuf: hmacSha1blocks(ptkBuf),
        eapolData: hmacSha1blocks(eapolData),
    };
}

