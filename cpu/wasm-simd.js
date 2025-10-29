async function pbkdf2_eapol_wasm({ authenticatorMIC, essidBuf, ptkBuf, eapolData, }) {
    const SHA1_WASM = await fetch('cpu/pbkdf2_eapol.wasm').then(r => r.arrayBuffer())
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

async function pbkdf2_pmkid_wasm({ pmkid, essidBuf, pmkNameBuf }) {
    const SHA1_WASM = await fetch('cpu/pbkdf2_eapol.wasm').then(r => r.arrayBuffer())
    const {instance: { exports: {
        SSID_BUF1: { value: SSID_BUF1 },
        SSID_BUF2: { value: SSID_BUF2 },
        PMK_NAME_BUF: { value: PMK_NAME_BUF },
        EXPECTED_PMKID: { value: EXPECTED_PMKID },
        password1: { value: password1 },
        password2: { value: password2 },
        pbkdf2_pmkid, memory: {buffer} } }} =
    await WebAssembly.instantiate(SHA1_WASM)
    new Uint32Array(buffer, SSID_BUF1, 16).set(essidBuf[0])
    new Uint32Array(buffer, SSID_BUF2, 16).set(essidBuf[1])
    new Uint32Array(buffer, PMK_NAME_BUF, 16).set(pmkNameBuf)
    new Uint32Array(buffer, EXPECTED_PMKID, 4).set(pmkid)

    const password1b = new Uint8Array(buffer, password1, 64);
    const password2b = new Uint8Array(buffer, password2, 64);

    return function hash(pass1, pass2) {
        password1b.set(pass1)
        password2b.set(pass2)
        return pbkdf2_pmkid(pass1.length, pass2.length)
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
    async function pbkdf2_pmkid_wasm(WASM_CODE, { pmkid, essidBuf, pmkNameBuf }) {
        const {instance: { exports: {
            SSID_BUF1: { value: SSID_BUF1 },
            SSID_BUF2: { value: SSID_BUF2 },
            PMK_NAME_BUF: { value: PMK_NAME_BUF },
            EXPECTED_PMKID: { value: EXPECTED_PMKID },
            password1: { value: password1 },
            password2: { value: password2 },
            pbkdf2_pmkid, memory: {buffer} } }} =
        await WebAssembly.instantiate(WASM_CODE)
        new Uint32Array(buffer, SSID_BUF1, 16).set(essidBuf[0])
        new Uint32Array(buffer, SSID_BUF2, 16).set(essidBuf[1])
        new Uint32Array(buffer, PMK_NAME_BUF, 16).set(pmkNameBuf)
        new Uint32Array(buffer, EXPECTED_PMKID, 4).set(pmkid)

        const password1b = new Uint8Array(buffer, password1, 64);
        const password2b = new Uint8Array(buffer, password2, 64);

        return function hash(pass1, pass2) {
            password1b.set(pass1)
            password2b.set(pass2)
            return pbkdf2_pmkid(pass1.length, pass2.length)
        }
    }
    let check_passwords = null
    const WORKER_NUM = ${id}
    self.onmessage = async function(e) {
        const { message, passwords, wasm, handshakeData } = e.data
        if (message === 'init') {
            if (handshakeData.version === 1) {
                check_passwords = await pbkdf2_pmkid_wasm(wasm, handshakeData)
                self.postMessage({ message: 'work', id: WORKER_NUM, hashrate: 0 })
            } else if (handshakeData.version === 2) {
                check_passwords = await pbkdf2_eapol_wasm(wasm, handshakeData)
                self.postMessage({ message: 'work', id: WORKER_NUM, hashrate: 0 })
            } else {
                console.error('unsupported handshakeData version', handshakeData.version)
            }
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
            const res = check_passwords(pass1, pass2)
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
        const wasm = await fetch('cpu/pbkdf2_eapol.wasm').then(r => r.arrayBuffer())
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



