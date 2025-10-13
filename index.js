const crypto = require('crypto')

function customPRF512(key, X) {
    let R = Buffer.alloc(0) 
    for (let i = 0; i < 4; i++) {
        X[X.length - 1] = i
        R = Buffer.concat([R, crypto.createHmac('sha1', key).update(X).digest()])
    }
    return R.subarray(0, 64)
}

function checkWPA2Password({ ssid, APmac, Clientmac, ANonce, SNonce, authenticatorMIC, eapolData }, password) {
    const pmk = crypto.pbkdf2Sync(password, ssid, 4096, 32, 'sha1')
    const ptk = customPRF512(pmk, Buffer.concat([
        Buffer.from("Pairwise key expansion"),
        Buffer.from([0x00]),
        Buffer.compare(APmac, Clientmac) < 0 ? Buffer.concat([APmac, Clientmac]) : Buffer.concat([Clientmac, APmac]),
        Buffer.compare(ANonce, SNonce) < 0 ? Buffer.concat([ANonce, SNonce]) : Buffer.concat([SNonce, ANonce]),
        Buffer.from([0x00]),
    ]))
    let micAlg = eapolData.length >= 7 && ((eapolData.readUInt16BE(5) & 0x07) === 1) ? 'md5' : 'sha1'
    eapolData.fill(0x00, 81, 81 + 16)
    const hmac = crypto.createHmac(micAlg, ptk.subarray(0, 16)).update(eapolData).digest()
    const computedMic = (micAlg === 'sha1') ? hmac.subarray(0, 16) : hmac
    return Buffer.compare(computedMic, authenticatorMIC) === 0
}
function checkWPAPassword({ ssid, APmac, Clientmac, pmkid }, password) {
    const pmk = crypto.pbkdf2Sync(password, ssid, 4096, 32, 'sha1')
    const hmac = crypto.createHmac('sha1', pmk)
    hmac.update(Buffer.concat([Buffer.from('PMK Name'), APmac, Clientmac]))
    return Buffer.compare(hmac.digest().subarray(0, 16), pmkid) === 0
} 

function parseHashcat22000(line) {
    const parts = line.split('*')
    assert(parts.length >= 8 && parts[0] === 'WPA' && (parts[1] === '02' || parts[1] === '01'), 'Invalid hashcat 22000 format')
    if (parts[1] === '01') {
        return {
            version: 1,
            pmkid: hexToBuffer(parts[2]),
            APmac: hexToBuffer(parts[3]),
            Clientmac: hexToBuffer(parts[4]),
            ssid: hexToString(parts[5]),
        };
    }
    const eapolData = hexToBuffer(parts[7])
    assert(eapolData[0] === 0x01 && eapolData[1] === 0x03, 'eapolData should start with 0x0103')
    return {
        version: 2,
        authenticatorMIC: hexToBuffer(parts[2]),
        APmac: hexToBuffer(parts[3]),
        Clientmac: hexToBuffer(parts[4]),
        ssid: hexToString(parts[5]),
        ANonce: hexToBuffer(parts[6]),
        eapolData,
        SNonce: eapolData.subarray(17, 49)
    };
}

function hexToBuffer(hexString) { return Buffer.from(hexString.replace(/:/g, ''), 'hex') }
function hexToString(hex) {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
}
function assert(cond, text) {
    if (!cond) {
        const err = new Error(text || 'unknown error')
        console.error(`❌ ${text || 'unknown error'}`)
        err.stack = err.stack.split('\n').filter(x => !x.includes('at assert')).join('\n')
        throw err
    }
}

function test(hc22000, password) {
    const handshakeData = parseHashcat22000(hc22000)
    // console.log('handshakeData:', handshakeData)
    let checked = false
    if (handshakeData.version === 2) {
        checked = checkWPA2Password(handshakeData, password)
    } else if (handshakeData.version === 1) {
        checked = checkWPAPassword(handshakeData, password)
    } else {
        console.log('❌', hc22000.slice(0, 32)+'...', 'invalid version:', handshakeData.version)
        return 
    }
    if (checked) {
        console.log('✅', hc22000.slice(0, 32)+'...', '==', password)
    } else {
        console.log('❌', hc22000.slice(0, 32)+'...', '!=', password)
    }
}
test('WPA*02*d5355382b8a9b806dcaf99cdaf564eb6*00146c7e4080*001346fe320c*4861726b6f6e656e*225854b0444de3af06d1492b852984f04cf6274c0e3218b8681756864db7a055*0103007502010a0010000000000000000159168bc3a5df18d71efb6423f340088dab9e1ba2bbc58659e07b3764b0de8570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020100*02',
    '12345678')
test('WPA*02*6baba51340c8a83e2081af3b4bb64da9*00212972a319*002100ab55a9*4d4f4d31*14312696ea57a1c3ea614f7cb68b1455c3009c59a76d349b9a0ffe0d166d6ac2*0103007502010a0000000000000000000f069a5c6e3d9ef06f21e87023d72b4e05a3bac5338ac28495fdb8ce8566957bcb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac020100000fac040100000fac020800*00',
    'MOM12345')
test('WPA*01*72189b473af24c5e4b90e69e7af2db5f*28107b94bb29*f0a2251dc881*6f676f676f***',
    '15211521')
test('WPA*02*cc303dcc8fb0b285257353480a52c563*000d93ebb08c*00095b91535d*74657374*54adc644966dc8423d44364a1de9ec22415522bd0555ee718f8a53b8d679470c*0103005ffe010900200000000000000001fe5f0c5b5423815f35fe606720bbb9466d8601a8b4493af4cf5a0317f38c83870000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*05', 
    'biscotte')