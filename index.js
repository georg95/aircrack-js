const crypto = require('crypto');

function customPRF512(key, X) {
    let R = Buffer.alloc(0) 
    for (let i = 0; i < 4; i++) {
        X[X.length - 1] = i
        R = Buffer.concat([R, crypto.createHmac('sha1', key).update(X).digest()])
    }
    return R.subarray(0, 64)
}

function checkWPAPassword({ ssid, APmac, Clientmac, ANonce, SNonce, authenticatorMIC, eapolData }, password) {
    const pmk = crypto.pbkdf2Sync(password, ssid, 4096, 32, 'sha1')
    const ptk = customPRF512(pmk, Buffer.concat([
        Buffer.from("Pairwise key expansion"),
        Buffer.from([0x00]),
        Buffer.compare(APmac, Clientmac) < 0 ? Buffer.concat([APmac, Clientmac]) : Buffer.concat([Clientmac, APmac]),
        Buffer.compare(ANonce, SNonce) < 0 ? Buffer.concat([ANonce, SNonce]) : Buffer.concat([SNonce, ANonce]),
        Buffer.from([0x00]),
    ]))
    const hmac = crypto.createHmac('sha1', ptk.subarray(0, 16)).update(eapolData)
    return  Buffer.compare(hmac.digest().subarray(0, 16), authenticatorMIC) === 0
}

function parseHashcat22000(line) {
    const parts = line.split('*')
    assert(parts.length >= 8 && parts[0] === 'WPA' && parts[1] === '02', 'Invalid hashcat 22000 format')
    assert(parts[parts.length - 1] === '02', 'Only WPA*02*...*02 version supported')

    const eapolData = hexToBuffer(parts[7])
    assert(eapolData[0] === 0x01 && eapolData[1] === 0x03, 'eapolData should start with 0x0103')
    return {
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

function test() {
    const hashLine = 'WPA*02*d5355382b8a9b806dcaf99cdaf564eb6*00146c7e4080*001346fe320c*4861726b6f6e656e*225854b0444de3af06d1492b852984f04cf6274c0e3218b8681756864db7a055*0103007502010a0010000000000000000159168bc3a5df18d71efb6423f340088dab9e1ba2bbc58659e07b3764b0de8570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020100*02';
    const handshakeData = parseHashcat22000(hashLine)
    console.log('handshakeData:', handshakeData)
    console.log(checkWPAPassword(handshakeData, "12345678") ? 'MATCH!' : 'no match')
}

test()