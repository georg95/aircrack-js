const crypto = require('crypto');

function customPRF512(key, A, B) {
    const blen = 64;
    let i = 0;
    let R = Buffer.alloc(0);
    
    while (i <= ((blen * 8 + 159) / 160)) {
        const hmac = crypto.createHmac('sha1', key);
        hmac.update(A);
        hmac.update(Buffer.from([0x00]));
        hmac.update(B);
        hmac.update(Buffer.from([i]));
        R = Buffer.concat([R, hmac.digest()]);
        i += 1;
    }
    return R.slice(0, blen);
}

function checkWPAPassword(handshakeData, password) {
    const {
        ssid,
        APmac,
        Clientmac,
        ANonce,
        SNonce,
        authenticatorMIC,
        eapolData
    } = handshakeData;
    const A = "Pairwise key expansion"
  
    const macCompare = Buffer.compare(APmac, Clientmac)
    const nonceCompare = Buffer.compare(ANonce, SNonce)
    
    const minMac = macCompare < 0 ? APmac : Clientmac
    const maxMac = macCompare < 0 ? Clientmac : APmac
    const minNonce = nonceCompare < 0 ? ANonce : SNonce
    const maxNonce = nonceCompare < 0 ? SNonce : ANonce
    
    const B = Buffer.concat([minMac, maxMac, minNonce, maxNonce])
    const pmk = crypto.pbkdf2Sync(password, ssid, 4096, 32, 'sha1')
    console.log('pmk:', pmk.toString('hex'))
    const ptk = customPRF512(pmk, Buffer.from(A), B)
    console.log('ptk:', ptk.toString('hex'))
    const hmac = crypto.createHmac('sha1', ptk.slice(0, 16))
    hmac.update(eapolData)
    const calculatedMIC = hmac.digest('hex').slice(0, 32)
    return calculatedMIC === authenticatorMIC.toString('hex')
}

function hexToBuffer(hexString) {
    return Buffer.from(hexString.replace(/:/g, ''), 'hex')
}

function parseHashcat22000(line) {
    const parts = line.split('*')
    
    if (parts.length < 8 || parts[0] !== 'WPA' || parts[1] !== '02') {
        throw new Error('Invalid hashcat 22000 format');
    }
    
    const messagePairParts = parts.slice(6, parts.length - 1);
    
    return {
        format: `${parts[0]}*${parts[1]}`,
        pmkid: parts[2],
        macAp: parts[3],
        macClient: parts[4],
        essid: hexToString(parts[5]),
        essidHex: parts[5],
        messagePair: messagePairParts.join('*'),
        keyVersion: parts[parts.length - 1]
    };
}

function hexToString(hex) {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
}

function test() {
    const hashLine = 'WPA*02*d5355382b8a9b806dcaf99cdaf564eb6*00146c7e4080*001346fe320c*4861726b6f6e656e*225854b0444de3af06d1492b852984f04cf6274c0e3218b8681756864db7a055*0103007502010a0010000000000000000159168bc3a5df18d71efb6423f340088dab9e1ba2bbc58659e07b3764b0de8570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020100*02';
    const parsed = parseHashcat22000(hashLine)
    console.log('parsed:', parsed)
    const handshakeData = {
        ssid: "Harkonen",
        APmac: hexToBuffer("00146c7e4080"),
        Clientmac: hexToBuffer("001346fe320c"),
        ANonce: hexToBuffer("225854b0444de3af06d1492b852984f04cf6274c0e3218b8681756864db7a055"),
        SNonce: hexToBuffer("59168bc3a5df18d71efb6423f340088dab9e1ba2bbc58659e07b3764b0de8570"),
        authenticatorMIC: hexToBuffer("d5355382b8a9b806dcaf99cdaf564eb6"),
        eapolData: hexToBuffer("0103007502010a0010000000000000000159168bc3a5df18d71efb6423f340088dab9e1ba2bbc58659e07b3764b0de8570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020100")
    };
    console.log('handshakeData:', handshakeData)
    console.log(checkWPAPassword(handshakeData, "12345678") ? 'MATCH!' : 'no match')
}

test()