async function parsePcapFile(file) {
  return new Promise(resolve => {
    var reader = new FileReader();
    reader.onload = function() {
      try {
        resolve(parsePcap(this.result))
      } catch(e) {
        resolve({ error: e.message })
      }
    }
    reader.readAsArrayBuffer(file);
  })
}

function parsePcap(arrayBuffer) {
  const view = new DataView(arrayBuffer)
  assert(view.byteLength >= 24, '[PCAP] pcap too small')
  const rawMagic = view.getUint32(0, false)
  if (rawMagic === 0x0a0d0d0a) {
    return parsePcapng(arrayBuffer, view)
  }
  assert(rawMagic !== 0x0a0d0d0a, '[PCAP] pcapng detected — this parser expects classic pcap')
  let le = null
  if (rawMagic === 0xa1b2c3d4) le = false
  else if (rawMagic === 0xd4c3b2a1) le = true
  else if (rawMagic === 0xa1b23c4d) le = false
  else if (rawMagic === 0x4d3cb2a1) le = true
  assert(le !== null, '[PCAP] Unknown pcap magic: 0x' + rawMagic.toString(16))
  const getU32 = (offs) => view.getUint32(offs, le)
  const getU16 = (offs) => view.getUint16(offs, le)
  const versionMajor = getU16(4)
  const versionMinor = getU16(6)
  const network = getU32(20)
  assert(network === 105 || network === 127 || network === 119, `[PCAP] this is not wifi capture (network=${network})`)
  assert_weak(`${versionMajor}.${versionMinor}` === '2.4', `[PCAP] strange vesrion ${versionMajor}.${versionMinor}`)

  let off = 24
  const eapolFrames = []
  const pmkidFrames = []
  const bssidToEssid = {}
  while (off + 16 <= view.byteLength) {
    const ts = getU32(off)
    assert_weak(ts > 1000000000 && ts < 1800000000, `[PCAP] timestamp ${ts} is outside 2001-2027 window`)
    const incl_len = getU32(off + 8)
    off += 16
    if (off + incl_len > view.byteLength) break
    let pktData = new Uint8Array(arrayBuffer, off, incl_len)
    parse80211packet(pktData, { network, le, ts, eapolFrames, pmkidFrames, bssidToEssid })
    off += incl_len
  }
  assert_weak(off === view.byteLength, '[PCAP] file is cut in the middle of packet')
  eapolFrames.sort((a, b) => a.ts - b.ts)

  return { eapolFrames, pmkidFrames, bssidToEssid }
}

function parse80211packet(pktData, { network, le, ts, eapolFrames, pmkidFrames, bssidToEssid }) {
  let radiotapSize = 0
  if (network === 119) { radiotapSize = new DataView(pktData.buffer, pktData.byteOffset).getUint32(4, le) }
  if (network === 127) { radiotapSize = new DataView(pktData.buffer, pktData.byteOffset).getUint16(2, le) }
  assert(radiotapSize >= 0 && radiotapSize < pktData.length, `Invalid radiotap header size: ${radiotapSize.toString(16)}`)
  pktData = pktData.subarray(radiotapSize)
  const frameControl = pktData[0] | (pktData[1] << 8);
  const type = (frameControl >> 2) & 0b11;
  const subtype = (frameControl >> 4) & 0b1111;
  const hdrLen = calc80211HeaderLength(frameControl, type, subtype)
  const { bssid, sta, essid } = parseAddressesAndEssid(pktData, hdrLen, { type, subtype })
  if (essid) {
    bssidToEssid[bytesToHex(bssid)] = essid
  }
  const eapolData = parseEapolFrame(pktData, hdrLen)
  if (eapolData) {
    const pmkid = extractPMKID(pktData, eapolData.eapolOffset)
    if (pmkid) {
      pmkidFrames.push({ pmkid, ts, bssid: bytesToHex(bssid), sta: bytesToHex(sta), essid })
    }
    eapolFrames.push({...eapolData, ts, bssid: bytesToHex(bssid), sta: bytesToHex(sta), essid })
  }
}

function parsePcapng(arrayBuffer, view) {
  let offset = 0
  const len = view.byteLength
  let network = null
  let packetCount = 0

  const eapolFrames = []
  const pmkidFrames = []
  const bssidToEssid = {}
  while (offset + 8 <= len) {
    const blockType = view.getUint32(offset, true)
    const blockTotalLength = view.getUint32(offset + 4, true)
    if (blockTotalLength < 12 || offset + blockTotalLength > len) break

    switch (blockType) {
      case 0x00000001: {
        network = view.getUint16(offset + 8, true)
        break
      }
      case 0x00000006: {
        assert(network === 105 || network === 127 || network === 119, `[PCAP] this is not wifi capture (network=${network})`)
        const ts = (view.getUint32(offset + 12, true) * 0x100000000 + view.getUint32(offset + 16, true)) / 1_000_000
        assert_weak(ts > 1000000000 && ts < 1800000000, `[PCAP] timestamp ${ts} is outside 2001-2027 window`)
        const capturedLen = view.getUint32(offset + 20, true)
        const packetData = new Uint8Array(arrayBuffer, offset + 28, capturedLen)
        parse80211packet(packetData, { network, le: true, ts, eapolFrames, pmkidFrames, bssidToEssid })
        packetCount++
        break
      }
      case 0x00000003:
        console.warn('TODO Simple Packet Block parse - skipped')
        break
      default:
        break
    }
    offset += blockTotalLength;
  }
  return { eapolFrames, pmkidFrames, bssidToEssid }
}

const ELEMID_VENDOR = 0xDD
const RSN_OUI = [0x00, 0x0f, 0xac]
function extractPMKID(buf, eapolOffset) {
  if (eapolOffset + 99 >= buf.length) return null;
  const keyInfo = buf[eapolOffset + 6];
  const keyDescriptorVersion = keyInfo & 7;
  if (((keyInfo & 0x08) === 0) || ((keyInfo & 0x40) !== 0) || ((keyInfo & 0x80) === 0)) {
    return null;
  }
  if ((buf[eapolOffset + 5] & 0x01) !== 0) return null;
  let p = eapolOffset + 99;
  while (p + 2 <= buf.length) {
    const el_id = buf[p];
    const el_len = buf[p + 1];
    if (p + 2 + el_len > buf.length) break;
    if (el_id === ELEMID_VENDOR) {
      let pos = p + 2;
      if (el_len >= 3 + 1 + 16) {
        if (buf[pos] === RSN_OUI[0] && buf[pos + 1] === RSN_OUI[1] && buf[pos + 2] === RSN_OUI[2]) {
          pos += 3;
          pos += 1;
          if (pos + 16 <= p + 2 + el_len) {
            const pmkid = buf.slice(pos, pos + 16);
            let allZero = true;
            for (let i = 0; i < 16; i++) {
              if (pmkid[i] !== 0) { allZero = false; break; }
            }
            if (!allZero && keyDescriptorVersion > 0) {
              return pmkid
            }
          }
        }
      }
    }
    p += 2 + el_len;
  }
  return null;
}

function calc80211HeaderLength(frameControl, type, subtype) {
  let hdrLen = 24;
  if (((frameControl >> 8) & 1) && ((frameControl >> 9) & 1)) hdrLen += 6;
  if (type === 2 && subtype >= 8 && subtype <= 15) hdrLen += 2;
  if ((frameControl >> 15) & 1) hdrLen += 4;
  return hdrLen;
}

function parseEapolFrame(buf, payloadOffset) {
  let eapolOffset = null
  if (payloadOffset >= buf.length) { return null }
  if (buf.length - payloadOffset >= 8 && buf.subarray(payloadOffset, payloadOffset + 8).every((x, i) => x === [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E][i])) {
    eapolOffset = payloadOffset + 8
  }
  if (buf.length - payloadOffset >= 2 && buf[payloadOffset] === 0x88 && buf[payloadOffset + 1] === 0x8E) {
    eapolOffset = payloadOffset
  }
  if (!eapolOffset) { return null }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  if (eapolOffset + 4 > buf.length) return console.warn("Truncated EAPOL header");
  const type = buf[eapolOffset + 1];
  const length = view.getUint16(eapolOffset + 2, false); // big endian
  if (type !== 3) return console.warn("Not EAPOL-Key");
  const keyDescType = buf[eapolOffset + 4];
  const keyVersion = buf[eapolOffset + 6] & 0x07
  if (keyVersion !== 2) { console.warn(`EAPOL keyVersion ${keyVersion} not supported`); return null }
  const keyInfo = view.getUint16(eapolOffset + 5, false); // big endian
  const keyLen = view.getUint16(eapolOffset + 7, false);
  const replayCounter = view.getBigUint64(eapolOffset + 9, false);
  const nonce = buf.slice(eapolOffset + 17, eapolOffset + 49);
  const mic = buf.slice(eapolOffset + 81, eapolOffset + 97);
  const micBit = (keyInfo >> 8) & 1;
  const ackBit = (keyInfo >> 7) & 1;
  const installBit = (keyInfo >> 6) & 1;
  const secureBit = (keyInfo >> 9) & 1;
  const keyDataLen = length - 95;
  let msgNum = "?";
  if (!micBit && ackBit) msgNum = 1;
  else if (micBit && !ackBit && !installBit && !secureBit && keyDataLen !== 0) msgNum = 2;
  else if (micBit && ackBit && installBit) msgNum = 3;
  else if (micBit && !ackBit && !installBit && keyDataLen === 0) msgNum = 4;
  return { msgNum, keyVersion, keyInfo, keyDescType, keyLen, replayCounter, nonce, mic, eapolOffset, eapolData: buf.subarray(eapolOffset, eapolOffset + length + 4) }
}

function parseAddressesAndEssid(buf, hdrLen, { type, subtype }) {
  let addr1 = buf.slice(4, 10), addr2 = buf.slice(10, 16), addr3 = buf.slice(16, 22), bssid = null, sta = null, essid = null;
  const toDS   = (buf[1] & 0x01) !== 0;
  const fromDS = (buf[1] & 0x02) !== 0;
  if (type === 2) {
    if (!toDS && !fromDS) { bssid = addr3; sta = addr2; }
    if (!toDS && fromDS) { bssid = addr2; sta = addr1; }
    if (toDS && !fromDS) { bssid = addr1; sta = addr2; }
  }
  if (type === 0 && [8, 5].includes(subtype)) {
    bssid = addr3
    const fixedParamsLen = 12
    const tagsOffset = hdrLen + fixedParamsLen
    let pos = tagsOffset
    while (pos + 2 <= buf.length) {
      const tagNum = buf[pos]
      const tagLen = buf[pos + 1]
      if (pos + 2 + tagLen > buf.length) break
      if (tagNum === 0) {
        essid = new TextDecoder().decode(buf.slice(pos + 2, pos + 2 + tagLen))
        break
      }
      pos += 2 + tagLen
    }
  }
  return { bssid, sta, essid };
}

// TODO check for messages retranslation
// 101 = M3+M4, EAPOL from M4 (authorized) - usable if NONCE_CLIENT is not zeroed
function findFullHandshake(frames) {
  let state = 1
  let msgs = []
  let lastTs = 0
  let result = null
  const sta = frames[0].sta
  for (let i = 0; i < frames.length; i++) {
    if (i > 0 && frames[i].ts - lastTs > 1) { state = 1; msgs = [] }
    if (frames[i].msgNum === 1 && state === 1) { msgs.push(frames[i]); state = 2 }
    if (frames[i].msgNum === 2 && state === 2) { msgs.push(frames[i]); state = 3 }
    if (frames[i].msgNum === 3 && state === 3) { msgs.push(frames[i]); state = 4 }
    if (frames[i].msgNum === 4 && state === 4 && !frames[i].nonce.every(x => x === 0)) {
      msgs.push(frames[i]);
      result = { sta, anonceBuf: msgs[2].nonce, micBuf: msgs[3].mic, eapolBuf: msgs[3].eapolData, messagePair: '05' };
      state = 1
      msgs = []
    }
    lastTs = frames[i].ts
  }
  return result
}
// 010 = M2+M3, EAPOL from M2 (authorized - ANONCE from M3)
function findPartialHandshakeM2M3(frames) {
  let state = 2
  let msgs = []
  let lastTs = 0
  let result = null
  const sta = frames[0].sta
  for (let i = 0; i < frames.length; i++) {
    if (i > 0 && frames[i].ts - lastTs > 1) { state = 2; msgs = [] }
    if (frames[i].msgNum === 2 && state === 2) { msgs.push(frames[i]); state = 3 }
    if (frames[i].msgNum === 3 && state === 3) {
      msgs.push(frames[i]);
      result = { sta, anonceBuf: msgs[1].nonce, micBuf: msgs[0].mic, eapolBuf: msgs[0].eapolData, messagePair: '02' };
      state = 2
      msgs = []
    }
    lastTs = frames[i].ts
  }
  return result
}
// 000 = M1+M2, EAPOL from M2 (challenge - ANONCE from M1)
function findPartialHandshakeM1M2(frames) {
  let state = 1
  let msgs = []
  let lastTs = 0
  let result = null
  const sta = frames[0].sta
  for (let i = 0; i < frames.length; i++) {
    if (i > 0 && frames[i].ts - lastTs > 1) { state = 1; msgs = [] }
    if (frames[i].msgNum === 1 && state === 1) { msgs.push(frames[i]); state = 2 }
    if (frames[i].msgNum === 2 && state === 2) {
      msgs.push(frames[i]);
      result = { sta, anonceBuf: msgs[0].nonce, micBuf: msgs[1].mic, eapolBuf: msgs[1].eapolData, messagePair: '00' }
      state = 1
      msgs = []
    }
    lastTs = frames[i].ts
  }
  return result
}

function bytesToHex(u8) {
  const out = [];
  for (let i = 0; i < u8.length; i++) out.push(u8[i].toString(16).padStart(2, '0'));
  return out.join('');
}
function stringToBytes(s) {
  return s.split('').map(x => x.charCodeAt(0).toString(16).padStart(2, '0')).join('')
}

if (typeof assert === 'undefined') {
  global.assert = function (cond, text) {
      if (!cond) {
          const err = new Error(text || 'unknown error')
          err.stack = err.stack.split('\n').filter(x => !x.includes('at assert')).join('\n')
          throw err
      }
  }
}

function assert_weak(cond, text) { if (!cond) { console.warn(text || 'unknown warning') } }

function buildHandshakes({ eapolFrames, bssidToEssid }) {
  const APs = {};
  for (const pkt of eapolFrames) {
    if (!APs[pkt.bssid]) { APs[pkt.bssid] = {} }
    if (!APs[pkt.bssid][pkt.sta]) { APs[pkt.bssid][pkt.sta] = [] }
    APs[pkt.bssid][pkt.sta].push(pkt)
  }
  const handshakesByEssid = {};
  for (const bssid in APs) {
    const essid = bssidToEssid[bssid]
    if (!essid) { console.warn(`Coud not find SSID for mac ${bssid.toUpperCase()}`); continue }
    const framesPack = Object.values(APs[bssid])
    let handshake = framesPack.map(findFullHandshake).find(x => x)
       || framesPack.map(findPartialHandshakeM2M3).find(x => x)
       || framesPack.map(findPartialHandshakeM1M2).find(x => x)
    if (!handshake) continue;
    handshake.eapolBuf.fill(0x00, 81, 81 + 16)
    handshakesByEssid[essid] = [
      'WPA', '02', bytesToHex(handshake.micBuf), bssid, handshake.sta,
      stringToBytes(essid), bytesToHex(handshake.anonceBuf),
      bytesToHex(handshake.eapolBuf), handshake.messagePair
    ].join('*')
  }
  return handshakesByEssid
}

function buildPMKID({ pmkidFrames, bssidToEssid }) {
  let pmkids = {}
  for (let { pmkid, essid, bssid, sta } of pmkidFrames) {
    essid = essid || bssidToEssid[bssid]
    if (!essid) { console.warn(`Coud not find SSID for mac ${bssid.toUpperCase()}`); continue }
    pmkids[essid] = ['WPA', '01', bytesToHex(pmkid), bssid, sta, stringToBytes(essid), '', '', ''].join('*')
  }
  return pmkids
}

if (typeof module === 'object') {
  module.exports = { buildHandshakes, buildPMKID, parsePcap }
}