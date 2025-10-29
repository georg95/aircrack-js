let LOADED_HASHES = {}
let MODE = 'cpu'
let CUSTOM_PASSWORDS_LIST = []
let fileNames = new Set()

document.addEventListener('DOMContentLoaded', () => {
  window.pcap_files.onchange = async (e) => {
    if (e.target.files.length === 0) {
      return
    }
    let allEAPOLframes = []
    let allPMKIDframes = []
    let allBssidToEssid = {}
    await Promise.all(Array.from(e.target.files).filter(f => f.name.endsWith('.cap') || f.name.endsWith('.pcap')).map(async f => {
      const { error, eapolFrames, pmkidFrames, bssidToEssid } = await parsePcapFile(f)
      if (error) {
        fileNames.add(`${f.name}: ${error}`)
      } else {
        fileNames.add(f.name)
        allBssidToEssid = { ...allBssidToEssid, ...bssidToEssid }
        allEAPOLframes = allEAPOLframes.concat(eapolFrames)
        allPMKIDframes = allPMKIDframes.concat(pmkidFrames)
      }
    }))
    const handshakes = buildHandshakes({ eapolFrames: allEAPOLframes, bssidToEssid: allBssidToEssid })
    const pmkids = buildPMKID({ pmkidFrames: allPMKIDframes, bssidToEssid: allBssidToEssid })
    const hc22000Hashes = {}
    await Promise.all(Array.from(e.target.files).filter(f => f.name.endsWith('.hc22000')).map(async file => {
      return new Promise(resolve => {
        var reader = new FileReader()
        reader.onload = function() {
          const text = this.result
          const hc22000Lines = text.split('\n').filter(x => x)
          for (let hc22000line of hc22000Lines) {
            const essid = hexToString(hc22000line.split('*')[5])
            if (!essid) {
              fileNames.add(`${file.name}: Invalid hc22000 format`)
              resolve()
              return
            }
            hc22000Hashes[essid] = hc22000line
          }
          fileNames.add(file.name)
          resolve()
        }
        reader.readAsText(file)
      })
    }))
    setHashes({ ...handshakes, ...pmkids, ...hc22000Hashes })
    let resText = Object.keys(LOADED_HASHES).map(essid => {
      if (LOADED_HASHES[essid].split('*')[1] === '01') {
        return `* ${essid}: [PMKID]`
      }
      const eapolType = parseInt(LOADED_HASHES[essid].split('*')[8], 16) & 0x7
      return `* ${essid}: [EAPOL 0x${LOADED_HASHES[essid].split('*')[8]} - ${eapolType === 5 ? 'full' : 'partial'}]`
    }).join('\n')
    if (resText === '') {
      resText = 'No EAPOL/PMKID detected'
    }
    Array.from(e.target.files).filter(f => f.name.endsWith('.txt')).forEach(f => {
      if (CUSTOM_PASSWORDS_LIST.findIndex((f2) => f.name === f2.name) === -1) {
        CUSTOM_PASSWORDS_LIST.push(f)
      }
      fileNames.add(f.name)
    })
    window.pcap_files_view.innerText = Array.from(fileNames.keys()).join('\n') + '\n\n' + resText
  }

  async function setDevices() {
    window.select_device.innerHTML = ''
    window.select_device.onchange = (e) => {
      const deviceName = window.select_device.selectedOptions[0].name
      MODE = deviceName
      if (deviceName === 'gpu - not available') {
        log('Your browser not support WebGPU - use Chrome, enable flags:\nchrome://flags#force-high-performance-gpu\nchrome://flags#enable-unsafe-webgpu', true)
      } else if (deviceName === 'gpu - disabled') {
        log('In Chrome enable flags and restart:\nchrome://flags#force-high-performance-gpu\nchrome://flags#enable-unsafe-webgpu', true)
      } else {
        log('', true)
      }
    }
    const option = document.createElement('option')
    option.name = 'cpu'
    option.innerText = `CPU: ${navigator.hardwareConcurrency || 4} threads`
    window.select_device.appendChild(option)
    if (navigator.gpu) {
      MODE = 'gpu'
      const option = document.createElement('option')
      option.name = 'gpu'
      option.selected = true
      const adapter = await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' })
      option.innerText = `GPU: ${adapter.info.description || adapter.info.vendor}`
      window.select_device.appendChild(option)
      const optionFail = document.createElement('option')
      optionFail.name = 'gpu - disabled'
      optionFail.innerText = `I don't see my GPU`
      window.select_device.appendChild(optionFail)
    } else {
      const option = document.createElement('option')
      option.name = 'gpu - not available'
      option.innerText = `GPU (not available)`
      window.select_device.appendChild(option)
    }
  }
  setDevices()

  function setHashes(hashes) {
    LOADED_HASHES = { ...LOADED_HASHES, ...hashes }
    window.select_essid.innerHTML = ''
    for (let essid in LOADED_HASHES) {
      const option = document.createElement('option')
      option.name = essid
      option.innerText = essid
      window.select_essid.appendChild(option)
    }
    window.start_btn.style.display = Object.keys(LOADED_HASHES).length >= 1 ? 'block' : 'none'
    window.select_essid.style.display = Object.keys(LOADED_HASHES).length >= 2 ? 'block' : 'none'
  }

  const SPINNER = ['|', '/', '-', '\\']
  let spinner = 0
  window.start_btn.onclick = async () => {
    window.start_btn.style.display = 'none'
    window.stop_btn.style.display = 'block'
    const { stop, next } = await filePasswords_stream(CUSTOM_PASSWORDS_LIST.length > 0 ? CUSTOM_PASSWORDS_LIST : [
      { url: 'https://georg95.github.io/SecLists/Passwords/Default-Credentials/Routers/0ALL-USERNAMES-AND-PASSWORDS.txt', filePasswords: 75 },
      { url: 'https://georg95.github.io/SecLists/Passwords/Default-Credentials/default-passwords.txt', filePasswords: 439 },
      { url: 'https://georg95.github.io/SecLists/Passwords/Default-Credentials/cirt-net_collection.txt', filePasswords: 312 },
      { url: 'https://georg95.github.io/SecLists/Passwords/Software/john-the-ripper.txt', filePasswords: 466 },
      { url: 'https://georg95.github.io/SecLists/Passwords/Most-Popular-Letter-Passes.txt', filePasswords: 4221 },
      { url: 'https://georg95.github.io/SecLists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt', filePasswords: 4800 },
      { url: 'https://georg95.github.io/SecLists/Passwords/unkown-azul.txt', filePasswords: 1778 },
      { url: 'https://georg95.github.io/SecLists/Passwords/seasons.txt', filePasswords: 4453 },
      { url: 'https://georg95.github.io/SecLists/Passwords/days.txt', filePasswords: 5596 },
      { url: 'https://georg95.github.io/SecLists/Passwords/months.txt', filePasswords: 11923 },
      { url: 'https://georg95.github.io/SecLists/Passwords/Keyboard-Walks/Keyboard-Combinations.txt', filePasswords: 7748 },
      { url: 'https://georg95.github.io/SecLists/Passwords/Cracked-Hashes/milw0rm-dictionary.txt', filePasswords: 36279 },
      { url: 'https://georg95.github.io/SecLists/Passwords/Common-Credentials/1900-2020.txt', filePasswords: 45012 },
      { url: 'https://georg95.github.io/SecLists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt', filePasswords: 45578 },
      { url: 'https://duyet.github.io/bruteforce-database/8-more-passwords.txt', filePasswords: 61682 },
      { url: 'https://georg95.github.io/SecLists/Passwords/mssql-passwords-nansh0u-guardicore.txt', filePasswords: 84581 },
      { url: "https://georg95.github.io/SecLists/Passwords/Leaked-Databases/honeynet2.txt", filePasswords: 122461 },
      { url: "https://georg95.github.io/SecLists/Passwords/Leaked-Databases/Ashley-Madison.txt", filePasswords: 196641 },
      { url: 'https://georg95.github.io/SecLists/Passwords/Software/cain-and-abel.txt', filePasswords: 225382 },
      { url: 'https://georg95.github.io/SecLists/Passwords/Keyboard-Walks/walk-the-line.txt', filePasswords: 279552 },
      { url: "https://georg95.github.io/SecLists/Passwords/Leaked-Databases/000webhost.txt", filePasswords: 573432 },
      { url: 'https://georg95.github.io/SecLists/Passwords/Software/bt4-password.txt', filePasswords: 955419 },
      { url: 'https://georg95.github.io/SecLists/Passwords/darkc0de.txt', filePasswords: 993322 },
      { url: 'https://georg95.github.io/SecLists/Passwords/openwall.net-all.txt', filePasswords: 2791112 },
      { url: 'https://georg95.github.io/SecLists/Passwords/Common-Credentials/xato-net-10-million-passwords.txt', filePasswords: 3199716 },
      { url: "https://georg95.github.io/SecLists/Passwords/Leaked-Databases/alleged-gmail-passwords.txt", filePasswords: 2240098 },
      { url: "https://georg95.github.io/SecLists/Passwords/Leaked-Databases/md5decryptor-uk.txt", filePasswords: 2323805 },
      { url: 'https://georg95.github.io/SecLists/Passwords/Common-Credentials/Pwdb_top-10000000.txt', filePasswords: 6958317 },
      { url: "https://georg95.github.io/SecLists/Passwords/Wikipedia/wikipedia_en_vowels_no_compounds_top-1000000.txt", filePasswords: 519641 },
      { url: "https://georg95.github.io/SecLists/Passwords/Wikipedia/wikipedia_fr_vowels_no_compounds_top-1000000.txt", filePasswords: 539376 },
      { url: "https://georg95.github.io/SecLists/Passwords/Wikipedia/wikipedia_es_vowels_no_compounds_top-1000000.txt", filePasswords: 569873 },
      { url: "https://georg95.github.io/SecLists/Passwords/Wikipedia/wikipedia_pt_vowels_no_compounds_top-1000000.txt", filePasswords: 570191 },
      { url: "https://georg95.github.io/SecLists/Passwords/Common-Credentials/Language-Specific/German_common-password-list.txt", filePasswords: 1570576 },
      { url: "https://georg95.github.io/SecLists/Passwords/Common-Credentials/Language-Specific/Chinese-common-password-list.txt", filePasswords: 2647330 },
      { url: "https://georg95.github.io/SecLists/Passwords/Common-Credentials/Language-Specific/Spanish_common-usernames-and-passwords.txt", filePasswords: 395990 },
      { url: "https://georg95.github.io/SecLists/Passwords/Common-Credentials/Language-Specific/Dutch_common-pasword-list.txt", filePasswords: 3214818 },
    ])
    const hc22000line = LOADED_HASHES[window.select_essid.selectedOptions[0].name]
    window.stop_btn.onclick = stop
    let password = null
    if (MODE === 'gpu') {
      password = await bruteGPU(
        hc22000line,
        next,
        ({ gpuName, BATCH_SIZE, avgHashrate, file, progress }) =>
          log(`[GPU ${gpuName} x ${BATCH_SIZE}] ${SPINNER[(spinner++)%SPINNER.length]} ${(avgHashrate / 1000).toFixed(1)} kH/s\n${file} ${progress * 100 | 0}%`, true)
      )
    } else {
      password = await bruteCpu(
        hc22000line,
        () => next(500),
        ({ THREADS, avgHashrate, file, progress }) =>
          log(`[CPUx${THREADS}] ${SPINNER[(spinner++)%SPINNER.length]} ${(avgHashrate / 1000).toFixed(1)} kH/s\n${file} ${progress * 100 | 0}%`, true)
      )
    }
    window.stop_btn.style.display = 'none'
    window.start_btn.style.display = 'block'
    if (password) {
      log(`Found password: ${password}`, true)
    } else {
      log('Not found', true)
    }
  }
})

async function filePasswords_stream(files) {
  let curFile = 0
  let nextBatch = await getPasswords(files[curFile++])
  let currentOperation = Promise.resolve()
  
  async function next(batchSize) {
    assert(batchSize, 'specify batch size when stream passwords')
    // allow only sequential reading
    currentOperation = currentOperation.then(async () => {
      let passwords = await nextBatch(batchSize)
      if (!passwords && curFile < files.length) {
        nextBatch = await getPasswords(files[curFile++])
        return nextBatch(batchSize)
      }
      return passwords
    })
    return currentOperation
  }
  
  return {
    next,
    stop() { nextBatch = async () => null; curFile = files.length }
  }
}

async function getPasswords(file) {
  let reader = null
  if (file.url) {
    const resp = await fetch(file.url)
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
    reader = resp.body.getReader()
  } else {
    reader = file.stream().getReader()
  }
  
  let partialBuf = new Uint8Array(0)
  let partialBufIndex = 0
  let ended = false

  const MAX_PASSLEN = 64
  let used = 0, skipped = 0, readBytes = 0
  async function batch(passwordsCount) {
    if (ended) return null
    const buf32 = new Uint32Array(Math.ceil(passwordsCount * (MAX_PASSLEN + 4) / 4))
    const passwordsBuf = new Uint8Array(buf32.buffer, buf32.byteOffset, buf32.byteLength)

    var count = 0
    var curOffset = passwordsCount * 4
    while (count < passwordsCount) {
      const newLine = partialBuf.indexOf(10, partialBufIndex)
      if (partialBuf[newLine - 1] === 0x0D) { throw new Error('\\r detected') }
      if (newLine === -1) {
        const { done, value } = await reader.read()
        if (done) {
          ended = true
          const word = partialBuf.subarray(partialBufIndex)
          readBytes += word.length + 1
          if (word.length >= 8 && word.length < MAX_PASSLEN) {
            buf32[count++] = curOffset
            passwordsBuf.set(word, curOffset)
            passwordsBuf[curOffset + word.length] = 10
            used++
          } else { skipped++ }
          if (skipped > 0) { console.warn('Skipped passwords with < 8 characters:', skipped) }
          break
        }

        let newBuf = new Uint8Array(partialBuf.length - partialBufIndex + value.length)
        newBuf.set(partialBuf.subarray(partialBufIndex))
        newBuf.set(value, partialBuf.length - partialBufIndex)
        partialBuf = newBuf
        partialBufIndex = 0
        continue
      }
      const passlen = newLine - partialBufIndex
      readBytes += passlen + 1
      if (passlen >= 8 && passlen < MAX_PASSLEN) {
        buf32[count++] = curOffset
        passwordsBuf.set(partialBuf.subarray(partialBufIndex, newLine + 1), curOffset)
        curOffset += newLine + 1 - partialBufIndex
        used++
      } else { skipped++ }
      partialBufIndex = newLine + 1
    }

    return {
      name: file.url ? file.url.split('/').reverse()[0] : file.name,
      progress: file.filePasswords ?
        used / file.filePasswords :
        readBytes / file.size,
      buf: passwordsBuf,
      buf32,
      count
    }
  }

  return batch;
}