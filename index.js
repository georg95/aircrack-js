let LOADED_HASHES = {}

document.addEventListener('DOMContentLoaded', () => {
  window.pcap_files.onchange = async (e) => {
    if (e.target.files.length === 0) {
      return
    }
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
    let totalFrames = []
    let totalBssidToEssid = {}
    let fileNames = []
    await Promise.all(Array.from(e.target.files).map(async f => {
      const { error, eapolFrames, bssidToEssid } = await parsePcapFile(f)
      if (error) {
        fileNames.push(`${f.name}: ${error}`)
      } else {
        fileNames.push(f.name)
        totalBssidToEssid = { ...totalBssidToEssid, ...bssidToEssid }
        totalFrames = totalFrames.concat(eapolFrames)
      }
    }))
    setHashes(buildHandshakes({ eapolFrames: totalFrames, bssidToEssid: totalBssidToEssid }))
    let resText = Object.keys(LOADED_HASHES).map(essid => {
      const eapolType = parseInt(LOADED_HASHES[essid].split('*')[8], 16) & 0x7
      return `* ${essid}: [EAPOL 0x${LOADED_HASHES[essid].split('*')[8]} - ${eapolType === 5 ? 'full' : 'partial'}]`
    }).join('\n')
    if (resText === '') {
      resText = 'No EAPOL/PMKID detected'
    }
    window.pcap_files_view.innerText = fileNames.join('\n') + '\n\n' + resText
  }

  function setHashes(hashes) {
    LOADED_HASHES = hashes
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
    // const { stop, next } = numericPasswords8_stream(500)
    const { stop, next } = await filePasswords_stream([{ url: '8-more-passwords.txt', filePasswords: 61682 }], 500)
    window.stop_btn.onclick = stop
    const password = await bruteCpu(
      LOADED_HASHES[window.select_essid.selectedOptions[0].name],
      next,
      ({ THREADS, avgHashrate }) =>
        log(`[CPUx${THREADS}] ${(avgHashrate / 1000).toFixed(1)} kH/s ${SPINNER[(spinner++)%SPINNER.length]}`, true)
    )

    window.stop_btn.style.display = 'none'
    window.start_btn.style.display = 'block'
    if (password) {
      log(`Found password: ${password}`, true)
    } else {
      log('Not found', true)
    }
  }
})

async function filePasswords_stream(files, batchSize) {
  let curFile = 0
  let nextBatch = await getPasswords(files[curFile++])
  let currentOperation = Promise.resolve()
  
  async function next() {
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
    const resp = await fetch(`https://duyet.github.io/bruteforce-database/${file.url}`)
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
    reader = resp.body.getReader()
  } else {
    reader = file.stream().getReader()
  }
  
  let partialBuf = new Uint8Array(0)
  let partialBufIndex = 0
  let ended = false

  const MAX_PASSLEN = 25
  async function batch(passwordsCount) {
    if (ended) return null
    const buf32 = new Uint32Array(Math.ceil(passwordsCount * (MAX_PASSLEN + 4) / 4))
    const passwordsBuf = new Uint8Array(buf32.buffer, buf32.byteOffset, buf32.byteLength)

    var count = 0
    var curOffset = passwordsCount * 4
    while (count < passwordsCount) {
      const newLine = partialBuf.indexOf(10, partialBufIndex)
      if (newLine === -1 && !ended) {
        const { done, value } = await reader.read()
        if (done) {
          ended = true
          buf32[count++] = curOffset
          const word = partialBuf.subarray(partialBufIndex)
          passwordsBuf.set(word, curOffset)
          passwordsBuf[curOffset + word.length] = 10
          break
        }

        let newBuf = new Uint8Array(partialBuf.length - partialBufIndex + value.length)
        newBuf.set(partialBuf.subarray(partialBufIndex))
        newBuf.set(value, partialBuf.length - partialBufIndex)
        partialBuf = newBuf
        partialBufIndex = 0
        continue
      }
      buf32[count++] = curOffset
      passwordsBuf.set(partialBuf.subarray(partialBufIndex, newLine + 1), curOffset)
      curOffset += newLine + 1 - partialBufIndex
      partialBufIndex = newLine + 1
    }

    return {
      buf: passwordsBuf,
      buf32,
      count
    }
  }

  return batch;
}