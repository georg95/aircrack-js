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
    const { stop, next } = numericPasswords8_stream(500)
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
