document.addEventListener('DOMContentLoaded', () => {
  window.pcap_files.onchange = async (e) => {
    if (e.target.files.length === 0) {
      return
    }
    async function readPcap(file) {
      return new Promise(resolve => {
        var reader = new FileReader();
        reader.onload = function() {
          let resText = ''
          try {
            var res = pcapToHC22000(this.result)
            resText = Object.keys(res).map(essid => {
              const eapolType = parseInt(res[essid].split('*')[8], 16) & 0x7
              return `--- ${essid}: [EAPOL 0x${res[essid].split('*')[8]} - ${eapolType === 5 ? 'full' : 'partial'}]`
            }).join('\n')
            if (resText === '') {
              resText = 'No EAPOL/PMKID detected'
            }
          } catch(e) {
            resText = `Corrupted file: ${e.message}`
          }
          resolve(resText)
        }
        reader.readAsArrayBuffer(file);
      })
      
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
    var res = buildHandshakes({ eapolFrames: totalFrames, bssidToEssid: totalBssidToEssid })
    let resText = Object.keys(res).map(essid => {
      const eapolType = parseInt(res[essid].split('*')[8], 16) & 0x7
      return `* ${essid}: [EAPOL 0x${res[essid].split('*')[8]} - ${eapolType === 5 ? 'full' : 'partial'}]`
    }).join('\n')
    if (resText === '') {
      resText = 'No EAPOL/PMKID detected'
    }
    window.pcap_files_view.innerText = fileNames.join('\n') + '\n\n' + resText
  }
})