[<img height="150" alt="image" src="https://github.com/user-attachments/assets/94f6b592-cb8d-4b91-80c1-955735ed5b88" />](https://georg95.github.io/aircrack-js/)

[App link](https://georg95.github.io/aircrack-js/)

This is aircrack-ng browser port with gpu support (via WebGPU).<br/>

It supports classic WPA/WPA2 dictionary attack with 4-way EAPOL handshake(full or partial) or PMKID.<br />
You need only network capture file(s): `.cap`, `.pcap`, `.pcapng` or parsed handshakes/PMKIDs: `.hc22000`.<br />
Passwords dictionaries built-in from SecLists repo.<br />
Or you can drop your own .txt password list<br />

Speed is on par with `aicrack-ng --simd=avx` and hashcat 22000-mode for gpu<br />
Check with [Benchmark](https://georg95.github.io/aircrack-js/benchmark.html)<br />

## How to enable discrete NVidia/AMD GPU

use Chrome(or any Chromium-based) browser, open `chrome://flags` and enable options (if present)<br />

force-high-performance-gpu<br />
enable-unsafe-webgpu<br />

Then restart
