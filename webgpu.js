async function webGPUinit({ BUF_SIZE }) {
    assert(window.isSecureContext, 'WebGPU disabled for http:// protocol, works only on https://')
    assert(navigator.gpu, 'Browser not support WebGPU')
    assert(BUF_SIZE, 'no BUF_SIZE passed')
    const adapter = await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' })
    const device = await adapter.requestDevice() 
    var closed = false
    device.lost.then(()=>{
        assert(closed, 'WebGPU logical device was lost.')
        console.log('Cleaned WebGPU device resources')
    })

    async function inferenceTest({ inp, shaders, count }) {
        assert(inp?.length <= BUF_SIZE / 4, `expected input size to be <= ${BUF_SIZE / 4}, got ${inp?.length}`)
        device.queue.writeBuffer(shaders[0].bufferIn, 0, inp)
        const commandEncoder = device.createCommandEncoder()
        const passEncoder = commandEncoder.beginComputePass()
        for (let { binding, pipeline, workPerWarp } of shaders) {
            passEncoder.setBindGroup(0, binding)
            passEncoder.setPipeline(pipeline)
            passEncoder.dispatchWorkgroups(Math.ceil(count / workPerWarp))
        }
        passEncoder.end()
        return await readGpuBuffer(shaders[shaders.length - 1].bufferOut, 0, 4096, commandEncoder)
    }
    async function readGpuBuffer(sourceBuffer, offset, values, commandEncoder) {
        if (!commandEncoder) {
            commandEncoder = device.createCommandEncoder();
        }  
        commandEncoder.copyBufferToBuffer(
            sourceBuffer,
            offset * 4,
            stagingBuffer,
            0,
            values * 4
        );
        device.queue.submit([commandEncoder.finish()]);
        await stagingBuffer.mapAsync(GPUMapMode.READ);
        const arrayBuffer = stagingBuffer.getMappedRange(0, values * 4);
        const result = new Uint32Array(arrayBuffer.slice(), 0, values)
        stagingBuffer.unmap();
        return result;
    }

    var buffers = {
        inp: device.createBuffer({
            size: BUF_SIZE,
            usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST | GPUBufferUsage.COPY_SRC,
        }),
        out: device.createBuffer({
            size: 1024 * 128 * 4,
            usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST | GPUBufferUsage.COPY_SRC,
        }),
    }

    const stagingBuffer = device.createBuffer({
        size: 1024 * 128 * 4,
        usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
    });

    function clean() {
        buffers.inp.destroy()
        buffers.out.destroy()
        stagingBuffer.destroy()
        closed = true
        device.destroy()
    }

    const bindGroupLayout = device.createBindGroupLayout({
        entries: [
            {
                binding: 0,
                visibility: GPUShaderStage.COMPUTE,
                buffer: { type: 'read-only-storage' }
            },
            {
                binding: 1,
                visibility: GPUShaderStage.COMPUTE,
                buffer: { type: 'storage' },
            }
        ],
    });
    const bindGroup1 = {
      binding: device.createBindGroup({
          layout: bindGroupLayout,
          entries: [{
              binding: 0,
              resource: { buffer: buffers.inp },
          }, {
              binding: 1,
              resource: { buffer: buffers.out },
          }],
      }),
      bufferIn: buffers.inp,
      bufferOut: buffers.out,
    }

    const bindGroup2 = {
      binding: device.createBindGroup({
          layout: bindGroupLayout,
          entries: [{
              binding: 0,
              resource: { buffer: buffers.out },
          }, {
              binding: 1,
              resource: { buffer: buffers.inp },
          }],
      }),
      bufferIn: buffers.out,
      bufferOut: buffers.inp,
    }

    let bindGroup = bindGroup1

    async function buildShader(code, entryPoint, workPerWarp, name) {
      const module = device.createShaderModule({ code })
      const shaderInfo = await module.getCompilationInfo()
      if (shaderInfo.messages?.length > 0) {
        console.error(shaderInfo.messages)
        log('Some error ocurred during shader compiling')
      }
  
      let pipeline
      try {
        pipeline = await device.createComputePipelineAsync({
          layout: device.createPipelineLayout({
            bindGroupLayouts: [bindGroupLayout],
          }),
          compute: { module, entryPoint},
        });
      } catch (e) {
        console.error(e)
        log(`Pipeline creation error: ${e.message}`)
      }
      return { name, ...bindGroup, pipeline, workPerWarp }
    }

    return {
        name: adapter.info.description || adapter.info.vendor,
        clean,
        inferenceTest,
        buildShader,
    }
}

// ====================================== helper methods

function log(text, clear=false) {
    if (clear) window.output.innerHTML = ''
    window.output.innerHTML += text + '\n'
}

function assert(cond, text) {
    if (!cond) {
        const err = new Error(text || 'unknown error')
        log(`❌ ${text || 'unknown error'}`)
        err.stack = err.stack.split('\n').filter(x => !x.includes('at assert')).join('\n')
        throw err
    }
}

function bufUint32LESwap(buf) {
    for (let i = 0; i + 3 < buf.length; i += 4) {
        const a = buf[i]
        const b = buf[i + 1]
        const c = buf[i + 2]
        const d = buf[i + 3]

        buf[i] = d
        buf[i + 1] = c
        buf[i + 2] = b
        buf[i + 3] = a
    }
}

function hmacSha1blocks(data) {
  let u32blocks = []
  let totalLen = 64 + data.length
  let offset = 0
  let block = new Uint32Array(16)
  let view = new Uint8Array(block.buffer)
  while (data.length - offset >= 64) {
    view.set(data.subarray(offset, offset + 64))
    bufUint32LESwap(view)
    u32blocks.push(block.slice())
    offset += 64
  }
  let remaining = data.length - offset
  let tmp = new Uint8Array(128)
  tmp.set(data.subarray(offset))
  tmp[remaining] = 0x80
  let totalBits = totalLen * 8
  let padLen = (remaining + 1 + 8 <= 64) ? 64 : 128
  tmp[padLen - 2] = (totalBits >>> 8) & 0xff
  tmp[padLen - 1] = (totalBits >>> 0) & 0xff
  for (let i = 0; i < padLen; i += 64) {
    view.set(tmp.subarray(i, i + 64))
    bufUint32LESwap(view)
    u32blocks.push(block.slice())
  }
  return u32blocks
}
function initSaltBuffer(ssid, blockNum) {
  var salt_buf = new Uint32Array(16)
  var s8 = new Uint8Array(salt_buf.buffer, salt_buf.byteOffset, salt_buf.byteLength)
  s8.set(new TextEncoder().encode(ssid))
  s8[ssid.length + 3] = blockNum
  s8[ssid.length + 4] = 0x80
  bufUint32LESwap(s8)
  salt_buf[15] = (68 + ssid.length) * 8
  return salt_buf
}
function hexToString(hex) {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
}
function hexToUint8Array(hexString) {
    const bytes = [];
    for (let i = 0; i < hexString.length; i += 2) {
        bytes.push(parseInt(hexString.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
}
function u32toWgsl(arr) {
    return `array<u32, ${arr.length}>(${Array.from(arr).map(x => '0x'+x.toString(16)).join(',')})`
}
function u32toWgsl2d(arr) {
    return `array<array<u32, ${arr[0].length}>, ${arr.length}>(${arr.map(u32toWgsl).join(',\n')})`
}
function arrayCmp(a, b) { for (let i = 0; i < a.length && i < b.length; i++) { if (a[i] < b[i]) return -1; if (a[i] > b[i]) return 1; } return 0; }

function parseHashcat22000(line) {
    const parts = line.split('*')
    assert(parts.length >= 8 && parts[0] === 'WPA' && (parts[1] === '02' || parts[1] === '01'), 'Invalid hashcat 22000 format')
    if (parts[1] === '01') {
        return {
            version: 1,
            pmkid: hexToUint8Array(parts[2]),
            APmac: hexToUint8Array(parts[3]),
            Clientmac: hexToUint8Array(parts[4]),
            ssid: hexToString(parts[5]),
        };
    }
    const eapolData = hexToUint8Array(parts[7])
    assert(eapolData[0] === 0x01 && eapolData[1] === 0x03, 'eapolData should start with 0x0103')
    const ANonce = hexToUint8Array(parts[6])
    const SNonce = eapolData.subarray(17, 49)
    const APmac = hexToUint8Array(parts[3])
    const Clientmac = hexToUint8Array(parts[4])
    const ptkBuf = new Uint8Array([
        ...new TextEncoder().encode("Pairwise key expansion"),
        0x00,
        ...(arrayCmp(APmac, Clientmac) < 0 ? new Uint8Array([...APmac, ...Clientmac]) : new Uint8Array([...Clientmac, ...APmac])),
        ...(arrayCmp(ANonce, SNonce) < 0 ? new Uint8Array([...ANonce, ...SNonce]) : new Uint8Array([...SNonce, ...ANonce])),
        0x00,
    ])
    eapolData.fill(0x00, 81, 81 + 16)
    const authMic = hexToUint8Array(parts[2])
    bufUint32LESwap(authMic)
    const authenticatorMIC = new Uint32Array(authMic.buffer, authMic.byteOffset, authMic.byteLength / 4)
    const ssid = hexToString(parts[5])
    return {
        version: 2,
        authenticatorMIC,
        essidBuf: [initSaltBuffer(ssid, 1), initSaltBuffer(ssid, 2)],
        ptkBuf: hmacSha1blocks(ptkBuf),
        eapolData: hmacSha1blocks(eapolData),
    };
}
