async function webGPUinit({ BUF_SIZE, WORKGROUP_SIZE=64 }) {
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

    async function inference({ inp, count }) {
        assert(shader, 'run gpu.compile fisrt')
        assert(inp?.length <= BUF_SIZE / 4, `expected input size to be <= ${BUF_SIZE / 4}, got ${inp?.length}`)
        device.queue.writeBuffer(buffers.inp, 0, inp)
        const commandEncoder = device.createCommandEncoder()
        const passEncoder = commandEncoder.beginComputePass()
        passEncoder.setBindGroup(0, bindGroup)
        passEncoder.setPipeline(shader)
        passEncoder.dispatchWorkgroups(Math.ceil(count / WORKGROUP_SIZE))
        passEncoder.end()
        return await readGpuBuffer(buffers.out, 0, 4096, commandEncoder)
    }
    async function readGpuBuffer(sourceBuffer, offset, values, commandEncoder) {
        commandEncoder.copyBufferToBuffer(sourceBuffer, offset * 4, buffers.staging, 0, values * 4);
        device.queue.submit([commandEncoder.finish()]);
        await buffers.staging.mapAsync(GPUMapMode.READ);
        const arrayBuffer = buffers.staging.getMappedRange(0, values * 4);
        const result = new Uint32Array(arrayBuffer.slice(), 0, values)
        buffers.staging.unmap();
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
        staging: device.createBuffer({
            size: 1024 * 128 * 4,
            usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
        })
    }

    function clean() {
        buffers.inp.destroy()
        buffers.out.destroy()
        buffers.staging.destroy()
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
    const bindGroup = device.createBindGroup({
        layout: bindGroupLayout,
        entries: [{
            binding: 0,
            resource: { buffer: buffers.inp },
        }, {
            binding: 1,
            resource: { buffer: buffers.out },
        }],
    })
    let shader = null
    async function compile(handshakeData) {
        let pbkdf2Code = (await fetch('pbkdf2_eapol.wgsl').then(r => r.text()))
            .replaceAll('WORKGROUP_SIZE', WORKGROUP_SIZE)
            .replaceAll('ESSID_HASHDATA__', u32toWgsl2d(handshakeData.essidBuf))
            .replaceAll('PTK_HASHDATA__', u32toWgsl2d(handshakeData.ptkBuf))
            .replaceAll('PTK_HASHDATA_LEN', handshakeData.ptkBuf.length)
            .replaceAll('EAPOL_HASHDATA__', u32toWgsl2d(handshakeData.eapolData))
            .replaceAll('EAPOL_HASHDATA_LEN', handshakeData.eapolData.length)
            .replaceAll('AUTH_MIC__', u32toWgsl(handshakeData.authenticatorMIC))

        const module = device.createShaderModule({ code: pbkdf2Code })
        const shaderInfo = await module.getCompilationInfo()
        if (shaderInfo.messages?.length > 0) {
            console.error(shaderInfo.messages)
            log('Some error ocurred during shader compiling')
        }
        try {
            shader = await device.createComputePipelineAsync({
                layout: device.createPipelineLayout({
                    bindGroupLayouts: [bindGroupLayout],
                }),
                compute: { module, entryPoint: 'main' },
            });
        } catch (e) {
            console.error(e)
            log(`Pipeline creation error: ${e.message}`)
        }
    }

    return {
        name: adapter.info.description || adapter.info.vendor,
        compile,
        inference,
        clean,
    }
}

const MAX_BATCH_SIZE = 1024 * 256
async function bruteGPU(hc22000line, passwordStream, progress) {
    let curFile = 'compiling...', curProgress = 0, avgHashrate = 0, password = null, gpuName = ''
    const update = setInterval(() => progress({ gpuName, file: curFile, progress: curProgress, avgHashrate }), 200)
    try {
        const { name, compile, inference, clean } = await webGPUinit({ BUF_SIZE: MAX_BATCH_SIZE * 64 })
        gpuName = name
        await compile(parseHashcat22000(hc22000line))

        let BATCH_SIZE = 1024 * 128
        let nextChunk = passwordStream(BATCH_SIZE)
        while (true) {
            const start = performance.now()
            const chunk = await nextChunk
            if (!chunk) { break }
            curFile = chunk.name
            curProgress = chunk.progress
            const { buf, buf32, count } = chunk
            nextChunk = passwordStream(BATCH_SIZE)
            const out = await inference({ inp: buf32, count })
            if (out[0] !== 0xffffffff) {
                const start = buf32[out[0]]
                const end = buf.indexOf(10, start)
                password = new TextDecoder().decode(buf.subarray(start, end))
                break
            }
            avgHashrate = count / (performance.now() - start) * 1000
        }
        clean()
    } catch(e) { log(e.message); console.error(e); }
    clearInterval(update)
    return password
}

function u32toWgsl(arr) {
    return `array<u32, ${arr.length}>(${Array.from(arr).map(x => '0x'+x.toString(16)).join(',')})`
}
function u32toWgsl2d(arr) {
    return `array<array<u32, ${arr[0].length}>, ${arr.length}>(${arr.map(u32toWgsl).join(',\n')})`
}