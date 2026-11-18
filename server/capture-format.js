const fs = require('node:fs');

function inspectCaptureHeader(filename) {
    const descriptor = fs.openSync(filename, 'r');
    const bytes = Buffer.alloc(28);
    let count;
    try { count = fs.readSync(descriptor, bytes, 0, bytes.length, 0); }
    finally { fs.closeSync(descriptor); }
    const magic = bytes.subarray(0, 4).toString('hex');
    if (magic === '0a0d0d0a') {
        const bom = bytes.subarray(8, 12).toString('hex');
        if (count < 28 || !['4d3c2b1a', '1a2b3c4d'].includes(bom)) throw new Error('Invalid PCAPNG section header.');
        const length = bom === '4d3c2b1a' ? bytes.readUInt32LE(4) : bytes.readUInt32BE(4);
        if (length < 28 || length % 4 || length > 32 * 1024 * 1024) throw new Error('Invalid PCAPNG section length.');
        return { format: 'pcapng', extension: '.pcapng' };
    }
    if (count < 24 || !['d4c3b2a1', 'a1b2c3d4', '4d3cb2a1', 'a1b23c4d'].includes(magic)) throw new Error('Choose a valid PCAP or PCAPNG capture file.');
    const little = magic.startsWith('d4') || magic.startsWith('4d');
    const read16 = offset => little ? bytes.readUInt16LE(offset) : bytes.readUInt16BE(offset);
    if (read16(4) !== 2 || read16(6) !== 4) throw new Error('Only PCAP version 2.4 is supported.');
    return { format: 'pcap', extension: '.pcap', nanoseconds: magic === '4d3cb2a1' || magic === 'a1b23c4d' };
}
module.exports = { inspectCaptureHeader };
