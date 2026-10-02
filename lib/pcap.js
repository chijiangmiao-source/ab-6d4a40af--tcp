import { fail } from './errors.js';

// classic PCAP（libpcap）读取。支持两种魔数的两种字节序、微秒/纳秒精度。
// 不接受 pcapng。
const MAGIC_USEC = 0xa1b2c3d4;
const MAGIC_NSEC = 0xa1b23c4d;

function readU32(view, offset, le) {
  return le ? view.getUint32(offset, true) : view.getUint32(offset, false);
}
function readU16(view, offset, le) {
  return le ? view.getUint16(offset, true) : view.getUint16(offset, false);
}

export function parsePcap(buf) {
  if (!(buf instanceof Uint8Array) || buf.length < 24) {
    throw fail('BAD_PCAP', 'PCAP 全局头不足 24 字节', { length: buf?.length ?? 0 });
  }
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const leMagic = dv.getUint32(0, true);
  const beMagic = dv.getUint32(0, false);
  let le = null;
  let nano = false;
  if (leMagic === MAGIC_USEC || leMagic === MAGIC_NSEC) {
    le = true;
    nano = leMagic === MAGIC_NSEC;
  } else if (beMagic === MAGIC_USEC || beMagic === MAGIC_NSEC) {
    le = false;
    nano = beMagic === MAGIC_NSEC;
  } else {
    throw fail('BAD_PCAP_MAGIC', '无法识别的 PCAP 魔数（仅支持 classic PCAP，不支持 pcapng）');
  }

  const versionMajor = readU16(dv, 4, le);
  const linktype = readU32(dv, 20, le) >>> 0;
  const packets = [];
  let off = 24;
  let num = 0;
  while (off < buf.length) {
    num += 1;
    if (buf.length - off < 16) {
      throw fail('TRUNCATED_CAPTURE', `第 ${num} 条记录头被截断，文件不完整`, {
        packet: num,
        offset: off,
      });
    }
    const inclLen = readU32(dv, off + 8, le) >>> 0;
    const origLen = readU32(dv, off + 12, le) >>> 0;
    const dataStart = off + 16;
    if (buf.length - dataStart < inclLen) {
      throw fail('TRUNCATED_CAPTURE', `第 ${num} 个包声明捕获 ${inclLen} 字节，但文件数据不足`, {
        packet: num,
        offset: dataStart,
        range: [dataStart, Math.min(dataStart + inclLen, buf.length)],
      });
    }
    const truncated = inclLen < origLen;
    packets.push({
      num,
      tsSec: readU32(dv, off, le) >>> 0,
      tsFrac: readU32(dv, off + 4, le) >>> 0,
      inclLen,
      origLen,
      truncated,
      data: buf.subarray(dataStart, dataStart + inclLen),
    });
    off = dataStart + inclLen;
  }

  return { le, nano, versionMajor, linktype, packets };
}
