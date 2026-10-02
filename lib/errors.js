// 统一的分析错误类型：所有拒绝结论都带稳定 code 与定位细节
// 常见定位字段：
//   packet   - 首个相关原始包号（pcap 内 1-based）
//   packet2  - 冲突对端包号（如有）
//   offset   - 字节偏移（按上下文：包内 / IP 数据报内 / 流内）
//   range    - [起始, 结束) 半开区间
export class AnalysisError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'AnalysisError';
    this.code = code;
    Object.assign(this, details);
  }

  toJSON() {
    return {
      ok: false,
      code: this.code,
      message: this.message,
      packet: this.packet ?? null,
      packet2: this.packet2 ?? null,
      offset: this.offset ?? null,
      range: this.range ?? null,
      ...(this.extra ?? {}),
    };
  }
}

export function fail(code, message, details) {
  return new AnalysisError(code, message, details);
}
