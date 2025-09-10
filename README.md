# BYTEMARK.AI —— 字节级 AI 标识器

以“最小侵入”的方式，将“AI 生成”标识写入常见媒体文件（图片 / 视频 / 动图）的原始字节结构中，并提供极速验证能力。无需解码、无需重编码，尽量遵循各格式规范，确保文件依然可正常打开与播放。

> 入口文件：`add_ai_tag.py`

## 亮点

- 支持多种格式（写入 + 验证）：
  - PNG：在 `IEND` 前插入 `tEXt`（`AI_Generated=True` 和 `Description`）
  - JPEG：在 `SOI` 之后插入 `COM` 段（`0xFFFE`）
  - WebP：插入 `XMP ` chunk，并置位 `VP8X` 的 XMP 标志（`0x10`），兼容动图（ANIM/ANMF）
  - GIF：在 `Trailer` (0x3B) 前插入 `Comment Extension`，自动拆分为 255 字节子块
  - BMP：在文件尾部追加自定义 Trailer（`AI__ + length + payload`），并更新 `bfSize`
  - TIFF：在文件末尾追加新的 IFD（`ImageDescription`，ASCII），并把 IFD0 的 next 指向它
  - MP4/MOV：在 `moov` 内插入私有 `uuid` box（包含固定 16B id + 载荷），并更新 `moov` 大小
  - AVI：在末尾或 `idx1` 前插入 `LIST/INFO`（含 `ISFT`/`ICMT`），并更新 RIFF 大小
- 零解码验证：按格式逐字节解析，快速检测是否存在 AI 标识
- 统一日志：使用 `logging`，输出更规范

## 安装

- 纯 Python 实现，无第三方依赖
- Python 3.8+

## 使用

```python
from add_ai_tag import add_ai_metadata_fast, verify_ai_metadata
import base64

with open('input.webp', 'rb') as f:
    raw = f.read()

# 添加 AI 标识（返回 base64 字符串）
modified_b64 = add_ai_metadata_fast(raw)
modified_bytes = base64.b64decode(modified_b64)

# 写回文件
with open('modified.webp', 'wb') as f:
    f.write(modified_bytes)

# 验证
res = verify_ai_metadata(modified_bytes)
print(res)
```

或直接运行：

```bash
python add_ai_tag.py path/to/your.webp
```

## 设计要点（按格式）

- PNG：`tEXt` before `IEND`，合法且通用。
- JPEG：`COM` 段紧跟 `SOI`，不破坏编码数据。
- WebP：处理 `VP8X` 标志位与 chunk 对齐，更新 RIFF 大小，动图兼容。
- GIF：Comment Extension 使用 255 字节子块并以 `0x00` 终止。
- BMP：尾部 Trailer + 更新 `bfSize`，避免影响位图头和像素区。
- TIFF：在 IFD0 后追加新的 IFD，写入 `ImageDescription`，并更新 next 指针。
- MP4/MOV：在 `moov` 内注入 `uuid` box，更新 `moov` 大小（不做全文件重写）。
- AVI：追加 `LIST/INFO`，修正 RIFF size。

## 注意事项

- MP4/MOV 未做完整箱体重写，常见播放器兼容；如需更严谨规范，可进一步扩展。
- TIFF 目前是将 IFD0 的 next 覆盖为新 IFD；如需要保留链表，应遍历至末尾 IFD 再挂接。
- BMP 尾部追加为非标准做法，但更新了 `bfSize`，常见解析器可忽略尾部数据。
- AVI 索引与对齐在大多数样本下可正常工作，生产环境建议充分回归。
  
- **欢迎 PR / Issue：新增格式支持、规范性改进、增强 CLI 等**
