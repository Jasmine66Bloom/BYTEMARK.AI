# BYTEMARK.AI — Byte-level AI Marker for Media

Embed an "AI-generated" seal directly into the bytes of common media formats (images / video / animations) and verify it at blazing speed without decoding or re-encoding. BYTEMARK.AI aims to follow each format’s layout to preserve playability and visual fidelity.

> Entry point: `add_ai_tag.py`

## Highlights

- Supported formats (insertion + verification):
  - PNG: insert `tEXt` before `IEND` (`AI_Generated=True` and `Description`)
  - JPEG: insert a `COM` segment right after `SOI` (`0xFFFE`)
  - WebP: insert an `XMP ` chunk and set the `VP8X` XMP flag (`0x10`), compatible with animated WebP (ANIM/ANMF)
  - GIF: insert a `Comment Extension` before `Trailer` (0x3B), auto-splitting into 255-byte sub-blocks
  - BMP: append a custom trailer (`AI__ + length + payload`) and update `bfSize`
  - TIFF: append a new IFD (`ImageDescription`, ASCII) at the end and link it from IFD0 via the next pointer
  - MP4/MOV: inject a private `uuid` box into `moov` (fixed 16B id + payload) and update the `moov` size
  - AVI: append a `LIST/INFO` (with `ISFT`/`ICMT`) near the end and update RIFF size
- Verification requires no decoding: format-specific byte scans for instant results
- Structured logs: standard `logging` via `logger`

## Installation

- Pure Python, no external dependencies
- Python 3.8+

## Usage

```python
from add_ai_tag import add_ai_metadata_fast, verify_ai_metadata
import base64

with open('input.webp', 'rb') as f:
    raw = f.read()

# Add AI marker (returns base64 string)
modified_b64 = add_ai_metadata_fast(raw)
modified_bytes = base64.b64decode(modified_b64)

# Save back to file
with open('modified.webp', 'wb') as f:
    f.write(modified_bytes)

# Verify
res = verify_ai_metadata(modified_bytes)
print(res)
```

Or run directly:

```bash
python add_ai_tag.py path/to/your.webp
```

## Design Notes (by format)

- PNG: legal `tEXt` before `IEND`.
- JPEG: `COM` segment after `SOI`, leaving encoded data untouched.
- WebP: respects `VP8X` flags and chunk alignment; updates RIFF size; works with animated WebP.
- GIF: Comment Extension sub-blocks of 255 bytes, terminated by `0x00`.
- BMP: trailing custom area + `bfSize` update to avoid corrupting headers/pixels.
- TIFF: append a new IFD with `ImageDescription` and update the next pointer from IFD0.
- MP4/MOV: inject a `uuid` box inside `moov` and update `moov` size (no full box rewrite).
- AVI: add `LIST/INFO` and fix RIFF size.

## Caveats

- MP4/MOV handling only updates `moov` size; most players are fine, but a full ISO BMFF rewrite can be added if needed.
- TIFF currently overwrites IFD0's next pointer to our new IFD; to preserve a chain, traverse to the last IFD and link there.
- BMP trailing data is non-standard but widely tolerated; `bfSize` is updated for consistency.
- AVI index/alignments work for common cases; regression testing is recommended for production workflows.

- **Contributions welcome: more formats, stricter spec compliance, richer CLI (batching, directory scans, custom outputs)**
