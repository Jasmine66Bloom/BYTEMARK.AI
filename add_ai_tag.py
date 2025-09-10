import base64
import zlib
import struct
from typing import Union, Optional
import sys
import logging

# Configure module-level logger
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

AI_MARKER_TEXT = "此内容为AI生成"  # 统一常量
AI_MARKER_BYTES = AI_MARKER_TEXT.encode('utf-8')  # UTF-8 bytes

def detect_format(media_data: bytes) -> str:
    """检测图像/视频格式（复用magic bytes逻辑）"""
    if media_data.startswith(b'\x89PNG\r\n\x1a\n'): return 'PNG'
    if media_data.startswith(b'\xff\xd8\xff'): return 'JPEG'
    if media_data.startswith(b'RIFF') and b'WEBP' in media_data[:12]: return 'WEBP'
    if media_data.startswith(b'GIF8') or media_data.startswith(b'GIF87'): return 'GIF'
    if media_data.startswith(b'BM'): return 'BMP'
    if media_data.startswith(b'\x49\x49') or media_data.startswith(b'MM'): return 'TIFF'
    if media_data[4:8] == b'ftyp': return 'MOV' if b'qt  ' in media_data else 'MP4'
    if media_data.startswith(b'RIFF') and b'AVI ' in media_data[8:12]: return 'AVI'
    return 'UNKNOWN'

def calculate_crc_or_size(data: bytes, chunk_type: bytes = b'') -> bytes:
    """通用函数：复用CRC或大小计算（PNG CRC, 其他大小）"""
    if chunk_type:
        return zlib.crc32(chunk_type + data).to_bytes(4, 'big')
    return len(data).to_bytes(4, 'big')

def insert_chunk(data: bytes, pos: int, chunk_data: bytes) -> bytes:
    """通用函数：复用字节插入chunk/atom"""
    return data[:pos] + chunk_data + data[pos:]

def insert_bytes_metadata(data: bytes, fmt: str, ai_bytes: bytes) -> bytes:
    """字节级插入AI标识。
    针对不同媒体格式采取最安全、尽量规范的写法：
    - PNG: 在 IEND 前插入 tEXt
    - JPEG: 在 SOI 后插入 COM 段
    - WEBP: 在 VP8X 之后插入 XMP 块并设置 VP8X 对应标志
    - GIF: 在 Trailer 前插入 Comment Extension（255 字节子块）
    - BMP: 追加自定义尾部并更新 bfSize
    - TIFF: 追加新的 IFD（ImageDescription），并把 IFD0 的 next 指向它
    - MP4/MOV: 在 moov 内插入 uuid box，并更新 moov box 的 size
    - AVI: 在末尾插入 LIST/INFO，并更新 RIFF size
    返回修改后的字节流，或在失败时返回 None。
    """
    try:
        if fmt == 'PNG':
            iend_pos = data.find(b'IEND')
            if iend_pos != -1:
                def create_chunk(kw: bytes, txt: bytes):
                    d = kw + b'\x00' + txt
                    length = calculate_crc_or_size(d)
                    crc = calculate_crc_or_size(d, b'tEXt')
                    return length + b'tEXt' + d + crc
                chunks = create_chunk(b'AI_Generated', b'True') + create_chunk(b'Description', ai_bytes)
                return insert_chunk(data, iend_pos, chunks)
        
        if fmt == 'JPEG':
            # 使用 COM 段，安全且被广泛忽略，不破坏图像
            if not data.startswith(b'\xff\xd8'):
                return data
            comment = ai_bytes
            max_payload = 65535 - 2
            if len(comment) > max_payload:
                comment = comment[:max_payload]
            com_len = struct.pack('>H', len(comment) + 2)
            com_segment = b'\xff\xfe' + com_len + comment
            return insert_chunk(data, 2, com_segment)
        
        if fmt == 'WEBP':
            riff_pos = 0
            vp8x_pos = data.find(b'VP8X', riff_pos + 12)
            # 使用 XMP chunk（四字符码 'XMP '），文本更合适；设置 VP8X XMP 标志 0x10
            xmp_payload = ai_bytes
            xmp_len_le = len(xmp_payload).to_bytes(4, 'little')
            xmp_chunk = b'XMP ' + xmp_len_le + xmp_payload
            if len(xmp_payload) % 2 == 1:
                xmp_chunk += b'\x00'
            new_data = data
            if vp8x_pos != -1:
                # 更新VP8X标志 (XMP 位 0x10)
                # VP8X: 'VP8X'(4) + size(4) + payload(10): flags(1) + reserved(3) + w-1(3) + h-1(3)
                flags_pos = vp8x_pos + 8
                new_flags = data[flags_pos] | 0x10
                new_data = new_data[:flags_pos] + bytes([new_flags]) + new_data[flags_pos + 1:]
                vp8x_size = int.from_bytes(data[vp8x_pos + 4:vp8x_pos + 8], 'little')
                vp8x_payload_end = vp8x_pos + 8 + vp8x_size
                if vp8x_size % 2 == 1:
                    vp8x_payload_end += 1  # 对齐填充
                insert_pos = vp8x_payload_end
                new_data = insert_chunk(new_data, insert_pos, xmp_chunk)
            else:
                # 无 VP8X：构造一个带 XMP 标志位的 VP8X 并紧随其后插入 XMP
                vp8x = b'VP8X' + b'\x0A\x00\x00\x00' + b'\x10\x00\x00\x00' + b'\x00\x00\x00' + b'\x00\x00\x00'
                insert_pos = 12  # RIFF WEBP后
                new_data = insert_chunk(new_data, insert_pos, vp8x + xmp_chunk)
            # 更新RIFF大小
            new_size = len(new_data) - 8
            new_data = new_data[:4] + new_size.to_bytes(4, 'little') + new_data[8:]
            return new_data
        
        if fmt == 'GIF':
            # 在 Trailer(0x3B) 前插入 Comment Extension（处理 255 字节子块）
            trailer_pos = data.rfind(b'\x3B')
            if trailer_pos == -1:
                trailer_pos = len(data)
            payload = ai_bytes
            blocks = []
            i = 0
            while i < len(payload):
                chunk = payload[i:i+255]
                blocks.append(bytes([len(chunk)]) + chunk)
                i += 255
            blocks.append(b'\x00')
            comment_extension = b'\x21\xFE' + b''.join(blocks)
            return insert_chunk(data, trailer_pos, comment_extension)
        
        if fmt == 'BMP':
            # 采用尾部自定义区并更新文件大小，避免破坏位图头与像素数据
            if len(data) < 14 or data[:2] != b'BM':
                return data
            trailer = b'AI__' + struct.pack('<I', len(ai_bytes)) + ai_bytes
            new_data = data + trailer
            new_size = len(new_data)
            new_data = new_data[:2] + struct.pack('<I', new_size) + new_data[6:]
            return new_data
        
        if fmt == 'TIFF':
            # 读取字节序与 IFD0，构造新的 IFD，并把 IFD0 的 next 指向新 IFD
            be = data[:2] == b'MM'
            le = data[:2] == b'II'
            if not (be or le):
                return data
            endian = '>' if be else '<'
            def u16(b):
                return struct.unpack(endian + 'H', b)[0]
            def u32(b):
                return struct.unpack(endian + 'I', b)[0]
            def p16(v):
                return struct.pack(endian + 'H', v)
            def p32(v):
                return struct.pack(endian + 'I', v)
            ifd0_off = u32(data[4:8])
            if ifd0_off + 2 > len(data):
                return data
            count0 = u16(data[ifd0_off:ifd0_off+2])
            entries0_end = ifd0_off + 2 + count0 * 12
            if entries0_end + 4 > len(data):
                return data
            next_ifd_off_pos = entries0_end
            desc = ai_bytes + b'\x00'
            new_ifd_offset = len(data)
            new_desc_offset = new_ifd_offset + 2 + 12 + 4
            new_ifd = b''.join([
                p16(1),            # entries
                p16(0x010E),       # ImageDescription
                p16(2),            # ASCII
                p32(len(desc)),
                p32(new_desc_offset),
                p32(0)             # next IFD = 0
            ])
            new_data = data + new_ifd + desc
            new_data = new_data[:next_ifd_off_pos] + p32(new_ifd_offset) + new_data[next_ifd_off_pos+4:]
            return new_data
        
        if fmt in ['MP4', 'MOV']:
            # 在 moov 中插入 uuid box，并更新 moov 大小
            i = 0
            data_len = len(data)
            moov_pos = -1
            while i + 8 <= data_len:
                box_size = int.from_bytes(data[i:i+4], 'big')
                box_type = data[i+4:i+8]
                if box_type == b'moov':
                    moov_pos = i
                    break
                if box_size < 8:
                    break
                i += box_size
            if moov_pos == -1:
                return data
            moov_size = int.from_bytes(data[moov_pos:moov_pos+4], 'big')
            insert_pos = moov_pos + 8
            uuid = b'12345678AI_TAGS_1'  # 16B 固定标识
            payload = ai_bytes
            uuid_box_size = 4 + 4 + 16 + len(payload)
            uuid_box = uuid_box_size.to_bytes(4, 'big') + b'uuid' + uuid + payload
            new_data = insert_chunk(data, insert_pos, uuid_box)
            new_moov_size = moov_size + uuid_box_size
            new_data = new_data[:moov_pos] + new_moov_size.to_bytes(4, 'big') + new_data[moov_pos+4:]
            return new_data
        
        if fmt == 'AVI':
            # 在末尾（或 idx1 前）插入 LIST/INFO，更新 RIFF size
            idx1_pos = data.rfind(b'idx1')
            insert_pos = idx1_pos if idx1_pos != -1 else len(data)
            ai_text = ai_bytes + b'\x00'
            def avi_chunk(fourcc: bytes, payload: bytes) -> bytes:
                size = struct.pack('<I', len(payload))
                chunk = fourcc + size + payload
                if len(payload) % 2 == 1:
                    chunk += b'\x00'
                return chunk
            info_payload = avi_chunk(b'ISFT', ai_text) + avi_chunk(b'ICMT', ai_text)
            list_payload = b'INFO' + info_payload
            list_size = struct.pack('<I', len(list_payload))
            info_list = b'LIST' + list_size + list_payload
            new_data = insert_chunk(data, insert_pos, info_list)
            if new_data[:4] == b'RIFF':
                riff_size = len(new_data) - 8
                new_data = new_data[:4] + struct.pack('<I', riff_size) + new_data[8:]
            return new_data
    
    except Exception:
        pass
    return None

def add_ai_metadata_fast(input_data: Union[bytes, str]) -> str:
    """主函数：添加'AI生成'标识（全字节级，速度最快）。
    入参可为 bytes 或 base64 字符串；返回 base64 字符串。
    """
    if not input_data: return ""
    if isinstance(input_data, str):  # base64输入
        data = base64.b64decode(input_data)
    else:  # bytes输入
        data = input_data
    fmt = detect_format(data)
    if fmt == 'UNKNOWN': return base64.b64encode(data).decode('utf-8')
    ai_bytes = AI_MARKER_BYTES
    
    # 全字节插入
    result = insert_bytes_metadata(data, fmt, ai_bytes)
    if result is not None:
        return base64.b64encode(result).decode('utf-8')
    return base64.b64encode(data).decode('utf-8')  # fallback原

# 示例使用
# modified_base64 = add_ai_metadata_fast(your_binary_or_base64_data)

def verify_ai_metadata(input_data: Union[bytes, str]) -> dict:
    """主验证函数：不解码媒体，基于字节结构做快速解析与标记检测。"""
    if not input_data: return {'verified': False, 'media_desc': '空数据', 'ai_marker': None}
    if isinstance(input_data, str):  # base64输入
        data = base64.b64decode(input_data)
    else:  # bytes输入
        data = input_data
    fmt = detect_format(data)
    media_desc = f"格式: {fmt}, 大小: {len(data)} bytes"
    ai_found = None
    verified = False
    
    try:
        # 字节级解析描述（无解码）
        if fmt in ['PNG', 'JPEG', 'WEBP', 'GIF', 'BMP', 'TIFF']:
            # 简单头提取尺寸（复用字节）
            if fmt == 'PNG':
                width, height = struct.unpack('>II', data[16:24])
                media_desc += f", 尺寸: ({width}, {height})"
            elif fmt == 'JPEG':
                pos = data.find(b'\xff\xc0')
                if pos != -1:
                    height, width = struct.unpack('>HH', data[pos+5:pos+9])
                    media_desc += f", 尺寸: ({width}, {height})"
            elif fmt == 'WEBP':
                vp8x_pos = data.find(b'VP8X')
                if vp8x_pos != -1:
                    # 读取 VP8X payload 中的宽高（各3字节，little-endian，存的是减1的值）
                    # offsets: flags(+8), reserved(+9..+11), width_minus_1(+12..+14), height_minus_1(+15..+17)
                    if len(data) >= vp8x_pos + 18:
                        w_minus_1 = data[vp8x_pos+12] | (data[vp8x_pos+13] << 8) | (data[vp8x_pos+14] << 16)
                        h_minus_1 = data[vp8x_pos+15] | (data[vp8x_pos+16] << 8) | (data[vp8x_pos+17] << 16)
                        width = w_minus_1 + 1
                        height = h_minus_1 + 1
                        media_desc += f", 尺寸: ({width}, {height})"
            elif fmt == 'GIF':
                width, height = struct.unpack('<HH', data[6:10])
                media_desc += f", 尺寸: ({width}, {height})"
            elif fmt == 'BMP':
                width, height = struct.unpack('<II', data[18:26])
                media_desc += f", 尺寸: ({width}, {height})"
            elif fmt == 'TIFF':
                if data[0:2] == b'\x49\x49':  # little endian
                    num_entries = struct.unpack('<H', data[8:10])[0]
                    ifd_pos = 8 + 2
                    width, height = 0, 0
                    for _ in range(num_entries):
                        tag = struct.unpack('<H', data[ifd_pos:ifd_pos+2])[0]
                        if tag == 0x0100:  # width
                            offset = struct.unpack('<I', data[ifd_pos+8:ifd_pos+12])[0]
                            width = struct.unpack('<I', data[offset:offset+4])[0]
                        if tag == 0x0101:  # height
                            offset = struct.unpack('<I', data[ifd_pos+8:ifd_pos+12])[0]
                            height = struct.unpack('<I', data[offset:offset+4])[0]
                        ifd_pos += 12
                    media_desc += f", 尺寸: ({width}, {height})"
                # big endian类似
        elif fmt in ['MP4', 'MOV', 'AVI']:
            if b'moov' in data: media_desc += ", 包含moov (视频轨道)"
            if b'udta' in data or b'INFO' in data: media_desc += ", 包含元数据"
            if b'avc1' in data or b'H264' in data: media_desc += ", 编码: H.264"
        
        # 字节级检查AI标识（按格式精准检测）
        if fmt == 'JPEG' and data.startswith(b'\xff\xd8'):
            # 扫描段，查找 COM (0xFFFE)
            i = 2
            while i + 4 <= len(data) and data[i] == 0xFF:
                while i < len(data) and data[i] == 0xFF:
                    i += 1
                if i >= len(data): break
                marker = data[i]
                i += 1
                # 无长度段
                if marker in (0xD8, 0xD9):
                    continue
                if i + 2 > len(data): break
                seg_len = struct.unpack('>H', data[i:i+2])[0]
                if marker == 0xFE and i + seg_len <= len(data):
                    payload = data[i+2:i+seg_len]
                    if AI_MARKER_BYTES in payload:
                        verified = True
                        ai_found = 'JPEG-COM: ' + AI_MARKER_TEXT
                        break
                i += seg_len
        elif fmt == 'WEBP':
            # 遍历 RIFF chunk，查找 XMP 块
            if data[:4] == b'RIFF' and data[8:12] == b'WEBP':
                i = 12
                while i + 8 <= len(data):
                    fourcc = data[i:i+4]
                    size = int.from_bytes(data[i+4:i+8], 'little')
                    start = i + 8
                    end = start + size
                    if end > len(data): break
                    if fourcc == b'XMP ':
                        if AI_MARKER_BYTES in data[start:end]:
                            verified = True
                            ai_found = 'WEBP-XMP: ' + AI_MARKER_TEXT
                            break
                    i = end + (size % 2)
        elif fmt == 'GIF':
            # 查找 Comment Extension，拼接子块检查
            pos = 0
            while True:
                pos = data.find(b'\x21\xFE', pos)
                if pos == -1: break
                j = pos + 2
                found = False
                while j < len(data):
                    if j >= len(data): break
                    blen = data[j]
                    j += 1
                    if blen == 0:  # 结束
                        break
                    block = data[j:j+blen]
                    if AI_MARKER_BYTES in block:
                        found = True
                        break
                    j += blen
                if found:
                    verified = True
                    ai_found = 'GIF-COMMENT: ' + AI_MARKER_TEXT
                    break
                pos = j
        elif fmt == 'BMP':
            # 尾部自定义 trailer: 'AI__' + len + payload
            magic_pos = data.rfind(b'AI__')
            if magic_pos != -1 and magic_pos + 8 <= len(data):
                length = struct.unpack('<I', data[magic_pos+4:magic_pos+8])[0]
                payload = data[magic_pos+8:magic_pos+8+length]
                if AI_MARKER_BYTES in payload:
                    verified = True
                    ai_found = 'BMP-TRAILER: ' + AI_MARKER_TEXT
        elif fmt == 'TIFF':
            # 简化：直接按字节搜索（我们插入的是 ASCII ImageDescription）
            if AI_MARKER_BYTES in data:
                verified = True
                ai_found = 'TIFF-IFD: ' + AI_MARKER_TEXT
        elif fmt in ['MP4', 'MOV']:
            # 在 moov 内查找 uuid box
            i = 0
            data_len = len(data)
            while i + 8 <= data_len:
                box_size = int.from_bytes(data[i:i+4], 'big')
                box_type = data[i+4:i+8]
                if box_size < 8 or i + box_size > data_len:
                    break
                if box_type == b'moov':
                    j = i + 8
                    end = i + box_size
                    while j + 8 <= end:
                        sz = int.from_bytes(data[j:j+4], 'big')
                        typ = data[j+4:j+8]
                        if sz < 8 or j + sz > end:
                            break
                        if typ == b'uuid' and j + 24 <= end:
                            uuid = data[j+8:j+24]
                            if uuid == b'12345678AI_TAGS_1':
                                payload = data[j+24:j+sz]
                                if AI_MARKER_BYTES in payload:
                                    verified = True
                                    ai_found = 'MP4-UUID: ' + AI_MARKER_TEXT
                                    break
                        j += sz
                if verified:
                    break
                i += box_size
        elif fmt == 'AVI':
            # 遍历 LIST INFO，解析 ICMT/ISFT
            pos = 12  # after RIFF header
            while pos + 8 <= len(data):
                ckid = data[pos:pos+4]
                cksize = struct.unpack('<I', data[pos+4:pos+8])[0]
                if ckid == b'LIST' and pos + 12 <= len(data):
                    list_type = data[pos+8:pos+12]
                    if list_type == b'INFO':
                        k = pos + 12
                        end = pos + 8 + cksize
                        while k + 8 <= min(end, len(data)):
                            cid = data[k:k+4]
                            sz = struct.unpack('<I', data[k+4:k+8])[0]
                            start = k + 8
                            stop = start + sz
                            if stop > len(data): break
                            if cid in (b'ICMT', b'ISFT'):
                                if AI_MARKER_BYTES in data[start:stop]:
                                    verified = True
                                    ai_found = 'AVI-INFO: ' + AI_MARKER_TEXT
                                    break
                            k = stop + (sz % 2)
                        if verified:
                            break
                pos += 8 + cksize
        # 通用兜底：直接搜索字节
        if not verified and AI_MARKER_BYTES in data:
            verified = True
            ai_found = AI_MARKER_TEXT
        elif not verified and b'AI_Generated' in data:
            verified = True
            ai_found = "AI_Generated: True"
        
        if verified: logger.info("验证成功")
        else: logger.info("验证失败")
    
    except Exception as e:
        media_desc += f", 解析错误: {e}"
    
    return {'verified': verified, 'media_desc': media_desc, 'ai_marker': ai_found}

# 示例使用
# result = verify_ai_metadata(your_binary_or_base64_data)
# print(result)

def main(webp_file_path: str):
    """主函数：读本地WebP文件，添加AI标识，验证并解析"""
    # 读本地WebP文件
    with open(webp_file_path, 'rb') as f:
        original_data = f.read()
    
    logger.debug("原始WebP数据 (前50字节): %r", original_data[:50])
    
    # 添加AI标识
    modified_base64 = add_ai_metadata_fast(original_data)
    modified_data = base64.b64decode(modified_base64)  # 转回bytes
    
    # 验证和解析
    result = verify_ai_metadata(modified_data)
    logger.info("解析结果:")
    logger.info("AI标识: %s", result['ai_marker'])
    logger.info("媒体描述: %s", result['media_desc'])
    logger.info("验证成功: %s", result['verified'])
    
    # 保存修改后的文件（可选）
    with open('modified.webp', 'wb') as f:
        f.write(modified_data)
    logger.info("修改后的WebP保存为 'modified.webp'")
    
    # 返回原始WebP数据
    logger.debug("原始WebP数据 (前50字节, 确认无变): %r", original_data[:50])
    
if __name__ == "__main__":
    if len(sys.argv) < 2:
        logger.error("Usage: python script.py path_to_webp_file")
        sys.exit(1)
    webp_file_path = sys.argv[1]
    main(webp_file_path)