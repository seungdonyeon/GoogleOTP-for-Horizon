import io
import qrcode

def png_bytes(otpauth: str) -> bytes:
    img = qrcode.make(otpauth)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
