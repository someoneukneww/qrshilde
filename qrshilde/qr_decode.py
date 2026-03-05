from pyzbar.pyzbar import decode
from PIL import Image
import os

def decode_qr_image(image_path):
    """
    Decodes QR codes from an image file path.
    Returns a list of decoded objects.
    """
    if not os.path.exists(image_path):
        print(f"Error: Image file not found at {image_path}")
        return []

    try:
        # فتح الصورة باستخدام Pillow
        img = Image.open(image_path)
        
        # فك التشفير باستخدام pyzbar
        decoded_objects = decode(img)
        
        return decoded_objects
        
    except Exception as e:
        print(f"Error decoding QR image: {e}")
        return []
