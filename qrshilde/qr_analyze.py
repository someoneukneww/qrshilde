import argparse
import os
import cv2
import asyncio
from pathlib import Path

from qrshilde.src.ai.analyzer import analyze_qr_payload

def decode_qr_from_image(image_path):
    img = cv2.imread(image_path)
    if img is None:
        return None, "Error: Could not read image file."

    detector = cv2.QRCodeDetector()
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    data, _, _ = detector.detectAndDecode(img)
    if data:
        return data, None

    _, thresh = cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)
    data, _, _ = detector.detectAndDecode(thresh)
    if data:
        return data, None

    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    data, _, _ = detector.detectAndDecode(blurred)
    if data:
        return data, None

    inverted = cv2.bitwise_not(gray)
    data, _, _ = detector.detectAndDecode(inverted)
    if data:
        return data, None

    return None, "No QR code detected (Try checking the image manually)."

def main():
    parser = argparse.ArgumentParser(
        description="Analyze QR code (Image file OR Text payload) and generate a security report."
    )

    parser.add_argument(
        "--text",
        type=str,
        required=True,
        help="QR text content OR path to image file (.png/.jpg)",
    )

    parser.add_argument(
        "--out",
        type=str,
        default="report.md",
        help="Output Markdown report file.",
    )

    args = parser.parse_args()
    input_data = args.text
    out_file = Path(args.out)

    final_payload = input_data

    print("--------------------------------------------------")

    if os.path.exists(input_data):
        print(f"[📷] Detected image file: {input_data}")
        print("   [..] Decoding QR code from image...")

        decoded_text, error = decode_qr_from_image(input_data)
        if error:
            print(f"[❌] {error}")
            return

        print(f"[✅] Decoded Payload: {decoded_text}")
        print("--------------------------------------------------")
        final_payload = decoded_text
    else:
        print(f"[📝] Analyzing raw text input...")

    print("[+] Running security analysis...")
    result = asyncio.run(analyze_qr_payload(final_payload, report_id="cli"))

    if result and "report_md" in result:
        out_file.write_text(result["report_md"], encoding="utf-8")
        print(f"[+] Report saved successfully to: {out_file}")
    else:
        print("[❌] Analysis failed.")

if __name__ == "__main__":
    main()