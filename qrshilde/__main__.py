import argparse
import sys

# استيراد الملفات الفرعية
from . import qr_decode, qr_generate, qr_analyze, qr_inspect


def run_script_main(mod, argv):
    """
    Call module.main() after setting sys.argv the way the script expects.
    """
    if not hasattr(mod, "main"):
        raise SystemExit(f"{mod.__name__} has no main()")
    old = sys.argv[:]
    try:
        sys.argv = [mod.__name__] + argv
        mod.main()
    finally:
        sys.argv = old


def main():
    p = argparse.ArgumentParser(prog="qrshilde")
    sub = p.add_subparsers(dest="cmd", required=True)

    # 1. Decode Command (Old Utility)
    d = sub.add_parser("decode", help="Decode QR from image (Basic)")
    d.add_argument("image", help="Path to image (png/jpg)")
    d.add_argument("rest", nargs=argparse.REMAINDER, help="Extra args")

    # 2. Generate Command
    g = sub.add_parser("gen", help="Generate QR image")
    g.add_argument("text", help="Text/payload to encode")
    g.add_argument("-o", "--out", default="qrcode.png", help="Output image path")
    g.add_argument("rest", nargs=argparse.REMAINDER, help="Extra args")

    # 3. Analyze Command (The Main Feature 🌟)
    a = sub.add_parser("analyze", help="Analyze QR content (Text OR Image)")
    a.add_argument("target", help="Image path OR decoded text")
    a.add_argument("-o", "--out", default="report.md", help="Output report file")
    a.add_argument("rest", nargs=argparse.REMAINDER, help="Extra args")

    # 4. Inspect Command (Old Utility)
    i = sub.add_parser("inspect", help="Inspect QR payload (Basic Classification)")
    i.add_argument("target", help="Decoded text")
    i.add_argument("rest", nargs=argparse.REMAINDER, help="Extra args")

    args = p.parse_args()

    # --- التنفيذ ---

    if args.cmd == "decode":
        run_script_main(qr_decode, [args.image] + args.rest)

    elif args.cmd == "gen":
        # تمرير النص مباشرة (Positional)
        run_script_main(qr_generate, [args.text, "-o", args.out] + args.rest)

    elif args.cmd == "analyze":
        # ✅ التعديل هنا: نمرر "--text" لأن argparse داخل qr_analyze يتوقعها
        # رغم أننا سميناها "target" هنا، الملف الداخلي يتوقع --text أو Positional حسب برمجته
        # لكن لحظة! نحن عدلنا qr_analyze ليقبل --text كوسيط إجباري (Required).
        run_script_main(qr_analyze, ["--text", args.target, "--out", args.out] + args.rest)

    elif args.cmd == "inspect":
        run_script_main(qr_inspect, ["--text", args.target] + args.rest)


if __name__ == "__main__":
    main()