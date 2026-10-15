#!/usr/bin/env python3
"""
File Organizer + Enkripsi

Instalasi:   pip install cryptography

Contoh pemakaian:
  python file_organizer.py organize ~/Downloads --dry-run        # simulasi saja
  python file_organizer.py organize ~/Downloads                  # rapikan saja
  python file_organizer.py organize ~/Downloads --encrypt        # rapikan + enkripsi
  python file_organizer.py decrypt  ~/Downloads                  # buka enkripsi
"""

import argparse
import base64
import getpass
import os
import shutil
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CATEGORIES = {
    "Gambar": {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg"},
    "Dokumen": {".pdf", ".doc", ".docx", ".txt", ".odt", ".rtf", ".md"},
    "Spreadsheet": {".xls", ".xlsx", ".csv", ".ods"},
    "Presentasi": {".ppt", ".pptx", ".odp"},
    "Video": {".mp4", ".mkv", ".avi", ".mov", ".webm"},
    "Audio": {".mp3", ".wav", ".flac", ".aac", ".ogg"},
    "Arsip": {".zip", ".rar", ".7z", ".tar", ".gz"},
    "Kode": {".py", ".js", ".html", ".css", ".java", ".cpp", ".json"},
    "Aplikasi": {".exe", ".msi", ".apk", ".dmg", ".deb"},
}

ENC_EXT = ".enc"
MAGIC = b"FORG1"      # penanda format file terenkripsi
SALT_SIZE = 16
ITERATIONS = 480_000  # makin besar makin sulit ditebak (brute-force)


# ---------- Enkripsi ----------

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_file(src: Path, dest: Path, key: bytes, salt: bytes) -> None:
    token = Fernet(key).encrypt(src.read_bytes())
    dest.write_bytes(MAGIC + salt + token)


def decrypt_file(src: Path, dest: Path, password: str, key_cache: dict) -> None:
    raw = src.read_bytes()
    if not raw.startswith(MAGIC):
        raise ValueError("bukan file hasil enkripsi program ini")
    salt = raw[len(MAGIC): len(MAGIC) + SALT_SIZE]
    token = raw[len(MAGIC) + SALT_SIZE:]
    if salt not in key_cache:
        key_cache[salt] = derive_key(password, salt)
    dest.write_bytes(Fernet(key_cache[salt]).decrypt(token))


# ---------- Utilitas ----------

def get_category(path: Path) -> str:
    ext = path.suffix.lower()
    for name, exts in CATEGORIES.items():
        if ext in exts:
            return name
    return "Lainnya"


def unique_path(path: Path) -> Path:
    """Hindari menimpa file: report.pdf -> report (1).pdf"""
    if not path.exists():
        return path
    i = 1
    while True:
        candidate = path.with_name(f"{path.stem} ({i}){path.suffix}")
        if not candidate.exists():
            return candidate
        i += 1


def ask_password(confirm: bool) -> str:
    pw = getpass.getpass("Password: ")
    if not pw:
        sys.exit("Password tidak boleh kosong.")
    if confirm and pw != getpass.getpass("Ulangi password: "):
        sys.exit("Password tidak sama.")
    return pw


# ---------- Perintah utama ----------

def organize(folder: Path, encrypt: bool, dry_run: bool) -> None:
    key = salt = None
    if encrypt and not dry_run:
        print("PERINGATAN: jika password hilang, file TIDAK bisa dipulihkan.")
        password = ask_password(confirm=True)
        salt = os.urandom(SALT_SIZE)
        key = derive_key(password, salt)

    script = Path(__file__).resolve()
    count = 0
    for item in sorted(folder.iterdir()):
        if not item.is_file() or item.resolve() == script or item.name.startswith("."):
            continue

        target_dir = folder / get_category(item)
        target = unique_path(target_dir / item.name)
        label = f"{item.name} -> {target_dir.name}/"
        if encrypt:
            target = target.with_name(target.name + ENC_EXT)
            label += "  [enkripsi]"

        print(("[SIMULASI] " if dry_run else "") + label)
        count += 1
        if dry_run:
            continue

        target_dir.mkdir(exist_ok=True)
        if encrypt:
            encrypt_file(item, target, key, salt)
            item.unlink()  # hapus file asli setelah terenkripsi
        else:
            shutil.move(str(item), str(target))

    print(f"\nSelesai. {count} file diproses.")


def decrypt(folder: Path, keep: bool) -> None:
    files = sorted(folder.rglob(f"*{ENC_EXT}"))
    if not files:
        print("Tidak ada file .enc ditemukan.")
        return

    password = ask_password(confirm=False)
    key_cache: dict = {}
    ok = 0
    for f in files:
        dest = unique_path(f.with_suffix(""))  # buang ekstensi .enc
        try:
            decrypt_file(f, dest, password, key_cache)
        except InvalidToken:
            print(f"GAGAL (password salah / file rusak): {f.name}")
            continue
        except ValueError as e:
            print(f"LEWATI {f.name}: {e}")
            continue
        if not keep:
            f.unlink()
        print(f"Dibuka: {dest.name}")
        ok += 1
    print(f"\nSelesai. {ok}/{len(files)} file berhasil dibuka.")


def main() -> None:
    parser = argparse.ArgumentParser(description="File organizer dengan enkripsi")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_org = sub.add_parser("organize", help="rapikan file ke folder per kategori")
    p_org.add_argument("folder", type=Path)
    p_org.add_argument("--encrypt", action="store_true", help="enkripsi file")
    p_org.add_argument("--dry-run", action="store_true", help="simulasi saja")

    p_dec = sub.add_parser("decrypt", help="buka file .enc")
    p_dec.add_argument("folder", type=Path)
    p_dec.add_argument("--keep", action="store_true", help="simpan file .enc")

    args = parser.parse_args()
    if not args.folder.is_dir():
        sys.exit(f"Folder tidak ditemukan: {args.folder}")

    if args.cmd == "organize":
        organize(args.folder, args.encrypt, args.dry_run)
    else:
        decrypt(args.folder, args.keep)


if __name__ == "__main__":
    main()