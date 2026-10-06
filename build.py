#!/usr/bin/env python3
"""
Compila UbiDiscover a .exe amb PyInstaller (cal executar-ho a Windows).
    pip install pyinstaller
    python build.py
Resultat: dist/UbiDiscover.exe
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "ubidiscover.py")


def get_version():
    with open(SRC, encoding="utf-8") as f:
        m = re.search(r'^__version__\s*=\s*"([^"]+)"', f.read(), re.M)
    if not m:
        sys.exit("No s'ha trobat __version__ a ubidiscover.py")
    return m.group(1)


def write_version_file(ver):
    nums = [int(x) for x in re.findall(r"\d+", ver)][:4]
    nums += [0] * (4 - len(nums))
    t = tuple(nums)
    content = f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={t}, prodvers={t}, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040304B0', [
      StringStruct('CompanyName', 'Albert Coll Bordas'),
      StringStruct('FileDescription', 'UbiDiscover - descobridor de dispositius Ubiquiti'),
      StringStruct('FileVersion', '{ver}'),
      StringStruct('InternalName', 'UbiDiscover'),
      StringStruct('LegalCopyright', 'MIT - Albert Coll Bordas'),
      StringStruct('OriginalFilename', 'UbiDiscover.exe'),
      StringStruct('ProductName', 'UbiDiscover'),
      StringStruct('ProductVersion', '{ver}')])]),
    VarFileInfo([VarStruct('Translation', [0x0403, 1200])])
  ]
)
"""
    path = os.path.join(ROOT, "build", "version_info.txt")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def main():
    ver = get_version()
    # En una release de GitHub, el tag ha de coincidir amb __version__
    ref = os.environ.get("GITHUB_REF_NAME", "")
    if ref.startswith("v") and ref.lstrip("v") != ver:
        sys.exit(f"El tag {ref} no coincideix amb __version__ = {ver}")
    if os.environ.get("GITHUB_ENV"):
        with open(os.environ["GITHUB_ENV"], "a") as f:
            f.write(f"APP_VERSION={ver}\n")

    sep = ";" if os.name == "nt" else ":"
    ico = os.path.join(ROOT, "assets", "ubidiscover.ico")
    cmd = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
        "--onefile", "--noconsole", "--name", "UbiDiscover",
        "--icon", ico,
        "--add-data", f"{ico}{sep}assets",
        "--version-file", write_version_file(ver),
        SRC,
    ]
    print(">", " ".join(cmd))
    subprocess.check_call(cmd, cwd=ROOT)
    print(f"\nFet: dist/UbiDiscover.exe (v{ver})")


if __name__ == "__main__":
    main()
