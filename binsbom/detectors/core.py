
from __future__ import annotations
import pathlib, struct

class FileType:
    UNKNOWN = "unknown"
    ELF = "elf"
    PE = "pe"
    MACHO = "macho"
    JAVA_ARCHIVE = "jar"   # jar/war/ear/zip with MANIFEST

def sniff_type(p: pathlib.Path) -> str:
    with p.open("rb") as f:
        header = f.read(16)

    # ELF magic
    if header.startswith(b"\x7fELF"):
        return FileType.ELF

    # PE magic (MZ)
    if header.startswith(b"MZ"):
        return FileType.PE

    # Mach-O (fat & thin)
    machos = {
        0xFEEDFACE, 0xFEEDFACF, 0xCAFEBABE, 0xCAFED00D,
        0xCEFAEDFE, 0xCFFAEDFE, 0xBEBAFECA, 0xD00DFECA
    }
    if len(header) >= 4:
        (mnum,) = struct.unpack(">I", header[0:4])
        if mnum in machos:
            return FileType.MACHO

    # ZIP/JAR
    if header.startswith(b"PK\x03\x04"):
        try:
            import zipfile
            with zipfile.ZipFile(p, "r") as z:
                if any(n.upper() == "META-INF/MANIFEST.MF" for n in z.namelist()):
                    return FileType.JAVA_ARCHIVE
        except Exception:
            pass

    return FileType.UNKNOWN
