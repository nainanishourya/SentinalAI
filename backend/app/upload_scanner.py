"""Magic-byte / MIME file upload scanner.

Rejects uploads whose real binary signature does not match what the file's
extension claims to be (e.g. a .txt file renamed to .png), and rejects any
file whose content matches a known dangerous executable/script signature
regardless of the declared extension.
"""

IMAGE_SIGNATURES = {
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    "gif": [b"GIF87a", b"GIF89a"],
    "bmp": [b"BM"],
    "webp": [b"RIFF"],
}

DOCUMENT_SIGNATURES = {
    "pdf": [b"%PDF-"],
}

DANGEROUS_SIGNATURES = [
    (b"MZ", "Windows PE executable (.exe/.dll)"),
    (b"\x7fELF", "Linux ELF executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java multi-arch binary"),
    (b"PK\x03\x04", "ZIP-based archive (zip/jar/docm/xlsm with macros)"),
    (b"#!/", "Executable script with shebang"),
    (b"#!", "Executable script with shebang"),
]

KNOWN_EXT_GROUPS = {**IMAGE_SIGNATURES, **DOCUMENT_SIGNATURES}


def _detect_signature(content: bytes) -> tuple[str, str] | None:
    for sig, label in DANGEROUS_SIGNATURES:
        if content.startswith(sig):
            return "dangerous", label
    for ext, sigs in KNOWN_EXT_GROUPS.items():
        for sig in sigs:
            if content.startswith(sig):
                return "known", ext
    return None


def scan_upload(filename: str, content: bytes) -> dict:
    declared_ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    detection = _detect_signature(content)

    if detection and detection[0] == "dangerous":
        return {
            "verdict": "rejected",
            "declared_ext": declared_ext,
            "detected_type": detection[1],
            "reason": (
                f"File content matches a {detection[1]} signature but was uploaded as "
                f".{declared_ext or 'unknown'}. Executable/script content is never permitted "
                f"regardless of file extension."
            ),
            "error": "Invalid File Type",
        }

    if declared_ext in KNOWN_EXT_GROUPS:
        expected_sigs = KNOWN_EXT_GROUPS[declared_ext]
        matches = any(content.startswith(sig) for sig in expected_sigs)
        if not matches:
            detected_label = detection[1] if detection else "unrecognized / plain-text content"
            return {
                "verdict": "rejected",
                "declared_ext": declared_ext,
                "detected_type": detected_label,
                "reason": (
                    f"File was uploaded with a .{declared_ext} extension but its magic bytes do not "
                    f"match the {declared_ext.upper()} file signature. Detected content: {detected_label}. "
                    f"This indicates the file was renamed to masquerade as a {declared_ext.upper()} file."
                ),
                "error": "Invalid File Type",
            }
        return {
            "verdict": "accepted",
            "declared_ext": declared_ext,
            "detected_type": declared_ext,
            "reason": "Magic bytes match the declared file type.",
            "error": None,
        }

    return {
        "verdict": "accepted",
        "declared_ext": declared_ext or "unknown",
        "detected_type": detection[1] if detection else "unrecognized (no dangerous signature found)",
        "reason": "No dangerous signature detected; extension has no strict signature policy configured.",
        "error": None,
    }
