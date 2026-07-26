#!/usr/bin/env python3
"""Apply the 69_hide_stuff.patch fs/proc/base.c change in a way that works on
kernels new enough to use file_user_path() (e.g. Android 16 / 6.12).

The upstream SukiSU 69_hide_stuff.patch hunk for base.c was written against the
older `*path = vma->vm_file->f_path;` form and fails to apply on 6.12, which uses
`*path = *file_user_path(vma->vm_file);`. This rewrites proc_map_files_get_link's
lookup block to spoof VMAs whose backing file name contains "lineage" to
/system/framework/framework-res.apk, while preserving whatever assignment the
kernel originally used for the normal path.

Idempotent and non-fatal: if the file is already patched or the target block is
not found, it prints a note and exits 0 so the build can continue.
"""
import re
import sys

DEFAULT_PATH = "fs/proc/base.c"

# Matches the proc_map_files_get_link lookup block, tolerant of tabs/spaces and
# of the exact assignment used (file_user_path() on 6.12, f_path on older).
BLOCK = re.compile(
    r'vma = find_exact_vma\(mm, vm_start, vm_end\);[ \t]*\n'
    r'[ \t]*if \(vma && vma->vm_file\) \{[ \t]*\n'
    r'[ \t]*\*path = (?P<assign>[^;\n]+);[ \t]*\n'
    r'[ \t]*path_get\(path\);[ \t]*\n'
    r'[ \t]*rc = 0;[ \t]*\n'
    r'[ \t]*\}'
)


def replacement(m):
    assign = m.group("assign").strip()
    return (
        "vma = find_exact_vma(mm, vm_start, vm_end);\n"
        "\tif (vma) {\n"
        "\t\tif (vma->vm_file) {\n"
        "\t\t\tif (strstr(vma->vm_file->f_path.dentry->d_name.name, \"lineage\")) {\n"
        "\t\t\t\trc = kern_path(\"/system/framework/framework-res.apk\", LOOKUP_FOLLOW, path);\n"
        "\t\t\t} else {\n"
        "\t\t\t\t*path = " + assign + ";\n"
        "\t\t\t\tpath_get(path);\n"
        "\t\t\t\trc = 0;\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t}"
    )


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PATH
    try:
        with open(path, encoding="utf-8", errors="surrogateescape") as f:
            src = f.read()
    except FileNotFoundError:
        print(f"[hide_stuff] {path} not found; skipping (non-fatal)")
        return 0

    if "framework-res.apk" in src:
        print("[hide_stuff] base.c already patched; skipping")
        return 0

    new_src, n = BLOCK.subn(replacement, src, count=1)
    if n == 0:
        print("[hide_stuff] WARNING: target block not found in base.c; "
              "skipping lineage spoof (non-fatal)")
        return 0

    with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write(new_src)
    print("[hide_stuff] base.c patched for lineage path spoof")
    return 0


if __name__ == "__main__":
    sys.exit(main())
