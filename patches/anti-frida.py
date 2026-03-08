#!/usr/bin/env python3
"""Anti-Frida kernel patches for GKI 5.10 android12"""
import sys
import os

KERNEL_DIR = sys.argv[1] if len(sys.argv) > 1 else "."

def read_file(filepath):
    full = os.path.join(KERNEL_DIR, filepath)
    with open(full, "r") as f:
        return f.read()

def write_file(filepath, content):
    full = os.path.join(KERNEL_DIR, filepath)
    with open(full, "w") as f:
        f.write(content)

def patch_file(filepath, old, new, label, check_str):
    content = read_file(filepath)
    if check_str in content:
        print(f"  {label}: already patched, skipping")
        return True
    if old not in content:
        print(f"  {label}: FAILED - could not find target code!")
        print(f"  Looking for:")
        for i, line in enumerate(old.splitlines()[:5]):
            print(f"    {i}: {repr(line)}")
        return False
    content = content.replace(old, new, 1)
    write_file(filepath, content)
    print(f"  {label}: OK")
    return True

def insert_before(filepath, marker, code, label, check_str):
    content = read_file(filepath)
    if check_str in content:
        print(f"  {label}: already patched, skipping")
        return True
    if marker not in content:
        print(f"  {label}: FAILED - could not find marker!")
        print(f"  Looking for: {repr(marker[:80])}")
        return False
    content = content.replace(marker, code + "\n" + marker, 1)
    write_file(filepath, content)
    print(f"  {label}: OK")
    return True

errors = 0

# ============================================================
# PATCH 1: fs/proc/internal.h
# ============================================================
print("[1/4] Patching fs/proc/internal.h ...")

OLD_GET_PROC_TASK = """\
static inline struct task_struct *get_proc_task(const struct inode *inode)
{
\treturn get_pid_task(proc_pid(inode), PIDTYPE_PID);
}"""

NEW_GET_PROC_TASK = """\
static inline struct task_struct *get_proc_task(const struct inode *inode)
{
\tstruct task_struct *p = get_pid_task(proc_pid(inode), PIDTYPE_PID);
\tchar tcomm[64];

\tif (!p)
\t\treturn NULL;

\tif (p->flags & PF_WQ_WORKER)
\t\twq_worker_comm(tcomm, sizeof(tcomm), p);
\telse
\t\t__get_task_comm(tcomm, sizeof(tcomm), p);

\tif (strstr(tcomm, "frida") ||
\t    strstr(tcomm, "gmain") ||
\t    strstr(tcomm, "gum-js") ||
\t    strstr(tcomm, "linjector") ||
\t    strstr(tcomm, "gdbus") ||
\t    strstr(tcomm, "pool-frida"))
\t\treturn NULL;

\treturn p;
}"""

if not patch_file("fs/proc/internal.h", OLD_GET_PROC_TASK, NEW_GET_PROC_TASK,
                   "get_proc_task", "pool-frida"):
    errors += 1

# ============================================================
# PATCH 2: fs/proc/task_mmu.c
# ============================================================
print("[2/4] Patching fs/proc/task_mmu.c ...")

BYPASS_FUNC = """\
/*
 * Hide Frida-related VMAs from /proc/self/maps and /proc/self/smaps
 */
static int bypass_show_map_vma(struct vm_area_struct *vma)
{
\tstruct file *file = vma->vm_file;
\tconst char *name;

\tif (!file || !file->f_path.dentry)
\t\treturn 0;

\tname = file->f_path.dentry->d_iname;

\tif (strstr(name, "frida-") ||
\t    strstr(name, "frida_") ||
\t    strstr(name, "linjector"))
\t\treturn 1;

\tif (strstr(name, "libart.so") && (vma->vm_flags & VM_EXEC))
\t\treturn 1;

\tif (strstr(name, "jit-cache") ||
\t    strstr(name, "jit-zygote"))
\t\treturn 1;

\treturn 0;
}

"""

SHOW_MAP_MARKER = """\
static void
show_map_vma(struct seq_file *m, struct vm_area_struct *vma)"""

if not insert_before("fs/proc/task_mmu.c", SHOW_MAP_MARKER, BYPASS_FUNC,
                     "bypass_show_map_vma function", "bypass_show_map_vma"):
    errors += 1

# 2b: Add check inside show_map_vma
OLD_NAME_NULL = """\
\tconst char *name = NULL;

\tif (file) {"""

NEW_NAME_NULL = """\
\tconst char *name = NULL;

\tif (bypass_show_map_vma(vma))
\t\treturn;

\tif (file) {"""

if not patch_file("fs/proc/task_mmu.c", OLD_NAME_NULL, NEW_NAME_NULL,
                   "show_map_vma bypass check", "bypass_show_map_vma(vma))\n\t\treturn;"):
    errors += 1

# 2c: Add check inside show_smap
OLD_SMAP = """\
\tstruct mem_size_stats mss;

\tmemset(&mss, 0, sizeof(mss));"""

NEW_SMAP = """\
\tstruct mem_size_stats mss;

\tif (bypass_show_map_vma(vma))
\t\treturn 0;

\tmemset(&mss, 0, sizeof(mss));"""

if not patch_file("fs/proc/task_mmu.c", OLD_SMAP, NEW_SMAP,
                   "show_smap bypass check", "bypass_show_map_vma(vma))\n\t\treturn 0;"):
    errors += 1

# ============================================================
# PATCH 3: fs/proc/array.c - TracerPid always 0
# ============================================================
print("[3/4] Patching fs/proc/array.c ...")

OLD_TRACER = """\
\ttracer = ptrace_parent(p);
\tif (tracer)
\t\ttpid = task_pid_nr_ns(tracer, ns);"""

NEW_TRACER = """\
\t/* PATCH: TracerPid always 0 - hide ptrace/debugger */
\t/* tracer = ptrace_parent(p);
\tif (tracer)
\t\ttpid = task_pid_nr_ns(tracer, ns); */"""

if not patch_file("fs/proc/array.c", OLD_TRACER, NEW_TRACER,
                   "TracerPid", "TracerPid always 0"):
    errors += 1

# ============================================================
# PATCH 4: fs/proc/fd.c - Hide frida FDs
# ============================================================
print("[4/4] Patching fs/proc/fd.c ...")

OLD_FD = """\
\t\t\t*path = fd_file->f_path;
\t\t\tpath_get(&fd_file->f_path);
\t\t\tret = 0;"""

NEW_FD = """\
\t\t\t*path = fd_file->f_path;
\t\t\tpath_get(&fd_file->f_path);
\t\t\tret = 0;

\t\t\t/* PATCH: hide frida FDs from readlink */
\t\t\tif (fd_file->f_path.dentry &&
\t\t\t    fd_file->f_path.dentry->d_iname[0] != '\\0') {
\t\t\t\tconst char *fname = fd_file->f_path.dentry->d_iname;
\t\t\t\tif (strstr(fname, "frida") ||
\t\t\t\t    strstr(fname, "linjector") ||
\t\t\t\t    strstr(fname, "gadget")) {
\t\t\t\t\tpath_put(path);
\t\t\t\t\tret = -ENOENT;
\t\t\t\t}
\t\t\t}"""

if not patch_file("fs/proc/fd.c", OLD_FD, NEW_FD,
                   "fd readlink", "hide frida FDs from readlink"):
    errors += 1

# ============================================================
print()
if errors > 0:
    print(f"FAILED: {errors} patch(es) failed!")
    sys.exit(1)
else:
    print("All anti-frida patches applied successfully!")