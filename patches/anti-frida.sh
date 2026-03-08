#!/bin/bash
# Anti-Frida kernel patches for GKI 5.10 android12
# Applies modifications to internal.h, task_mmu.c, array.c, fd.c
set -e

KERNEL_DIR="${1:-.}"

echo "=== Applying Anti-Frida patches to $KERNEL_DIR ==="

# ============================================================
# PATCH 1: fs/proc/internal.h - Hide frida threads from /proc
# ============================================================
FILE="$KERNEL_DIR/fs/proc/internal.h"
echo "[1/4] Patching $FILE ..."

if ! grep -q "pool-frida" "$FILE"; then
  sed -i '/^static inline struct task_struct \*get_proc_task(const struct inode \*inode)$/,/^}$/c\
static inline struct task_struct *get_proc_task(const struct inode *inode)\
{\
\tstruct task_struct *p = get_pid_task(proc_pid(inode), PIDTYPE_PID);\
\tchar tcomm[64];\
\n\tif (!p)\
\t\treturn NULL;\
\n\tif (p->flags \& PF_WQ_WORKER)\
\t\twq_worker_comm(tcomm, sizeof(tcomm), p);\
\telse\
\t\t__get_task_comm(tcomm, sizeof(tcomm), p);\
\n\tif (strstr(tcomm, "frida") ||\
\t    strstr(tcomm, "gmain") ||\
\t    strstr(tcomm, "gum-js") ||\
\t    strstr(tcomm, "linjector") ||\
\t    strstr(tcomm, "gdbus") ||\
\t    strstr(tcomm, "pool-frida"))\
\t\treturn NULL;\
\n\treturn p;\
}' "$FILE"
  echo "  internal.h patched OK"
else
  echo "  internal.h already patched, skipping"
fi

# Verify
if grep -q "pool-frida" "$FILE"; then
  echo "  [PASS] internal.h verification OK"
else
  echo "  [FAIL] internal.h patch failed!"
  exit 1
fi

# ============================================================
# PATCH 2: fs/proc/task_mmu.c - Hide frida VMAs from maps/smaps
# ============================================================
FILE="$KERNEL_DIR/fs/proc/task_mmu.c"
echo "[2/4] Patching $FILE ..."

if ! grep -q "bypass_show_map_vma" "$FILE"; then
  # Add bypass_show_map_vma function before show_map_vma
  sed -i '/^static void$/,/^show_map_vma(struct seq_file \*m, struct vm_area_struct \*vma)$/{
    /^static void$/{
      i\
static int bypass_show_map_vma(struct vm_area_struct *vma)\
{\
\tstruct file *file = vma->vm_file;\
\tconst char *name;\
\n\tif (!file || !file->f_path.dentry)\
\t\treturn 0;\
\n\tname = file->f_path.dentry->d_iname;\
\n\tif (strstr(name, "frida-") ||\
\t    strstr(name, "frida_") ||\
\t    strstr(name, "linjector"))\
\t\treturn 1;\
\n\tif (strstr(name, "libart.so") \&\& (vma->vm_flags \& VM_EXEC))\
\t\treturn 1;\
\n\tif (strstr(name, "jit-cache") ||\
\t    strstr(name, "jit-zygote"))\
\t\treturn 1;\
\n\treturn 0;\
}\

    }
  }' "$FILE"

  # Add bypass check inside show_map_vma after "const char *name = NULL;"
  sed -i '/const char \*name = NULL;/a\\n\tif (bypass_show_map_vma(vma))\n\t\treturn;' "$FILE"

  # Add bypass check inside show_smap before memset
  sed -i '/struct mem_size_stats mss;/a\\n\tif (bypass_show_map_vma(vma))\n\t\treturn 0;' "$FILE"

  echo "  task_mmu.c patched OK"
else
  echo "  task_mmu.c already patched, skipping"
fi

# Verify
if grep -q "bypass_show_map_vma" "$FILE"; then
  echo "  [PASS] task_mmu.c verification OK"
else
  echo "  [FAIL] task_mmu.c patch failed!"
  exit 1
fi

# ============================================================
# PATCH 3: fs/proc/array.c - TracerPid always 0
# ============================================================
FILE="$KERNEL_DIR/fs/proc/array.c"
echo "[3/4] Patching $FILE ..."

if ! grep -q "TracerPid always 0" "$FILE"; then
  # Comment out the tracer lines
  sed -i 's/^\t*tracer = ptrace_parent(p);$/\t\/* PATCH: TracerPid always 0 *\/\n\t\/* tracer = ptrace_parent(p); *\//' "$FILE"
  sed -i 's/^\t*if (tracer)$/\t\/* if (tracer) *\//' "$FILE"
  sed -i 's/^\t*\ttpid = task_pid_nr_ns(tracer, ns);$/\t\/*\ttpid = task_pid_nr_ns(tracer, ns); *\//' "$FILE"
  echo "  array.c patched OK"
else
  echo "  array.c already patched, skipping"
fi

# Verify
if grep -q "TracerPid always 0" "$FILE"; then
  echo "  [PASS] array.c verification OK"
else
  echo "  [FAIL] array.c patch failed!"
  exit 1
fi

# ============================================================
# PATCH 4: fs/proc/fd.c - Hide frida FDs from readlink
# ============================================================
FILE="$KERNEL_DIR/fs/proc/fd.c"
echo "[4/4] Patching $FILE ..."

if ! grep -q "hide frida" "$FILE"; then
  # Add frida fd hiding after path_get inside proc_fd_link
  sed -i '/path_get(\&fd_file->f_path);/{
    n
    s/ret = 0;/ret = 0;\
\n\t\t\t\/* PATCH: hide frida FDs from readlink *\/\
\t\t\tif (fd_file->f_path.dentry \&\&\
\t\t\t    fd_file->f_path.dentry->d_iname[0] != '\\0') {\
\t\t\t\tconst char *fname = fd_file->f_path.dentry->d_iname;\
\t\t\t\tif (strstr(fname, "frida") ||\
\t\t\t\t    strstr(fname, "linjector") ||\
\t\t\t\t    strstr(fname, "gadget")) {\
\t\t\t\t\tpath_put(path);\
\t\t\t\t\tret = -ENOENT;\
\t\t\t\t}\
\t\t\t}/
  }' "$FILE"
  echo "  fd.c patched OK"
else
  echo "  fd.c already patched, skipping"
fi

# Verify
if grep -q "hide frida" "$FILE"; then
  echo "  [PASS] fd.c verification OK"
else
  echo "  [FAIL] fd.c patch failed!"
  exit 1
fi

echo ""
echo "=== All anti-frida patches applied successfully! ==="