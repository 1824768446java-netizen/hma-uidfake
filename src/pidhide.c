// SPDX-License-Identifier: GPL-2.0
/*
 * Hide selected PIDs from /proc for every caller, including root.
 * Match hide_pids= (numeric) and hide_cmdlines= (cmdline substring).
 */
#include <linux/cred.h>
#include <linux/dirent.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/magic.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "uidfake.h"

#define PIDHIDE_MAX 64
#define PIDHIDE_PAT 8
#define PIDHIDE_STR 512
#define PIDHIDE_CLEN 256

int get_cmdline(struct task_struct *tsk, char *buffer, int buflen);

static DEFINE_SPINLOCK(pidhide_lock);
static int pidhide_n;
static int pidhide_pids[PIDHIDE_MAX];
static int pidhide_np;
static char pidhide_pats[PIDHIDE_PAT][64];
static char pidhide_list[PIDHIDE_STR] = "";
static char hide_cmdlines[PIDHIDE_STR] =
	"oh_my_keymint/daemon,hide-root-module/permissions_service.sh";

static bool all_digits(const char *s)
{
	if (!s || !*s)
		return false;
	for (; *s; s++) {
		if (*s < '0' || *s > '9')
			return false;
	}
	return true;
}

static int parse_pid(const char *s)
{
	long v;
	char *end;

	if (!all_digits(s))
		return -1;
	v = simple_strtol(s, &end, 10);
	if (!end || *end || v <= 1 || v > INT_MAX)
		return -1;
	return (int)v;
}

void pidhide_apply_str(const char *val)
{
	char tmp[PIDHIDE_STR];
	char *p, *tok;
	int n = 0;
	int pids[PIDHIDE_MAX];
	unsigned long flags;

	if (!val)
		val = "";
	strscpy(tmp, val, sizeof(tmp));
	p = tmp;
	while ((tok = strsep(&p, ", \t\n")) != NULL) {
		int pid;

		if (!*tok)
			continue;
		pid = parse_pid(tok);
		if (pid < 0)
			continue;
		if (n < PIDHIDE_MAX)
			pids[n++] = pid;
	}
	spin_lock_irqsave(&pidhide_lock, flags);
	pidhide_n = n;
	memcpy(pidhide_pids, pids, sizeof(int) * n);
	spin_unlock_irqrestore(&pidhide_lock, flags);
	pr_info("uidfake: pidhide %d pid(s)\n", n);
}

void pidhide_apply_cmdlines(const char *val)
{
	char tmp[PIDHIDE_STR];
	char *p, *tok;
	int n = 0;
	char pats[PIDHIDE_PAT][64];
	unsigned long flags;

	if (!val)
		val = "";
	strscpy(tmp, val, sizeof(tmp));
	p = tmp;
	while ((tok = strsep(&p, ",\n")) != NULL) {
		while (*tok == ' ' || *tok == '\t')
			tok++;
		if (!*tok)
			continue;
		if (n < PIDHIDE_PAT)
			strscpy(pats[n++], tok, 64);
	}
	spin_lock_irqsave(&pidhide_lock, flags);
	pidhide_np = n;
	memcpy(pidhide_pats, pats, sizeof(pats));
	spin_unlock_irqrestore(&pidhide_lock, flags);
	pr_info("uidfake: pidhide %d cmdline pattern(s)\n", n);
}

static bool cmdline_match(struct task_struct *t)
{
	char buf[PIDHIDE_CLEN];
	char pats[PIDHIDE_PAT][64];
	int n, i, np;
	unsigned long flags;

	spin_lock_irqsave(&pidhide_lock, flags);
	np = pidhide_np;
	memcpy(pats, pidhide_pats, sizeof(pats[0]) * np);
	spin_unlock_irqrestore(&pidhide_lock, flags);
	if (np <= 0)
		return false;

	n = get_cmdline(t, buf, sizeof(buf) - 1);
	if (n <= 0)
		return false;
	if (n >= (int)sizeof(buf))
		n = sizeof(buf) - 1;
	buf[n] = 0;
	for (i = 0; i < n; i++) {
		if (buf[i] == 0)
			buf[i] = ' ';
	}
	for (i = 0; i < np; i++) {
		if (pats[i][0] && strstr(buf, pats[i]))
			return true;
	}
	return false;
}

static bool pid_in_list(int pid)
{
	unsigned long flags;
	int i, n;
	int local[PIDHIDE_MAX];

	spin_lock_irqsave(&pidhide_lock, flags);
	n = pidhide_n;
	memcpy(local, pidhide_pids, sizeof(int) * n);
	spin_unlock_irqrestore(&pidhide_lock, flags);
	for (i = 0; i < n; i++) {
		if (local[i] == pid)
			return true;
	}
	return false;
}

bool pidhide_has(int pid)
{
	struct task_struct *t;
	bool hit;

	if (pid <= 1)
		return false;
	if (pid_in_list(pid))
		return true;

	rcu_read_lock();
	t = find_task_by_vpid(pid);
	if (t)
		get_task_struct(t);
	rcu_read_unlock();
	if (!t)
		return false;
	hit = cmdline_match(t);
	put_task_struct(t);
	return hit;
}

static bool fd_is_proc(int fd)
{
	struct file *f;
	bool yes = false;

	if (fd < 0)
		return false;
	f = fget(fd);
	if (!f)
		return false;
	if (f->f_inode && f->f_inode->i_sb)
		yes = f->f_inode->i_sb->s_magic == PROC_SUPER_MAGIC;
	fput(f);
	return yes;
}

bool pidhide_name_hidden(const char *name)
{
	int pid = parse_pid(name);

	return pid > 1 && pidhide_has(pid);
}

static bool pidhide_abspath(const char *path)
{
	const char *rest;
	char buf[16];
	int i = 0, pid;

	if (strncmp(path, "/proc/", 6) != 0)
		return false;
	rest = path + 6;
	while (rest[i] && rest[i] != '/' && i < (int)sizeof(buf) - 1) {
		buf[i] = rest[i];
		i++;
	}
	buf[i] = 0;
	if (!i)
		return false;
	pid = parse_pid(buf);
	return pid > 1 && pidhide_has(pid);
}

bool pidhide_open_hidden(int dfd, const char __user *filename)
{
	char name[96];
	long n;

	if (!filename)
		return false;
	n = strncpy_from_user(name, filename, sizeof(name) - 1);
	if (n <= 0)
		return false;
	name[n] = 0;
	if (name[0] == '/')
		return pidhide_abspath(name);
	if (pidhide_name_hidden(name))
		return fd_is_proc(dfd);
	return false;
}

bool pidhide_pid_arg(int pid)
{
	return pidhide_has(pid);
}

long pidhide_filter_dirents(int fd, void __user *dirp, long nread)
{
	u8 *buf;
	long in = 0, out = 0;

	if (nread <= 0 || !fd_is_proc(fd))
		return nread;
	buf = kvmalloc(nread, GFP_KERNEL);
	if (!buf)
		return nread;
	if (copy_from_user(buf, dirp, nread)) {
		kvfree(buf);
		return nread;
	}
	while (in < nread) {
		struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + in);
		unsigned short reclen = d->d_reclen;

		if (reclen < offsetof(struct linux_dirent64, d_name) + 1 ||
		    in + reclen > nread)
			break;
		if (!pidhide_name_hidden(d->d_name)) {
			if (out != in)
				memmove(buf + out, buf + in, reclen);
			out += reclen;
		}
		in += reclen;
	}
	if (out != nread && copy_to_user(dirp, buf, out))
		out = nread;
	kvfree(buf);
	return out;
}

void pidhide_init(void)
{
	pidhide_apply_cmdlines(hide_cmdlines);
}

static int param_set_pidhide(const char *val, const struct kernel_param *kp)
{
	(void)kp;
	pidhide_apply_str(val);
	strscpy(pidhide_list, val ? val : "", sizeof(pidhide_list));
	return 0;
}

static int param_set_cmdlines(const char *val, const struct kernel_param *kp)
{
	(void)kp;
	pidhide_apply_cmdlines(val);
	strscpy(hide_cmdlines, val ? val : "", sizeof(hide_cmdlines));
	return 0;
}

static const struct kernel_param_ops pidhide_ops = {
	.set = param_set_pidhide,
	.get = param_get_string,
};

static const struct kernel_param_ops cmdline_ops = {
	.set = param_set_cmdlines,
	.get = param_get_string,
};

static struct kparam_string pidhide_kps = {
	.maxlen = sizeof(pidhide_list),
	.string = pidhide_list,
};

static struct kparam_string cmdline_kps = {
	.maxlen = sizeof(hide_cmdlines),
	.string = hide_cmdlines,
};

module_param_cb(hide_pids, &pidhide_ops, &pidhide_kps, 0600);
MODULE_PARM_DESC(hide_pids,
		 "comma-separated PIDs hidden from all /proc callers");

module_param_cb(hide_cmdlines, &cmdline_ops, &cmdline_kps, 0600);
MODULE_PARM_DESC(
	hide_cmdlines,
	"comma-separated cmdline substrings hidden from all /proc callers");
