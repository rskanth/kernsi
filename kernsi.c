/*
 *
 * Filename: kernsi.c
 *
 * Description: Syscall intercept code for kernel module.
 *
 * Author: Rupavatharam, Sreekanth rskanth@yahoo.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


#include<linux/init.h>
#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/errno.h>
#include<linux/types.h>
#include<linux/unistd.h>
#include<asm/current.h>
#include<linux/sched.h>
#include<linux/syscalls.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("rskanth@yahoo.com");

unsigned long *ksi_syscall_table;

struct mysyscall {
	void *orig_ptr;
	void *new_ptr;
	int num_syscall;
};


void *get_orig_fn(int syscall);
asmlinkage int new_write(unsigned int fd, const char __user *buf, size_t count);
asmlinkage int new_socket(int domain, int type , int protocol);
static int kernsi_init_mod(void);
static void kernsi_exit_mod(void);

asmlinkage int new_write(unsigned int fd, const char __user *buf, size_t count)
{
	asmlinkage int (*original_write)(unsigned int, const char __user *, size_t);

	original_write = get_orig_fn(__NR_write);
	printk_ratelimited(KERN_INFO
				"write %s - fd: %d buf: %p count: %ld\n",
		current->comm, fd, buf, count);
	if(original_write)
		return (*original_write)(fd, buf, count);
	return -1;
}

asmlinkage int new_socket(int domain, int type , int protocol)
{
	asmlinkage int (*original_socket)(int, int, int);
	printk("%s - Domain: 0x%x, type: 0x%x, protocol: 0x%x\n", current->comm,
		domain, type, protocol);
	original_socket = get_orig_fn(__NR_socket);
	if(original_socket)
	    	return (*original_socket)(domain, type, protocol);
	return -1;
}

#define MAX_SYSCALLS 10 /* XXX */

/* Add the syscalls that you would want to hijack here */
struct mysyscall hijack_calls[MAX_SYSCALLS] = {
    				    { NULL, (void *)new_socket, __NR_socket},
	    			    { NULL, (void *)new_write, __NR_write},
			 	    { NULL, NULL, 0 },
		 		};

void *get_orig_fn(int syscall)
{
    	int i;
    	for(i=0;i<MAX_SYSCALLS;i++) {
	    if(hijack_calls[i].num_syscall == syscall)
		return hijack_calls[i].orig_ptr;
	}
	return NULL;
}

void get_syscall_table(void)
{
	ksi_syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
	printk("ksi_syscall_table: %p\n", ksi_syscall_table);

}


static int kernsi_init_mod(void)
{
	int i;
	struct mysyscall *entry;
    	get_syscall_table();
	if(ksi_syscall_table == NULL)
	    return -1;
	//Changing control bit to allow write
	write_cr0 (read_cr0 () & (~ 0x10000));
	for(i=0;i<MAX_SYSCALLS;i++) {
	    	entry = &hijack_calls[i];
		if(entry && entry->new_ptr != NULL) {
			entry->orig_ptr = (void *)ksi_syscall_table[entry->num_syscall];
			ksi_syscall_table[entry->num_syscall] = (unsigned long)entry->new_ptr;
			printk("Changing ptr for %d from %p --> %p\n", entry->num_syscall,
						entry->orig_ptr,
						entry->new_ptr);
		}

	}
	//Changing control bit back
	write_cr0 (read_cr0 () | 0x10000);
	return 0;
}

static void kernsi_exit_mod(void)
{
	struct mysyscall *entry;
	int i;

	//Cleanup
	write_cr0 (read_cr0 () & (~ 0x10000));
	for(i=0;i<MAX_SYSCALLS;i++) {
	    	entry = &hijack_calls[i];
		if(entry->orig_ptr) {
		    	printk("Restoring ptr for %d \n", entry->num_syscall);
			ksi_syscall_table[entry->num_syscall] =
			    	(unsigned long) entry->orig_ptr;

		}
	}
	write_cr0 (read_cr0 () | 0x10000);
	printk("Module exited cleanly");
	return;
}

module_init(kernsi_init_mod);
module_exit(kernsi_exit_mod);
