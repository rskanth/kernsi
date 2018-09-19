/*
 *
 * Filename: kernsi.c
 *
 * Description: Syscall intercept code for kernel module.
 *
 * Author: Rupavatharam, Sreekanth <rupavath@juniper.net>
 *
 * Copyright (c) 2018, Juniper Networks Inc.
 * All rights reserved.
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
MODULE_AUTHOR("rupavath");

unsigned long *ksi_syscall_table;

asmlinkage int (*original_write)(unsigned int, const char __user *, size_t);
asmlinkage int (*original_socket)(int, int, int);

asmlinkage int new_write(unsigned int fd, const char __user *buf, size_t count){
	//Hijacked write function here
//	printk("%s: %d\n", __func__, __LINE__);
	return (*original_write)(fd, buf, count);
}

asmlinkage int new_socket(int a, int b , int c)
{
	printk("%s - %s: %d\n", current->comm, __func__, __LINE__);
    	return (*original_socket)(a, b, c);
}

void
get_syscall_table(void)
{
	ksi_syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
	printk("ksi_syscall_table: %p\n", ksi_syscall_table);

}

static int kernsi_init_mod(void){

    	get_syscall_table();
	//Changing control bit to allow write
	write_cr0 (read_cr0 () & (~ 0x10000));

	original_write = (void *)ksi_syscall_table[__NR_write];
	original_socket = (void *)ksi_syscall_table[__NR_socket];
	if(ksi_syscall_table == NULL)
	    return -1;
	ksi_syscall_table[__NR_write] = (unsigned long) new_write;
	ksi_syscall_table[__NR_socket] = (unsigned long) new_socket;
	printk("Write system call old address: %p\n", original_write);
	printk("Write system call new address: %p\n", new_write);
	//Changing control bit back
	write_cr0 (read_cr0 () | 0x10000);
	return 0;
}

static void kernsi_exit_mod(void){
	//Cleanup
	write_cr0 (read_cr0 () & (~ 0x10000));
	ksi_syscall_table[__NR_write] = (unsigned long)original_write;
	ksi_syscall_table[__NR_socket] = (unsigned long)original_socket;
	write_cr0 (read_cr0 () | 0x10000);
	printk("Module exited cleanly");
	return;
}

module_init(kernsi_init_mod);
module_exit(kernsi_exit_mod);
