# kernsi
Syscall intercept in  Linux kernel

This is a prototype(Work in progress) to show how you can intercept a system call inside the kernel and do additional processing before handing it off to the original handler of the system call. One could potentially build an equivalent of 'Packet filter' for System calls. 
  It could also be used to add/change the data supplied to the system calls and influence the output. E.g., you can add some extra bytes of data in send() system call. IT can also modify the output of a system call after it has been called(E.g., add extra bytes in a read system call)
One of the more commonly used method to hijack system calls is the LD_PRELOAD method. This loads a custom library that take over the system call and modifies the input/output. However, LD_PRELOAD method will not work with statically compiled applications.
