#include <stdio.h>
#include <sys/mman.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

static int my_errno = 0;
#define SYS_ERRNO my_errno
#include "linux-syscall-support/linux_syscall_support.h"

int _start(void)
{
	char *shellcode;
	ssize_t nread;
	void (*func)(void);

	shellcode = sys_mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
			     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (shellcode == MAP_FAILED) {
		sys_write(2, "mmap() error!\n", 14);
		sys_exit_group(EXIT_FAILURE);
	}

	nread = sys_read(STDIN_FILENO, shellcode, 0x1000);
	if (nread <= 0) {
		sys_write(2, "error reading shellcode!\n", 25);
		sys_exit_group(EXIT_FAILURE);
	}

	func = (void (*)(void))shellcode;
	func();

	sys_exit_group(EXIT_SUCCESS);
	/* not reached */
	return 0;
}
