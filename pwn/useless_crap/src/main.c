#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <seccomp.h>

static void sandbox(void)
{
	scmp_filter_ctx ctx;

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (!ctx) {
		puts("seccomp_init() error");
		exit(EXIT_FAILURE);
	}

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1,
			 SCMP_A0(SCMP_CMP_EQ, 0));
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
			 SCMP_A0(SCMP_CMP_EQ, 1));
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);

	if (seccomp_load(ctx) < 0) {
		seccomp_release(ctx);
		puts("seccomp_load() error");
		exit(EXIT_FAILURE);
	}

	seccomp_release(ctx);
}

static void handler(int sig)
{
	(void)sig;
	exit(EXIT_SUCCESS);
}

static void init(void)
{
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
#if 1
	alarm(60);
	signal(SIGALRM, handler);
#endif
}

static void menu(void)
{
	puts("1. read");
	puts("2. write");
	puts("3. exit");
}

static int get_num(void)
{
	char buf[16] = { 0 };

	if (!fgets(buf, sizeof(buf), stdin))
		exit(EXIT_FAILURE);

	return (int)strtol(buf, NULL, 10);
}

static int read_count = 0;
static int write_count = 0;

static void empty_newline(void)
{
	while (getchar() != '\n')
		;
}

static void do_read(void)
{
	uint64_t addr, value;

	if (read_count > 1) {
		puts("No more reads for you!");
		return;
	}

	printf("addr: ");
	scanf("%lx", &addr);
	empty_newline();

	value = *(uint64_t *)addr;
	printf("value: %p\n", (void *)value);

	++read_count;
}

static void do_write(void)
{
	uint64_t addr, value;

	if (write_count > 1) {
		puts("No more writes for you!");
		return;
	}

	printf("addr/value: ");
	scanf("%lx %lx", &addr, &value);
	empty_newline();
	*(uint64_t *)addr = value;

	++write_count;
}

static char *feedback;
#define FEEDBACK_SIZE 0x500

static void leave_feedback(void)
{
	char c;

	if (feedback) {
		puts("that's enough feedback for one day...");
		return;
	}

	feedback = calloc(1, FEEDBACK_SIZE + 1);

	printf("feedback: ");
	if (!fgets(feedback, FEEDBACK_SIZE, stdin))
		exit(EXIT_FAILURE);

	printf("you entered: %s\n", feedback);
	puts("Do you want to keep your feedback? (y/n)");

	c = getchar();
	empty_newline();
	
	if (c == 'y')
		return;
	else if (c == 'n')
		free(feedback);
}

static void view_feedback(void)
{
	if (!feedback) {
		puts("Leave feedback first!");
		return;
	}

	printf("feedback: %s\n", feedback);
}

/*
 * plan:
 * leak stdin
 * change stdin pointer to overwrite read/write count
 * shellcode has to close stdin, open flag, dump it to stdout
 */
int main(void)
{
	int choice;

	init();
	sandbox();

	for (;;) {
		menu();
		printf("> ");
		choice = get_num();

		switch (choice) {
		case 1:
			do_read();
			break;
		case 2:
			do_write();
			break;
		case 3:
			leave_feedback();
			break;
		case 4:
			view_feedback();
			break;
		case 5:
			exit(EXIT_SUCCESS);
		default:
			printf("Invalid choice: %d\n", choice);
			break;
		}
	}

	return 0;
}
