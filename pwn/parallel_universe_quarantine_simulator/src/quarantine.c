#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static void print_menu(void)
{
	printf("1. wash hands\n");
	printf("2. order takeout\n");
	printf("3. play ctf\n");
	printf("4. shake hands with a stranger\n");
	printf("> ");
}

static int get_num(void)
{
	char buf[16] = { 0 };

	if (!fgets(buf, sizeof(buf), stdin)) {
		perror("fgets()");
		exit(EXIT_FAILURE);
	}

	return strtoul(buf, NULL, 10);
}

static uintptr_t get_addr(void)
{
	char buf[16] = { 0 };

	if (!fgets(buf, sizeof(buf), stdin)) {
		perror("fgets()");
		exit(EXIT_FAILURE);
	}

	return strtoull(buf, NULL, 16);
}

static __attribute__((optnone)) void wash_hands(void)
{
	size_t amount;
	char *soap;

	printf("How much soap? ");
	amount = get_num();
	if (amount > 2000000) {
		printf("Woah! Don't use up all the soap!\n");
		return;
	}

	soap = malloc(amount);
	printf("Successfully added soap!\n");
}

static void order(void)
{
	char input[1024];
	char order[1024];

	printf("What would you like to order? ");
	if (!fgets(input, sizeof(input), stdin)) {
		perror("fgets()");
		exit(EXIT_FAILURE);
	}

	char *ptr = strchr(input, '\n');
	if (ptr)
		*ptr = '\0';
	snprintf(order, sizeof(order),
		 "you ordered: %s\nit will arrive in ETA minutes\n", input);

	printf(order);
}

static void ctf(void)
{
	uintptr_t addr, value;

	printf("addr: ");
	addr = get_addr();

	printf("value: ");
	value = get_addr();

	*(void **)addr = (void *)value;
}

static void shake_hands(void)
{
	uintptr_t addr, res;

	printf("That sounds a bit risky...\n");
	addr = get_addr();

	res = *(uintptr_t *)addr;

	printf("This is the result: %p\n", (void *)res);
}

int main(void)
{
	int choice;

	setvbuf(stdout, NULL, _IONBF, 0);

	for (;;) {
		print_menu();
		choice = get_num();

		switch (choice) {
		case 1:
			wash_hands();
			break;
		case 2:
			order();
			break;
		case 3:
			ctf();
			break;
		case 4:
			shake_hands();
			break;
		case 5:
			printf("bye!\n");
			exit(EXIT_SUCCESS);
		default:
			printf("invalid choice: %d\n", choice);
			break;
		}
	}
	
	return 0;
}
