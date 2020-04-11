#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>

struct plant {
	char *buf;
	size_t size;
	uint16_t off_max;
};

static struct plant plants[3];

static void read_flag(void)
{
	void *map;
	int fd;

	fd = open("flag.txt", O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Couldn't open flag.txt!\n");
		exit(EXIT_FAILURE);
	}

	map = mmap(NULL, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		fprintf(stderr, "Couldn't mmap flag!\n");
		exit(EXIT_FAILURE);
	}

	close(fd);
}

static void menu(void)
{
	puts("1. add plant specimen");
	puts("2. read plant data");
	puts("3. read plant data at offset");
	puts("4. remove plant specimen");
	puts("5. exit");
	printf("> ");
}

static int get_num(void)
{
	char buf[16] = { 0 };

	if (!fgets(buf, sizeof(buf), stdin))
		exit(EXIT_FAILURE);

	return atoi(buf);
}

static struct plant *get_free_plant(void)
{
	for (size_t i = 0; i < 3; i++)
		if (!plants[i].buf)
			return &plants[i];
	return NULL;
}

static struct plant *get_plant(void)
{
	size_t idx;

	printf("index: ");
	idx = get_num();
	if (idx >= 3) {
		printf("invalid index!\n");
		return NULL;
	}

	if (!plants[idx].buf) {
		printf("invalid index %zu\n", idx);
		return NULL;
	}

	return &plants[idx];
}

static void add_plant(void)
{
	size_t size;
	struct plant *note;

	note = get_free_plant();
	if (!note) {
		printf("no more room!\n");
		return;
	}

	printf("size: ");
	size = get_num();
	if (size == 0 || size > 1000000) {
		printf("invalid size!\n");
		return;
	}

	note->buf = malloc(size + 1);
	if (!note->buf) {
		fprintf(stderr, "malloc() error!\n");
		exit(EXIT_FAILURE);
	}

	printf("data: ");
	read(STDIN_FILENO, note->buf, size);
	if (note->buf[size - 1] == '\n')
		note->buf[size - 1] = '\n';

	note->size = size;
	note->buf[size] = '\0';
	note->off_max = size > 0xffff ? 0xffff : size;
}

static void read_plant_data(void)
{
	struct plant *n; 

	n = get_plant();
	if (n)
		printf("%s\n", n->buf);
}

static void read_plant_data_offset(void)
{
	struct plant *n;
	size_t off;

	n = get_plant();
	if (n) {
		printf("offset: ");
		off = get_num();

		if ((uint16_t)off > n->off_max) {
			printf("invalid offset!\n");
			return;
		}

		printf("%s\n", &n->buf[off]);
	}
}

static void remove_plant(void)
{
	struct plant *n;

	n = get_plant();
	if (n) {
		free(n->buf);
		n->buf = NULL;
		n->size = 0;
	}
}

static void handler(int sig)
{
	(void)sig;
	exit(EXIT_SUCCESS);
}

int main(void)
{
	int choice;

	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	read_flag();
	signal(SIGALRM, handler);
	alarm(30);

	printf("Welcome to the TG:HACK herbarium!\n");
	printf("The place where you can store all your plant specimens\n");

	for (;;) {
		menu();
		choice = get_num();
		switch (choice) {
		case 1:
			add_plant();
			break;
		case 2:
			read_plant_data();
			break;
		case 3:
			read_plant_data_offset();
			break;
		case 4:
			remove_plant();
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
