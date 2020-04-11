#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Random numbers and words for obfuscation? */
const int part1 = 42;
const char* part2 = "1337";

void print_flag()
{
	char *ret_val;
	char buffer [100];
	FILE *file;

	file = fopen("flag.txt","r");
	ret_val = fgets(buffer, 100, file);

	if (ret_val != NULL) {
		puts(buffer);
	}

	fclose(file);
	return;
}

void start()
{
	char password[32];
	char input[32];

	puts("Combat Ship software starting...\n");
	puts("Please enter password: ");

	fgets(input, 32, stdin);
	input[strcspn(input, "\n")] = '\0';

	snprintf(password, 32, "%d %s", part1, part2);

	if(strcmp(password, input) == 0) {
		puts("Access granted.\n Take this secret message:\n");
		print_flag();
	} else {
		puts("YOU DIED!");
		exit(0);
	}
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	start();

	return 0;
}
