#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "answers.h"

void read_line(char* buf, size_t size)
{
	fgets(buf, size, stdin);
	buf[strcspn(buf, "\n")] = '\0';
}

void q1()
{
	char captain[50] = { 0 };

	printf("Give me the captain's name?\n");
	read_line(captain, 50);

	if (strcmp(captain, answer_captain25) != 0) {
		exit(1);
	}
}

void q2()
{
	char starpower[50] = { 0 };

	printf("How much starpower does the Starfleet have?\n");
	read_line(starpower, 50);

	if (strcmp(starpower, answer_starpower58) != 0) {
		exit(1);
	}
}

void q3() 
{
	char year[50] = { 0 };

	printf("What year is this?\n");
	read_line(year, 10);

	if (strcmp(year, answer_year3) != 0) {
		exit(1);
	}
}

void q4()
{
	char cyber_weapon[50] = { 0 };

	printf("How many tonnes of cyber weapon is onboard on the main Starfleet?\n");
	read_line(cyber_weapon, 50);

	if (strcmp(cyber_weapon, answer_cyber_weapon96) != 0) {
		exit(1);
	}
}

void print_flag()
{
	printf("\n\nAccess granted. Take the secret message:\n");
	system("cat flag.txt");
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	printf("Welcome to the Combat Ship software...\n");
	printf("Please answer a few questions to access the system.\n");

	q1();
	q2();
	q3();
	q4();

	print_flag();

	return 0;
}
