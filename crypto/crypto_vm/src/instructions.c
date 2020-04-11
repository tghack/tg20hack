#include <sys/types.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "engine.h"
#include "instructions.h"
#include "vm.h"

void load_data(FILE *f, uint8_t *buf, size_t num)
{
	buf[0] = num;
	fread(buf+1, num, 1, f);
	// Decrypt the encrypted string
	for (size_t i = num-1; i > 0; i--) {
		buf[i+1] ^= buf[i];
	}
	buf[1] ^= LOAD_DATA;
}

void connect_and_send(const char *url, const char *data)
{
	char hostname[64] = { 0 };
	short port = 0;
	sscanf(url+1, "%[^:]:%hu", hostname, &port);

	char *data_hex = calloc(2*data[0]+1, 1);
	for (int i = 0; i < data[0]; i++) {
		snprintf(&data_hex[i*2], 3, "%02x", (uint8_t)(data[i+1]));
	}

	struct hostent *h =gethostbyname(hostname);
	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	memcpy(&saddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
	saddr.sin_port = htons(port);

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(sock, (struct sockaddr*)&saddr, sizeof(saddr)) == 0) {
		write(sock, data_hex, data[0]*2);
		close(sock);
		printf("Successfully connected and sent data\n");
	} else {
		printf("Failed to connect and send data\n");
	}
	free(data_hex);
}

void get_entropy(uint8_t *buf)
{
	getrandom(buf, 2, GRND_RANDOM);
}

void load_encryption_engine(struct engine **engine)
{
	*engine = calloc(sizeof(**engine), 1);
	engine_new(*engine);
}

void set_xor_set_tmp(struct engine *engine, size_t arg)
{
	engine->instructions[engine->ip] = engine_xor_set_tmp;
	engine->args[engine->ip] = arg;

	engine->ip++;
}

void set_shiftl_set_tmp(struct engine *engine, size_t arg)
{
	engine->instructions[engine->ip] = engine_shiftl_set_tmp;
	engine->args[engine->ip] = arg;

	engine->ip++;
}

void set_shiftr_set_tmp(struct engine *engine, size_t arg)
{
	engine->instructions[engine->ip] = engine_shiftr_set_tmp;
	engine->args[engine->ip] = arg;

	engine->ip++;
}

void set_add_set_tmp(struct engine *engine, size_t arg)
{
	engine->instructions[engine->ip] = engine_add_set_tmp;
	engine->args[engine->ip] = arg;

	engine->ip++;
}

void set_sub_set_tmp(struct engine *engine, size_t arg)
{
	engine->instructions[engine->ip] = engine_sub_set_tmp;
	engine->args[engine->ip] = arg;

	engine->ip++;
}

void set_xor_tmp(struct engine *engine)
{
	engine->instructions[engine->ip++] = engine_xor_tmp;
}

void set_shiftl_tmp(struct engine *engine)
{
	engine->instructions[engine->ip++] = engine_shiftl_tmp;
}

void set_shiftr_tmp(struct engine *engine)
{
	engine->instructions[engine->ip++] = engine_shiftr_tmp;
}

void set_add_tmp(struct engine *engine)
{
	engine->instructions[engine->ip++] = engine_add_tmp;
}

void set_sub_tmp(struct engine *engine)
{
	engine->instructions[engine->ip++] = engine_sub_tmp;
}

void set_xor(struct engine *engine, size_t arg)
{
	engine->instructions[engine->ip] = engine_xor;
	engine->args[engine->ip] = arg;

	engine->ip++;
}

void set_shiftl(struct engine *engine, size_t arg)
{
	engine->instructions[engine->ip] = engine_shiftl;
	engine->args[engine->ip] = arg;

	engine->ip++;
}

void set_shiftr(struct engine *engine, size_t arg)
{
	engine->instructions[engine->ip] = engine_shiftr;
	engine->args[engine->ip] = arg;

	engine->ip++;
}

void set_add(struct engine *engine, size_t arg)
{
	engine->instructions[engine->ip] = engine_add;
	engine->args[engine->ip] = arg;

	engine->ip++;
}

void set_sub(struct engine *engine, size_t arg)
{
	engine->instructions[engine->ip] = engine_sub;
	engine->args[engine->ip] = arg;

	engine->ip++;
}

void compile_encryption_engine(struct engine *engine)
{
	engine->ip = 0;
	engine->cycles = 0;
}

void init_encryption_engine(struct engine *engine, uint8_t *init)
{
	engine->ip = 0;
	engine->cycles = 0;
	memcpy(&engine->state, init, sizeof(engine->state));
}

void encrypt_data(struct engine *engine, uint8_t *data)
{
	size_t num_bytes = data[0];
	data = data + 1;

	// Encrypt all the bytes of plaintext
	for (size_t i = 0; i < num_bytes; i++) {
		// Execute all rounds of the created engine once
		while (engine->instructions[engine->ip] != NULL) {
			engine->instructions[engine->ip](engine,
							 engine->args[engine->ip]);
			engine->ip++;
			engine->cycles++;
		}
		// Encrypt the byte with the next instruction
		data[i] ^= engine->state;
		engine->ip = 0;
	}
}
