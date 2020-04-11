#ifndef INSTRUCTIONS_H
#define INSTRUCTIONS_H
#include <stdint.h>
#include <stdlib.h>

enum instruction {
	COMPILE_ENCRYPTION_ENGINE = 0,
	LOAD_ENCRYPTION_ENGINE = 1,
	INIT_ENCRYPTION_ENGINE = 2,
	CONNECT_AND_SEND = 3,
	ENCRYPT_DATA = 4,
	GET_ENTROPY = 5,
	LOAD_DATA = 6,
	SET_SHIFTL_SET_TMP = 7,
	SET_SHIFTR_SET_TMP = 8,
	SET_XOR_SET_TMP = 9,
	SET_ADD_SET_TMP = 10,
	SET_SUB_SET_TMP = 11,
	SET_SHIFTL_TMP = 12,
	SET_SHIFTR_TMP = 13,
	SET_XOR_TMP = 14,
	SET_ADD_TMP = 15,
	SET_SUB_TMP = 16,
	SET_SHIFTL = 17,
	SET_SHIFTR = 18,
	SET_XOR = 19,
	SET_ADD = 20,
	SET_SUB = 21,
	VM_STOP = 22,
	ILLEGAL_START_ONLY = 0xa4,
};

#include "vm.h"

void load_data(FILE *f, uint8_t *buf, size_t num);
void connect_and_send(const char *url, const char *data);
void get_entropy(uint8_t *buf);
void load_encryption_engine(struct engine **engine);
void set_xor_set_tmp(struct engine *engine, size_t arg);
void set_shiftl_set_tmp(struct engine *engine, size_t arg);
void set_shiftr_set_tmp(struct engine *engine, size_t arg);
void set_add_set_tmp(struct engine *engine, size_t arg);
void set_sub_set_tmp(struct engine *engine, size_t arg);
void set_xor_tmp(struct engine *engine);
void set_shiftl_tmp(struct engine *engine);
void set_shiftr_tmp(struct engine *engine);
void set_add_tmp(struct engine *engine);
void set_sub_tmp(struct engine *engine);
void set_xor(struct engine *engine, size_t arg);
void set_shiftl(struct engine *engine, size_t arg);
void set_shiftr(struct engine *engine, size_t arg);
void set_add(struct engine *engine, size_t arg);
void set_sub(struct engine *engine, size_t arg);
void compile_encryption_engine(struct engine *engine);
void init_encryption_engine(struct engine *engine, uint8_t *init);
void encrypt_data(struct engine *engine, uint8_t *data);

#endif // INSTRUCTIONS_H
