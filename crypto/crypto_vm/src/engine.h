#ifndef ENGINE_H
#define ENGINE_H
#include <stdint.h>
#include <stdlib.h>

struct engine {
	uint16_t state;
	uint16_t tmp;
	void (**instructions)(struct engine*, size_t);
	size_t *args;
	size_t ip;
	size_t cycles;
};

void engine_xor_set_tmp(struct engine *engine, size_t arg);
void engine_shiftl_set_tmp(struct engine *engine, size_t arg);
void engine_shiftr_set_tmp(struct engine *engine, size_t arg);
void engine_add_set_tmp(struct engine *engine, size_t arg);
void engine_sub_set_tmp(struct engine *engine, size_t arg);
void engine_xor_tmp(struct engine *engine, __attribute((unused))size_t _unused);
void engine_shiftl_tmp(struct engine *engine, __attribute((unused))size_t _unused);
void engine_shiftr_tmp(struct engine *engine, __attribute((unused))size_t _unused);
void engine_add_tmp(struct engine *engine, __attribute((unused))size_t _unused);
void engine_sub_tmp(struct engine *engine, __attribute((unused))size_t _unused);
void engine_xor(struct engine *engine, size_t arg);
void engine_shiftl(struct engine *engine, size_t arg);
void engine_shiftr(struct engine *engine, size_t arg);
void engine_add(struct engine *engine, size_t arg);
void engine_sub(struct engine *engine, size_t arg);

void engine_del(struct engine *engine);
void engine_new(struct engine *engine);
#endif // ENGINE_H
