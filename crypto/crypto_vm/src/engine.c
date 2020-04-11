#include "engine.h"

void engine_xor_set_tmp(struct engine *engine, size_t arg)
{
	engine->tmp = engine->state ^ arg;
}

void engine_shiftl_set_tmp(struct engine *engine, size_t arg)
{
	engine->tmp = engine->state << arg;
}

void engine_shiftr_set_tmp(struct engine *engine, size_t arg)
{
	engine->tmp = engine->state >> arg;
}

void engine_add_set_tmp(struct engine *engine, size_t arg)
{
	engine->tmp = engine->state + arg;
}

void engine_sub_set_tmp(struct engine *engine, size_t arg)
{
	engine->tmp = engine->state - arg;
}


void engine_xor_tmp(struct engine *engine, __attribute((unused))size_t _unused)
{
	engine->state ^= engine->tmp;
}

void engine_shiftl_tmp(struct engine *engine, __attribute((unused))size_t _unused)
{
	engine->state <<= engine->tmp;
}

void engine_shiftr_tmp(struct engine *engine, __attribute((unused))size_t _unused)
{
	engine->state >>= engine->tmp;
}

void engine_add_tmp(struct engine *engine, __attribute((unused))size_t _unused)
{
	engine->state += engine->tmp;
}

void engine_sub_tmp(struct engine *engine, __attribute((unused))size_t _unused)
{
	engine->state -= engine->tmp;
}

void engine_xor(struct engine *engine, size_t arg)
{
	engine->state ^= arg;
}

void engine_shiftl(struct engine *engine, size_t arg)
{
	engine->state <<= arg;
}

void engine_shiftr(struct engine *engine, size_t arg)
{
	engine->state >>= arg;
}

void engine_add(struct engine *engine, size_t arg)
{
	engine->state += arg;
}

void engine_sub(struct engine *engine, size_t arg)
{
	engine->state -= arg;
}

void engine_new(struct engine *engine)
{
	engine->instructions = calloc(sizeof(*(engine->instructions)), 128);
	engine->args = calloc(sizeof(*(engine->args)), 128);
	engine->state = 0;
	engine->tmp = 0;
	engine->ip = 0;
}

void engine_del(struct engine *engine)
{
	free(engine->instructions);
	free(engine->args);
	free(engine);
}
