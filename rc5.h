#pragma once

#include <stdint.h>

struct rc5_ctx;

const struct rc5_ctx *rc5_init(void);
uint32_t rc5_scramble(const struct rc5_ctx *ctx, uint32_t v);
uint32_t rc5_unscramble(const struct rc5_ctx *ctx, uint32_t v);
