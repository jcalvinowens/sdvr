#pragma once

#include <stdarg.h>

#include "crypto.h"

const struct authkeypair *get_selfkeys(const char *fmt, ...);

const struct authpubkey *get_clientpk(const char *name);
int save_clientpk(const struct enckey *k, const char *name);
const struct authpubkey *get_serverpk(const char *name);
int save_serverpk(const struct enckey *k, const char *name);
