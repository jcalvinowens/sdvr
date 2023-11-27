#pragma once

#define min(x, y) ({							\
	typeof(x) _min1 = (x);						\
	typeof(y) _min2 = (y);						\
	(void) (&_min1 == &_min2);					\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({							\
	typeof(x) _max1 = (x);						\
	typeof(y) _max2 = (y);						\
	(void) (&_max1 == &_max2);					\
	_max1 > _max2 ? _max1 : _max2; })

#define container_of(ptr, type, member) ({				\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);		\
	(type *)( (char *)__mptr - __builtin_offsetof(type,member) );})

#define S(x) #x
#define S_(x) S(x)
#define S__LN__ S_(__LINE__)
#define __log(...) do { fprintf(stderr, __VA_ARGS__); } while (0)
#define log(...) do { __log(__FILE__ ":" S__LN__ ": " __VA_ARGS__); } while (0)
#define err(...) do { log("ERROR: " __VA_ARGS__); } while (0)
#define fatal(...) do { log("FATAL: " __VA_ARGS__); abort(); } while (0)

#define BUG_ON(c) do { if (__builtin_expect(c, 0)) fatal(#c "\n"); } while (0)

#ifdef DEBUG
#define dbg(...) do { log(__VA_ARGS__); } while (0)
#else
#define dbg(...) do {} while (0)
#endif

#define static_assert(expr, ...) __static_assert(expr, ##__VA_ARGS__, #expr)
#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)

