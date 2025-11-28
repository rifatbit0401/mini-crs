#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void parse_message(const uint8_t *data, size_t size);
void fuzz_entry(const uint8_t *data, size_t size);
void unchecked_format(const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif
