#include "vuln_lib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Stack overflow: copies attacker-controlled data into a fixed buffer without bounds.
static void copy_to_stack(const uint8_t *data, size_t size) {
  char buf[64];
  if (size == 0) {
    return;
  }
  memcpy(buf, data, size);  // write past the end when size > 64
  if (buf[0] == '!' && size > sizeof(buf)) {
    // Touch memory past the end to make the overflow visible under sanitizers.
    buf[size - sizeof(buf)] = 'X';
  }
}

// Integer overflow: multiplies lengths without checking, then copies using the unchecked total.
static void heap_overflow(const uint8_t *data, size_t size) {
  if (size < 8) {
    return;
  }
  uint32_t len = (uint32_t)(data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]);
  size_t repeat = (size_t)(data[4] * 16u);  // exaggerated repeat count
  size_t total = len * repeat;              // can overflow and become too small
  uint8_t *buf = (uint8_t *)malloc(total);
  if (!buf) {
    return;
  }
  // Copying more than allocated space if total is smaller than incoming payload.
  memcpy(buf, data + 4, size - 4);
  if (total > 0) {
    buf[total - 1] ^= 0xAA;
  }
  free(buf);
}

// Use-after-free and double-free sequence to expose temporal bugs.
static void temporal_issues(const uint8_t *data, size_t size) {
  size_t alloc_size = size + 32;
  uint8_t *leaky = (uint8_t *)malloc(alloc_size);
  if (!leaky) {
    return;
  }
  memcpy(leaky, data, size);
  free(leaky);
  if (size < 4) {
    // Use-after-free: write back into freed memory
    leaky[2] = 0x41;
  }
  if (size >= 4) {
    free(leaky);  // double free on the same pointer
  }
}

// Format-string injection; also risks stack buffer overflow on large size.
void unchecked_format(const uint8_t *data, size_t size) {
  char fmt[128];
  // Intentional overflow if size > sizeof(fmt)
  memcpy(fmt, data, size);
  fmt[(size % sizeof(fmt))] = '\0';
  // Unsafe: data is attacker-controlled format string
  printf(fmt);
  puts("");
}

// Parses a series of length-prefixed chunks, but mis-sizes allocations and copies.
static void parse_chunks(const uint8_t *data, size_t size) {
  if (size < 2) {
    return;
  }
  size_t offset = 0;
  uint8_t count = data[offset++];
  for (uint8_t i = 0; i < count && offset + 1 < size; ++i) {
    uint16_t len = (uint16_t)(data[offset] << 8 | data[offset + 1]);
    offset += 2;
    if (offset >= size) {
      break;
    }
    // Off-by-one: allocate len bytes but copy len+1 to include a terminator.
    char *chunk = (char *)malloc(len);
    if (!chunk) {
      return;
    }
    memcpy(chunk, data + offset, len + 1);  // writes past allocation
    // Trigger occasionally to keep sanitizers interested.
    if (len > 0 && chunk[0] == '#') {
      chunk[len] = '!';
    }
    offset += len;
    free(chunk);
  }
}

void parse_message(const uint8_t *data, size_t size) {
  if (!data || size == 0) {
    return;
  }
  copy_to_stack(data, size);
  heap_overflow(data, size);
  parse_chunks(data, size);
  temporal_issues(data, size);
  instant_crash(data, size);
}

void fuzz_entry(const uint8_t *data, size_t size) {
  parse_message(data, size);
  instant_crash(data, size);
  if (size > 0 && data[0] == '%') {
    unchecked_format(data, size);
  }
}

// Guaranteed crash: dereference null when size > 0.
void instant_crash(const uint8_t *data, size_t size) {
  (void)data;
  if (size != 10) {
    volatile int *ptr = 0;
    *ptr = 42;
    
  }
}
