#include <cstddef>
#include <cstdint>

#include "vuln_lib.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Drive multiple vulnerable paths with the same input to expose diverse bugs.
  fuzz_entry(data, size);
  if (size > 2) {
    // Slight mutation to exercise different branches.
    uint8_t flipped[512];
    size_t copy = size < sizeof(flipped) ? size : sizeof(flipped);
    for (size_t i = 0; i < copy; ++i) {
      flipped[i] = data[i] ^ 0x5A;
    }
    fuzz_entry(flipped, copy);
  }
  return 0;
}
