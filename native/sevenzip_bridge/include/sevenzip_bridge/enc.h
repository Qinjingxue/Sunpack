#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct sup_enc_decoder sup_enc_decoder;
typedef ptrdiff_t (*sup_enc_read)(void *, uint8_t *, size_t);
typedef int (*sup_enc_seek)(void *, uint64_t);
typedef int (*sup_enc_write)(void *, const uint8_t *, size_t);
typedef int (*sup_enc_progress)(void *, uint64_t);
typedef uint32_t (*sup_enc_acquire)(void *, uint32_t);
typedef void (*sup_enc_release)(void *, uint32_t);
int sup_enc_open(void *, sup_enc_read, sup_enc_seek, uint64_t, const uint16_t *, size_t, sup_enc_decoder **, uint64_t *, sup_enc_acquire, sup_enc_release);
int sup_enc_decrypt(const sup_enc_decoder *, void *, sup_enc_read, sup_enc_seek, sup_enc_write, sup_enc_progress, sup_enc_acquire, sup_enc_release);
void sup_enc_close(sup_enc_decoder *);
#ifdef __cplusplus
}
namespace sunpack::sevenzip {
constexpr unsigned char kEncFormatId = 0xFB;
}
#endif
