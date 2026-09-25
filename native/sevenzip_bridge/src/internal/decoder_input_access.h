#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Random-access input capability exposed by SunPack archive streams to codec
 * hot paths. The stream pointer is the ISequentialInStream passed into 7-Zip.
 *
 * These calls never mutate the decoder-visible sequential cursor.
 */
int sunpack_input_random_access_size(
    void *stream,
    unsigned long long *size);

long sunpack_input_read_at(
    void *stream,
    unsigned long long offset,
    void *data,
    unsigned long size,
    unsigned long *processed);

#ifdef __cplusplus
}
#endif
