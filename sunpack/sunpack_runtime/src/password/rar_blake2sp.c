#include "Blake2.h"

/* Keep the vendored structure layout and alignment private to C. */
void sunpack_blake2sp_run(void *context, void (*run)(void *, void *))
{
    CBlake2sp state;
    Blake2sp_Init(&state);
    run(context, &state);
}
