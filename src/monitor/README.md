## L-MVX monitor
This directory contains the code for the Intel MPK pkey switch gates and the code to use features like seccomp.

### Example to use L-MVX
Using `test/test.c` as an example. The `lmvx_init()/lmvx_start()/lmvx_end()` have to be inserted to the application source code. The application's object files have to be linked with a `liblmvx.so`, which contains the empty implementation of the `lmvx_*()` functions.

Without the runtime `LD_PRELOAD`, the application calls the empty `lmvx_*()` functions. To enable the L-MVX, we need to use: `LD_PRELOAD=./libmonitor.so ./test.bin`

```
#include "../inc/lmvx.h"

int main()
{
        /** lmvx library **/
        lmvx_init();

        /** lmvx library **/
        lmvx_start("simple_func", 1, getpid());
        simple_func(getpid());
        /** lmvx library **/
        lmvx_end();
}
```
