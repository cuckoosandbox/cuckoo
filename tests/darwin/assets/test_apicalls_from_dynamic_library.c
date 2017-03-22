#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

int main(int argc, char const *argv[])
{
    void *h = dlopen("libruby.dylib", RTLD_LAZY);
    if (h == NULL) {
        return EXIT_FAILURE;
    } else {
        int (*rb_isalpha)(int) = dlsym(h, "rb_isalpha");
        int char_a = 0x61;
        return rb_isalpha(char_a) ? EXIT_SUCCESS : EXIT_FAILURE;
    }
}
