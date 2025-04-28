#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>

int check_char_n(char chr) {
    if (chr != 'n') {
        return 0;
    }
    return 1;
}

int check_char_e(char chr) {
    if (chr != 'e') {
        return 0;
    }
    return 1;
}

int check_char_d(char chr) {
    if (chr != 'd') {
        return 0;
    }
    return 1;
}

int check_char_l(char chr) {
    if (chr != 'l') {
        return 0;
    }
    return 1;
}

void check(const char *buf) {
    int found;

    if ( check_char_n(buf[0]) && check_char_e(buf[1]) && 
        check_char_e(buf[2]) && check_char_d(buf[3]) && 
        check_char_l(buf[4]) && check_char_e(buf[5]) ) {
            /* If the needle has an H, hang so we can show timeouts.*/
            if ( buf[6] == 'H') {
                for(;;);
            }
            raise(SIGSEGV);
    } 
    return;
}

#ifdef MAKE_DLL
#ifdef __cplusplus
__declspec(dllexport) __declspec(noinline) extern "C" int LLVMFuzzerTestOneInput( const unsigned char *input, size_t size ) {
#else 
__declspec(dllexport) __declspec(noinline) int LLVMFuzzerTestOneInput( const unsigned char *input, size_t size ) {
#endif
#else
#ifdef __cplusplus
__declspec(noinline) extern "C" int LLVMFuzzerTestOneInput( const unsigned char *input, size_t size ) {
#else 
__declspec(noinline) int LLVMFuzzerTestOneInput( const unsigned char *input, size_t size ) {
#endif
#endif

    char safeBuffer[8];

    if ( size < 8 ) {
        memset( safeBuffer, 0, sizeof(safeBuffer));
        memcpy( safeBuffer,input,size);
        check((char *)safeBuffer);
    } else {
        check((char *)input);
    }
    return 0;
}
