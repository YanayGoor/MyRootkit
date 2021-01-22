#include <stdio.h>
#include <stdarg.h> 

#include "utils.h"

void mrklog(const char *format, ...) {
    va_list a_list;
    va_start(a_list, format);

    using_color(COLOR_GRAY) {
        vprintf(format, a_list);
    }
}

void mrklogcrit(const char *format, ...) {
    va_list a_list;
    va_start(a_list, format);

    using_color(COLOR_CYAN) {
        vprintf(format, a_list);
    }
}

int __utils_color_console(const char *color) {
    printf("\033[%s", color);
    return 0;
}

void __utils_reset_color(int *i) {
    printf("\033[0m");
    fflush(stdout);
    (*i)++;
}

