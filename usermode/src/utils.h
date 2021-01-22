#ifndef UTILS_H
#define UTILS_H

#define COLOR_CYAN ("36m")
#define COLOR_GRAY ("30;1m")

void mrklog(const char *format, ...);
void mrklogcrit(const char *format, ...);

int __utils_color_console(const char *color);
void __utils_reset_color(int *i);

#define using_color(color) for (int i = __utils_color_console(color); i < 1; __utils_reset_color(&i))


#endif