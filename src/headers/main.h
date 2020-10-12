#ifndef MAIN_H
#define MAIN_H

int hide_file(const char *path_name);
int unhide_file(const char *path_name);

int hide_process(const char *exec_file_path);
int unhide_process(const char *exec_file_path);

void MRK_exit(void);

#endif  /* MAIN_H */
