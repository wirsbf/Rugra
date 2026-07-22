#pragma once
typedef struct DIR DIR;
struct dirent { char d_name[260]; int d_type; };
#define DT_DIR 4
#define DT_UNKNOWN 0
#define DT_LNK 10
DIR *opendir(const char *name);
struct dirent *readdir(DIR *dir);
int closedir(DIR *dir);
