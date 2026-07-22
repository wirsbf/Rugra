#pragma once
#include <io.h>
#include <direct.h>
#include <sys/stat.h>
#define getcwd _getcwd
#define access _access
#define F_OK 0
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
