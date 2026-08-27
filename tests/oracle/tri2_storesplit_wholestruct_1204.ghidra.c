/* ---- 0x1049a0: progressbarinit (90 bytes) ---- */

void progressbarinit(ProgressData *bar)

{
  char *__nptr;
  long lVar1;
  
  bar->total = 0;
  bar->prev = 0;
  bar->point = 0;
  bar->width = 0;
  *(undefined4 *)&bar->field_0x1c = 0;
  __nptr = (char *)curl_getenv("COLUMNS");
  if (__nptr != (char *)0x0) {
    lVar1 = strtol(__nptr,(char **)0x0,10);
    bar->width = (int)lVar1;
    free(__nptr);
    return;
  }
  bar->width = 0x4f;
  return;
}


/* ---- 0x104a00: hugehelp (84 bytes) ---- */


/* ---- 0x103460: my_fwrite (92 bytes) ---- */

int my_fwrite(void *buffer,size_t size,size_t nmemb,FILE *stream)

{
  size_t sVar1;
  FILE *__s;
  
  __s = (FILE *)stream->_IO_read_ptr;
  if (__s == (FILE *)0x0) {
    __s = fopen(*(char **)stream,"wb");
    stream->_IO_read_ptr = (char *)__s;
    if (__s == (FILE *)0x0) {
      return -1;
    }
  }
  sVar1 = fwrite(buffer,size,nmemb,__s);
  return (int)sVar1;
}
