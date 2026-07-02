/* ---- 0x102000: _init (27 bytes) ---- */

int _init(EVP_PKEY_CTX *ctx)

{
  undefined *puVar1;
  
  puVar1 = PTR___gmon_start___00116fe8;
  if (PTR___gmon_start___00116fe8 != (undefined *)0x0) {
    puVar1 = (undefined *)(*(code *)PTR___gmon_start___00116fe8)();
  }
  return (int)puVar1;
}


/* ---- 0x102020: FUN_00102020 (13 bytes) ---- */

void FUN_00102020(void)

{
  (*(code *)PTR_00116e78)();
  return;
}


/* ---- 0x1022e0: FUN_001022e0 (11 bytes) ---- */

void FUN_001022e0(void)

{
  (*(code *)PTR___cxa_finalize_00116ff8)();
  return;
}


/* ---- 0x1022f0: free (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void free(void *__ptr)

{
  (*(code *)PTR_free_00116e80)();
  return;
}


/* ---- 0x102300: __vfprintf_chk (11 bytes) ---- */

void __vfprintf_chk(void)

{
  (*(code *)PTR___vfprintf_chk_00116e88)();
  return;
}


/* ---- 0x102310: strcpy (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * strcpy(char *__dest,char *__src)

{
  char *pcVar1;
  
  pcVar1 = (char *)(*(code *)PTR_strcpy_00116e90)();
  return pcVar1;
}


/* ---- 0x102320: puts (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int puts(char *__s)

{
  int iVar1;
  
  iVar1 = (*(code *)PTR_puts_00116e98)();
  return iVar1;
}


/* ---- 0x102330: isatty (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int isatty(int __fd)

{
  int iVar1;
  
  iVar1 = (*(code *)PTR_isatty_00116ea0)();
  return iVar1;
}


/* ---- 0x102340: curl_easy_perform (11 bytes) ---- */

void curl_easy_perform(void)

{
  (*(code *)PTR_curl_easy_perform_00116ea8)();
  return;
}


/* ---- 0x102350: curl_slist_append (11 bytes) ---- */

void curl_slist_append(void)

{
  (*(code *)PTR_curl_slist_append_00116eb0)();
  return;
}


/* ---- 0x102360: fclose (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int fclose(FILE *__stream)

{
  int iVar1;
  
  iVar1 = (*(code *)PTR_fclose_00116eb8)();
  return iVar1;
}


/* ---- 0x102370: strlen (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

size_t strlen(char *__s)

{
  size_t sVar1;
  
  sVar1 = (*(code *)PTR_strlen_00116ec0)();
  return sVar1;
}


/* ---- 0x102380: __stack_chk_fail (11 bytes) ---- */

void __stack_chk_fail(void)

{
  (*(code *)PTR___stack_chk_fail_00116ec8)();
  return;
}


/* ---- 0x102390: strchr (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * strchr(char *__s,int __c)

{
  char *pcVar1;
  
  pcVar1 = (char *)(*(code *)PTR_strchr_00116ed0)();
  return pcVar1;
}


/* ---- 0x1023a0: strrchr (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * strrchr(char *__s,int __c)

{
  char *pcVar1;
  
  pcVar1 = (char *)(*(code *)PTR_strrchr_00116ed8)();
  return pcVar1;
}


/* ---- 0x1023b0: maprintf (11 bytes) ---- */

void maprintf(void)

{
  (*(code *)PTR_maprintf_00116ee0)();
  return;
}


/* ---- 0x1023c0: fputc (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int fputc(int __c,FILE *__stream)

{
  int iVar1;
  
  iVar1 = (*(code *)PTR_fputc_00116ee8)();
  return iVar1;
}


/* ---- 0x1023d0: fgets (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * fgets(char *__s,int __n,FILE *__stream)

{
  char *pcVar1;
  
  pcVar1 = (char *)(*(code *)PTR_fgets_00116ef0)();
  return pcVar1;
}


/* ---- 0x1023e0: strtol (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

long strtol(char *__nptr,char **__endptr,int __base)

{
  long lVar1;
  
  lVar1 = (*(code *)PTR_strtol_00116ef8)();
  return lVar1;
}


/* ---- 0x1023f0: memcpy (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void * memcpy(void *__dest,void *__src,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = (void *)(*(code *)PTR_memcpy_00116f00)();
  return pvVar1;
}


/* ---- 0x102400: time (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

time_t time(time_t *__timer)

{
  time_t tVar1;
  
  tVar1 = (*(code *)PTR_time_00116f08)();
  return tVar1;
}


/* ---- 0x102410: fileno (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int fileno(FILE *__stream)

{
  int iVar1;
  
  iVar1 = (*(code *)PTR_fileno_00116f10)();
  return iVar1;
}


/* ---- 0x102420: __xstat (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int __xstat(int __ver,char *__filename,stat *__stat_buf)

{
  int iVar1;
  
  iVar1 = (*(code *)PTR___xstat_00116f18)();
  return iVar1;
}


/* ---- 0x102430: malloc (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void * malloc(size_t __size)

{
  void *pvVar1;
  
  pvVar1 = (void *)(*(code *)PTR_malloc_00116f20)();
  return pvVar1;
}


/* ---- 0x102440: __isoc99_sscanf (11 bytes) ---- */

void __isoc99_sscanf(void)

{
  (*(code *)PTR___isoc99_sscanf_00116f28)();
  return;
}


/* ---- 0x102450: curl_easy_init (11 bytes) ---- */

void curl_easy_init(void)

{
  (*(code *)PTR_curl_easy_init_00116f30)();
  return;
}


/* ---- 0x102460: curl_getenv (11 bytes) ---- */

void curl_getenv(void)

{
  (*(code *)PTR_curl_getenv_00116f38)();
  return;
}


/* ---- 0x102470: realloc (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void * realloc(void *__ptr,size_t __size)

{
  void *pvVar1;
  
  pvVar1 = (void *)(*(code *)PTR_realloc_00116f40)();
  return pvVar1;
}


/* ---- 0x102480: __printf_chk (11 bytes) ---- */

void __printf_chk(void)

{
  (*(code *)PTR___printf_chk_00116f48)();
  return;
}


/* ---- 0x102490: curl_version (11 bytes) ---- */

void curl_version(void)

{
  (*(code *)PTR_curl_version_00116f50)();
  return;
}


/* ---- 0x1024a0: curl_slist_free_all (11 bytes) ---- */

void curl_slist_free_all(void)

{
  (*(code *)PTR_curl_slist_free_all_00116f58)();
  return;
}


/* ---- 0x1024b0: fopen (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

FILE * fopen(char *__filename,char *__modes)

{
  FILE *pFVar1;
  
  pFVar1 = (FILE *)(*(code *)PTR_fopen_00116f60)();
  return pFVar1;
}


/* ---- 0x1024c0: strcat (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * strcat(char *__dest,char *__src)

{
  char *pcVar1;
  
  pcVar1 = (char *)(*(code *)PTR_strcat_00116f68)();
  return pcVar1;
}


/* ---- 0x1024d0: curl_easy_setopt (11 bytes) ---- */

void curl_easy_setopt(void)

{
  (*(code *)PTR_curl_easy_setopt_00116f70)();
  return;
}


/* ---- 0x1024e0: curl_getdate (11 bytes) ---- */

void curl_getdate(void)

{
  (*(code *)PTR_curl_getdate_00116f78)();
  return;
}


/* ---- 0x1024f0: exit (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void exit(int __status)

{
  (*(code *)PTR_exit_00116f80)();
  return;
}


/* ---- 0x102500: fwrite (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

size_t fwrite(void *__ptr,size_t __size,size_t __n,FILE *__s)

{
  size_t sVar1;
  
  sVar1 = (*(code *)PTR_fwrite_00116f88)();
  return sVar1;
}


/* ---- 0x102510: __fprintf_chk (11 bytes) ---- */

void __fprintf_chk(void)

{
  (*(code *)PTR___fprintf_chk_00116f90)();
  return;
}


/* ---- 0x102520: curl_easy_cleanup (11 bytes) ---- */

void curl_easy_cleanup(void)

{
  (*(code *)PTR_curl_easy_cleanup_00116f98)();
  return;
}


/* ---- 0x102530: strdup (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * strdup(char *__s)

{
  char *pcVar1;
  
  pcVar1 = (char *)(*(code *)PTR_strdup_00116fa0)();
  return pcVar1;
}


/* ---- 0x102540: strequal (11 bytes) ---- */

void strequal(void)

{
  (*(code *)PTR_strequal_00116fa8)();
  return;
}


/* ---- 0x102550: curl_formparse (11 bytes) ---- */

void curl_formparse(void)

{
  (*(code *)PTR_curl_formparse_00116fb0)();
  return;
}


/* ---- 0x102560: strstr (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * strstr(char *__haystack,char *__needle)

{
  char *pcVar1;
  
  pcVar1 = (char *)(*(code *)PTR_strstr_00116fb8)();
  return pcVar1;
}


/* ---- 0x102570: strnequal (11 bytes) ---- */

void strnequal(void)

{
  (*(code *)PTR_strnequal_00116fc0)();
  return;
}


/* ---- 0x102580: __ctype_b_loc (11 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

ushort ** __ctype_b_loc(void)

{
  ushort **ppuVar1;
  
  ppuVar1 = (ushort **)(*(code *)PTR___ctype_b_loc_00116fc8)();
  return ppuVar1;
}


/* ---- 0x102590: __sprintf_chk (11 bytes) ---- */

void __sprintf_chk(void)

{
  (*(code *)PTR___sprintf_chk_00116fd0)();
  return;
}


/* ---- 0x1025a0: main (3510 bytes) ---- */

int main(int argc,char **argv)

{
  char cVar1;
  long lVar2;
  bool bVar3;
  URLGlob glob;
  int iVar4;
  int iVar5;
  Configurable *pCVar6;
  char *pcVar7;
  char *pcVar8;
  char *pcVar9;
  char *pcVar10;
  char *pcVar11;
  FILE *__stream;
  char *pcVar12;
  Configurable *config;
  long lVar13;
  ulong uVar14;
  OutStruct *pOVar15;
  int iVar16;
  URLGlob *pUVar17;
  undefined8 *puVar18;
  FILE *__stream_00;
  long in_FS_OFFSET;
  bool bVar19;
  byte bVar20;
  undefined1 auVar21 [24];
  undefined1 auVar22 [24];
  undefined1 auVar23 [24];
  undefined1 auVar24 [24];
  undefined1 auVar25 [24];
  undefined1 auVar26 [24];
  undefined1 auVar27 [24];
  undefined1 auVar28 [24];
  undefined1 in_stack_fffffffffffffc78 [280];
  undefined8 in_stack_fffffffffffffd90;
  char *in_stack_fffffffffffffd98;
  undefined8 uVar29;
  int local_230;
  int urlnum;
  URLGlob *urls;
  OutStruct outs;
  OutStruct heads;
  ProgressData progressbar;
  stat fileinfo;
  bool errorbuffer [256];
  
  __stream = stdin;
  bVar20 = 0;
  lVar2 = *(long *)(in_FS_OFFSET + 0x28);
  outs.stream = (FILE *)stdout;
  pCVar6 = &::config;
  for (config = (Configurable *)0x26; config != (Configurable *)0x0;
      config = (Configurable *)&config[-1].field_0x12f) {
    pCVar6->useragent = (char *)0x0;
    pCVar6 = (Configurable *)&pCVar6->cookie;
  }
  pCVar6 = (Configurable *)curl_version();
  ::config.useragent = (char *)maprintf();
  ::config.showerror = true;
  ::config.conf = 0;
  if (argc < 2) {
    iVar4 = parseconfig((char *)0x0,pCVar6);
    if (iVar4 != 0) goto LAB_00102728;
    pcVar12 = ::config.url;
    if (::config.url == (char *)0x0) {
      helpf((char *)0x0);
      iVar4 = 2;
      goto LAB_00102728;
    }
  }
  else {
    pCVar6 = (Configurable *)argv[1];
    iVar4 = strnequal(&DAT_001062f8,pCVar6,2);
    if ((iVar4 == 0) && (*argv[1] == '-')) {
      pCVar6 = (Configurable *)0x71;
      pcVar12 = strchr(argv[1],0x71);
      if (pcVar12 == (char *)0x0) goto LAB_00102651;
    }
    else {
LAB_00102651:
      iVar4 = parseconfig((char *)0x0,pCVar6);
      if (iVar4 != 0) goto LAB_00102728;
    }
    pcVar12 = (char *)0x0;
    iVar16 = 1;
    bVar3 = true;
    do {
      if (bVar3) {
        pcVar11 = argv[iVar16];
        if (*pcVar11 != '-') goto LAB_00102688;
        iVar4 = strequal(&DAT_001062f8);
        if (iVar4 != 0) {
          iVar16 = iVar16 + 1;
          if (iVar16 < argc) {
            bVar3 = false;
            goto LAB_00102688;
          }
          break;
        }
        pcVar7 = (char *)0x0;
        if (iVar16 < argc + -1) {
          pcVar7 = argv[(long)iVar16 + 1];
        }
        iVar4 = getparameter(pcVar11 + 1,pcVar7,(bool *)&progressbar,config);
        if (iVar4 != 0) goto LAB_00102728;
        if ((char)progressbar.total != '\0') {
          iVar16 = iVar16 + 1;
        }
      }
      else {
LAB_00102688:
        if (pcVar12 != (char *)0x0) {
          helpf("only one URL is supported!\n");
          iVar4 = 2;
          goto LAB_00102728;
        }
        pcVar12 = argv[iVar16];
      }
      iVar16 = iVar16 + 1;
    } while (iVar16 < argc);
    if ((pcVar12 == (char *)0x0) && (pcVar12 = ::config.url, ::config.url == (char *)0x0)) {
      helpf("no URL specified!\n");
      iVar4 = 2;
      goto LAB_00102728;
    }
  }
  iVar4 = glob_url(&urls,pcVar12,&urlnum);
  pcVar12 = ::config.outfile;
  if (iVar4 == 0) {
    bVar3 = false;
    if ((::config.outfile == (char *)0x0) && (::config.remotefile == false)) {
      bVar3 = 1 < urlnum;
    }
    iVar4 = 0;
    iVar16 = 0;
    pcVar11 = (char *)0x0;
    __stream_00 = (FILE *)0x0;
    local_230 = -1;
    while( true ) {
      uVar29 = 0x1027da;
      pcVar7 = next_url(urls);
      if (pcVar7 == (char *)0x0) break;
      if (pcVar12 != (char *)0x0) {
        uVar29 = 0x1027ff;
        ::config.outfile = strdup(pcVar12);
      }
      if (::config.outfile == (char *)0x0) {
        if (::config.remotefile != false) {
LAB_0010282a:
          pcVar8 = strstr(pcVar7,"://");
          ::config.outfile = pcVar8 + 3;
          if (pcVar8 == (char *)0x0) {
            ::config.outfile = pcVar7;
          }
          pcVar8 = strrchr(::config.outfile,0x2f);
          if (pcVar8 == (char *)0x0) {
            ::config.outfile = (char *)0x0;
          }
          else {
            ::config.outfile = pcVar8 + 1;
            if (pcVar8[1] != '\0') goto LAB_00102873;
          }
          helpf("Remote file name has no length!\n");
          iVar4 = 0x17;
          goto LAB_00102728;
        }
      }
      else {
        if (::config.infile != (char *)0x0) {
          helpf("you can\'t both upload and download!\n");
          iVar4 = 2;
          goto LAB_00102728;
        }
        if (::config.remotefile != false) goto LAB_0010282a;
        pUVar17 = urls;
        puVar18 = (undefined8 *)&stack0xfffffffffffffc78;
        for (lVar13 = 0x26; lVar13 != 0; lVar13 = lVar13 + -1) {
          *puVar18 = pUVar17->literal[0];
          pUVar17 = (URLGlob *)((long)pUVar17 + (ulong)bVar20 * -0x10 + 8);
          puVar18 = puVar18 + (ulong)bVar20 * -2 + 1;
        }
        glob.pattern[8].content.Set.elements = (char **)in_stack_fffffffffffffd90;
        auVar21 = in_stack_fffffffffffffc78._80_24_;
        auVar22 = in_stack_fffffffffffffc78._104_24_;
        auVar23 = in_stack_fffffffffffffc78._128_24_;
        auVar24 = in_stack_fffffffffffffc78._152_24_;
        auVar25 = in_stack_fffffffffffffc78._176_24_;
        auVar26 = in_stack_fffffffffffffc78._200_24_;
        auVar27 = in_stack_fffffffffffffc78._224_24_;
        auVar28 = in_stack_fffffffffffffc78._248_24_;
        glob.literal[0] = (char *)in_stack_fffffffffffffc78._0_8_;
        glob.literal[1] = (char *)in_stack_fffffffffffffc78._8_8_;
        glob.literal[2] = (char *)in_stack_fffffffffffffc78._16_8_;
        glob.literal[3] = (char *)in_stack_fffffffffffffc78._24_8_;
        glob.literal[4] = (char *)in_stack_fffffffffffffc78._32_8_;
        glob.literal[5] = (char *)in_stack_fffffffffffffc78._40_8_;
        glob.literal[6] = (char *)in_stack_fffffffffffffc78._48_8_;
        glob.literal[7] = (char *)in_stack_fffffffffffffc78._56_8_;
        glob.literal[8] = (char *)in_stack_fffffffffffffc78._64_8_;
        glob.literal[9] = (char *)in_stack_fffffffffffffc78._72_8_;
        glob.pattern[0].type = auVar21._0_4_;
        glob.pattern[0]._4_4_ = auVar21._4_4_;
        glob.pattern[0].content = (anon_union_16_3_e2f18bb4_for_content)auVar21._8_16_;
        glob.pattern[1].type = auVar22._0_4_;
        glob.pattern[1]._4_4_ = auVar22._4_4_;
        glob.pattern[1].content = (anon_union_16_3_e2f18bb4_for_content)auVar22._8_16_;
        glob.pattern[2].type = auVar23._0_4_;
        glob.pattern[2]._4_4_ = auVar23._4_4_;
        glob.pattern[2].content = (anon_union_16_3_e2f18bb4_for_content)auVar23._8_16_;
        glob.pattern[3].type = auVar24._0_4_;
        glob.pattern[3]._4_4_ = auVar24._4_4_;
        glob.pattern[3].content = (anon_union_16_3_e2f18bb4_for_content)auVar24._8_16_;
        glob.pattern[4].type = auVar25._0_4_;
        glob.pattern[4]._4_4_ = auVar25._4_4_;
        glob.pattern[4].content = (anon_union_16_3_e2f18bb4_for_content)auVar25._8_16_;
        glob.pattern[5].type = auVar26._0_4_;
        glob.pattern[5]._4_4_ = auVar26._4_4_;
        glob.pattern[5].content = (anon_union_16_3_e2f18bb4_for_content)auVar26._8_16_;
        glob.pattern[6].type = auVar27._0_4_;
        glob.pattern[6]._4_4_ = auVar27._4_4_;
        glob.pattern[6].content = (anon_union_16_3_e2f18bb4_for_content)auVar27._8_16_;
        glob.pattern[7].type = auVar28._0_4_;
        glob.pattern[7]._4_4_ = auVar28._4_4_;
        glob.pattern[7].content = (anon_union_16_3_e2f18bb4_for_content)auVar28._8_16_;
        glob.pattern[8].type = in_stack_fffffffffffffc78._272_4_;
        glob.pattern[8]._4_4_ = in_stack_fffffffffffffc78._276_4_;
        glob.pattern[8].content._8_8_ = in_stack_fffffffffffffd98;
        glob._296_8_ = uVar29;
        ::config.outfile = match_url(::config.outfile,glob);
LAB_00102873:
        if (::config.resume_from == 0) {
          if (::config.use_resume != false) {
            iVar5 = __xstat(1,::config.outfile,(stat *)&fileinfo);
            if (iVar5 == 0) {
              ::config.resume_from = (int)fileinfo.st_size;
            }
            if (::config.resume_from != 0) goto LAB_00102883;
          }
          outs.stream = (FILE *)0x0;
          outs.filename = ::config.outfile;
        }
        else {
LAB_00102883:
          outs.stream = (FILE *)fopen(::config.outfile,"ab");
          if ((FILE *)outs.stream == (FILE *)0x0) {
            helpf("Can\'t open \'%s\'!\n",::config.outfile);
            iVar4 = 0x17;
            goto LAB_00102728;
          }
        }
      }
      pcVar8 = ::config.infile;
      if (::config.infile != (char *)0x0) {
        pcVar9 = strstr(pcVar7,"://");
        pcVar10 = pcVar9 + 3;
        if (pcVar9 == (char *)0x0) {
          pcVar10 = pcVar7;
        }
        pcVar10 = strrchr(pcVar10,0x2f);
        if (pcVar10 == (char *)0x0) {
          lVar13 = -1;
          pcVar11 = pcVar7;
          do {
            if (lVar13 == 0) break;
            lVar13 = lVar13 + -1;
            cVar1 = *pcVar11;
            pcVar11 = pcVar11 + (ulong)bVar20 * -2 + 1;
          } while (cVar1 != '\0');
          uVar14 = 0xffffffffffffffff;
          pcVar11 = pcVar8;
          do {
            if (uVar14 == 0) break;
            uVar14 = uVar14 - 1;
            cVar1 = *pcVar11;
            pcVar11 = pcVar11 + (ulong)bVar20 * -2 + 1;
          } while (cVar1 != '\0');
          pcVar11 = (char *)malloc(~uVar14 - lVar13);
          if (pcVar11 == (char *)0x0) {
LAB_0010334e:
            helpf("out of memory\n");
            iVar4 = 0x1b;
            goto LAB_00102728;
          }
          pcVar10 = "%s/%s";
LAB_00102923:
          __sprintf_chk(pcVar11,1,0xffffffffffffffff,pcVar10,pcVar7,pcVar8);
          pcVar8 = ::config.infile;
          pcVar7 = pcVar11;
        }
        else if (pcVar10[1] == '\0') {
          lVar13 = -1;
          pcVar11 = pcVar7;
          do {
            if (lVar13 == 0) break;
            lVar13 = lVar13 + -1;
            cVar1 = *pcVar11;
            pcVar11 = pcVar11 + (ulong)bVar20 * -2 + 1;
          } while (cVar1 != '\0');
          uVar14 = 0xffffffffffffffff;
          pcVar11 = pcVar8;
          do {
            if (uVar14 == 0) break;
            uVar14 = uVar14 - 1;
            cVar1 = *pcVar11;
            pcVar11 = pcVar11 + (ulong)bVar20 * -2 + 1;
          } while (cVar1 != '\0');
          pcVar11 = (char *)malloc(~uVar14 - lVar13);
          if (pcVar11 == (char *)0x0) goto LAB_0010334e;
          pcVar10 = "%s%s";
          goto LAB_00102923;
        }
        __stream = fopen(pcVar8,"rb");
        if ((__stream == (FILE *)0x0) ||
           (iVar5 = __xstat(1,::config.infile,(stat *)&fileinfo), iVar5 != 0)) {
          helpf("Can\'t open \'%s\'!\n",::config.infile);
          iVar4 = 0x1a;
          goto LAB_00102728;
        }
        local_230 = (int)fileinfo.st_size;
      }
      if ((((::config.conf & 0x4000U) != 0) && (::config.use_resume != false)) &&
         (::config.resume_from == 0)) {
        ::config.resume_from = -1;
      }
      if (::config.headerfile == (char *)0x0) {
        bVar19 = __stream_00 == (FILE *)0x0;
      }
      else if ((*::config.headerfile == '-') && (::config.headerfile[1] == '\0')) {
        bVar19 = stdout == (FILE *)0x0;
        __stream_00 = stdout;
        heads.stream = (FILE *)stdout;
      }
      else {
        __stream_00 = (FILE *)0x0;
        bVar19 = true;
        heads.filename = ::config.headerfile;
        heads.stream = (FILE *)__stream_00;
      }
      if (outs.stream != (FILE *)0x0) {
        iVar5 = fileno((FILE *)outs.stream);
        iVar5 = isatty(iVar5);
        if ((iVar5 != 0) && ((::config.conf & 0x2004000U) == 0)) {
          ::config.conf = ::config.conf | 0x400;
        }
      }
      iVar16 = iVar16 + 1;
      if (1 < urlnum) {
        in_stack_fffffffffffffd98 = ::config.outfile;
        if (::config.outfile == (char *)0x0) {
          in_stack_fffffffffffffd98 = "<stdout>";
        }
        in_stack_fffffffffffffd90 = 0x102a69;
        __fprintf_chk(stderr,1,"\n[%d/%d]: %s --> %s\n",iVar16,urlnum,pcVar7);
        if (bVar3) {
          __printf_chk(1,"%s%s\n",&DAT_001062f0,pcVar7);
        }
      }
      if (::config.errors == (FILE *)0x0) {
        ::config.errors = stderr;
      }
      lVar13 = curl_easy_init();
      if (lVar13 == 0) {
        fwrite("curl: failed to init libcurl!\n",1,0x1e,(FILE *)::config.errors);
      }
      else {
        curl_easy_setopt(lVar13,0x2711,&outs);
        curl_easy_setopt(lVar13,0x4e2b,my_fwrite);
        curl_easy_setopt(lVar13,0x2719,__stream);
        curl_easy_setopt(lVar13,0xe,local_230);
        curl_easy_setopt(lVar13,0x2712,pcVar7);
        curl_easy_setopt(lVar13,0x2714,::config.proxy);
        curl_easy_setopt(lVar13,0x29,(uint)::config.conf & 0x20);
        curl_easy_setopt(lVar13,0x2a,(uint)::config.conf & 0x100);
        curl_easy_setopt(lVar13,0x2b,(uint)::config.conf & 0x400);
        curl_easy_setopt(lVar13,0x2c,(uint)::config.conf & 0x800);
        curl_easy_setopt(lVar13,0x2d,(uint)::config.conf & 0x1000);
        curl_easy_setopt(lVar13,0x2e,(uint)::config.conf & 0x4000);
        curl_easy_setopt(lVar13,0x2f,(uint)::config.conf & 0x8000);
        curl_easy_setopt(lVar13,0x30,(uint)::config.conf & 0x10000);
        curl_easy_setopt(lVar13,0x32,(uint)::config.conf & 0x100000);
        curl_easy_setopt(lVar13,0x33,(uint)::config.conf & 0x400000);
        curl_easy_setopt(lVar13,0x34,(uint)::config.conf & 0x800000);
        curl_easy_setopt(lVar13,0x35,(uint)::config.conf & 0x1000000);
        curl_easy_setopt(lVar13,0x36,(uint)::config.conf & 0x8000000);
        curl_easy_setopt(lVar13,0x37,(uint)::config.conf & 0x10000000);
        curl_easy_setopt(lVar13,0x2715,::config.userpwd);
        curl_easy_setopt(lVar13,0x2716,::config.proxyuserpwd);
        curl_easy_setopt(lVar13,0x2717,::config.range);
        curl_easy_setopt(lVar13,0x271a,errorbuffer);
        curl_easy_setopt(lVar13,0xd,::config.timeout);
        curl_easy_setopt(lVar13,0x271f,::config.postfields);
        curl_easy_setopt(lVar13,0x2720,::config.referer);
        curl_easy_setopt(lVar13,0x3a,(uint)::config.conf & 0x10);
        curl_easy_setopt(lVar13,0x2722,::config.useragent);
        curl_easy_setopt(lVar13,0x2721,::config.ftpport);
        curl_easy_setopt(lVar13,0x13,::config.low_speed_limit);
        curl_easy_setopt(lVar13,0x14,::config.low_speed_time);
        iVar4 = 0;
        if (::config.use_resume != false) {
          iVar4 = ::config.resume_from;
        }
        curl_easy_setopt(lVar13,0x15,iVar4);
        curl_easy_setopt(lVar13,0x2726,::config.cookie);
        curl_easy_setopt(lVar13,0x2727,::config.headers);
        curl_easy_setopt(lVar13,0x2728,::config.httppost);
        curl_easy_setopt(lVar13,0x2729,::config.cert);
        curl_easy_setopt(lVar13,0x272a,::config.cert_passwd);
        curl_easy_setopt(lVar13,0x1b,(int)::config.crlf);
        curl_easy_setopt(lVar13,0x272c,::config.quote);
        curl_easy_setopt(lVar13,0x2737,::config.postquote);
        pOVar15 = (OutStruct *)::config.headerfile;
        if (::config.headerfile != (char *)0x0) {
          pOVar15 = &heads;
        }
        curl_easy_setopt(lVar13,0x272d,pOVar15);
        curl_easy_setopt(lVar13,0x272f,::config.cookiefile);
        curl_easy_setopt(lVar13,0x20,::config.ssl_version);
        curl_easy_setopt(lVar13,0x21,::config.timecond);
        curl_easy_setopt(lVar13,0x22,::config.condtime);
        curl_easy_setopt(lVar13,0x2734,::config.customrequest);
        curl_easy_setopt(lVar13,0x2735,::config.errors);
        curl_easy_setopt(lVar13,0x2738,::config.writeout);
        if ((::config.progressmode == true) && ((::config.conf & 0x10000400U) == 0)) {
          progressbarinit(&progressbar);
          curl_easy_setopt(lVar13,0x4e58,myprogress);
          curl_easy_setopt(lVar13,0x2749,&progressbar);
        }
        iVar4 = curl_easy_perform(lVar13);
        curl_easy_cleanup(lVar13);
        if ((iVar4 != 0) && (::config.showerror != false)) {
          __fprintf_chk(::config.errors,1,"curl: (%d) %s\n",iVar4,errorbuffer);
        }
      }
      if ((::config.errors != stderr) && ((FILE *)::config.errors != stdout)) {
        fclose((FILE *)::config.errors);
      }
      if (((::config.headerfile != (char *)0x0) && (bVar19)) && (heads.stream != (FILE *)0x0)) {
        fclose((FILE *)heads.stream);
      }
      if (pcVar11 != (char *)0x0) {
        free(pcVar11);
      }
      if ((::config.outfile != (char *)0x0) && (outs.stream != (FILE *)0x0)) {
        fclose((FILE *)outs.stream);
      }
      if (::config.infile != (char *)0x0) {
        fclose(__stream);
      }
      if (__stream_00 != (FILE *)0x0) {
        fclose(__stream_00);
      }
      if (::config.url != (char *)0x0) {
        free(::config.url);
      }
      free(pcVar7);
      if ((::config.outfile != (char *)0x0) && (::config.remotefile == false)) {
        free(::config.outfile);
      }
    }
    curl_slist_free_all(::config.quote);
    curl_slist_free_all(::config.postquote);
    curl_slist_free_all(::config.headers);
  }
LAB_00102728:
  if (lVar2 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar4;
}


/* ---- 0x103370: _start (47 bytes) ---- */

void processEntry _start(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  (*(code *)PTR___libc_start_main_00116fe0)
            (main,param_2,&stack0x00000008,__libc_csu_init,__libc_csu_fini,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}


/* ---- 0x1033a0: deregister_tm_clones (34 bytes) ---- */

/* WARNING: Removing unreachable block (ram,0x001033b3) */
/* WARNING: Removing unreachable block (ram,0x001033bf) */

void deregister_tm_clones(void)

{
  return;
}


/* ---- 0x1033d0: register_tm_clones (51 bytes) ---- */

/* WARNING: Removing unreachable block (ram,0x001033f4) */
/* WARNING: Removing unreachable block (ram,0x00103400) */

void register_tm_clones(void)

{
  return;
}


/* ---- 0x103410: __do_global_dtors_aux (54 bytes) ---- */

void __do_global_dtors_aux(void)

{
  if (completed_8061 == '\0') {
    if (PTR___cxa_finalize_00116ff8 != (undefined *)0x0) {
      FUN_001022e0(__dso_handle);
    }
    deregister_tm_clones();
    completed_8061 = 1;
    return;
  }
  return;
}


/* ---- 0x103450: frame_dummy (9 bytes) ---- */

void frame_dummy(void)

{
  register_tm_clones();
  return;
}


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


/* ---- 0x1034d0: myprogress (477 bytes) ---- */

int myprogress(void *clientp,size_t dltotal,size_t dlnow,size_t ultotal,size_t ulnow)

{
  long lVar1;
  ulong uVar2;
  bool *pbVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  ulong uVar7;
  ulong uVar8;
  long in_FS_OFFSET;
  float fVar9;
  float fVar10;
  char format [40];
  bool line [256];
  bool outline [256];
  
  uVar8 = ulnow + dlnow;
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  *(ulong *)((long)clientp + 0x10) = uVar8;
  if (dltotal + ultotal == 0) {
    uVar2 = *(ulong *)((long)clientp + 8) >> 10;
    uVar4 = (uint)(uVar8 >> 10);
    uVar7 = uVar2 & 0xffffffff;
    if ((int)uVar4 <= (int)uVar2) goto LAB_0010353d;
    do {
      uVar6 = (int)uVar7 + 1;
      uVar7 = (ulong)uVar6;
      fputc(0x23,stderr);
    } while (uVar4 != uVar6);
  }
  else {
    fVar10 = (float)uVar8 / (float)(dltotal + ultotal);
    fVar9 = DAT_00107178 * fVar10;
    iVar5 = (int)(fVar10 * (float)(*(int *)((long)clientp + 0x18) + -7));
    if (iVar5 < 1) {
      iVar5 = 0;
    }
    else {
      pbVar3 = line;
      do {
        *pbVar3 = true;
        pbVar3 = pbVar3 + 1;
      } while (pbVar3 != line + (ulong)(iVar5 - 1) + 1);
    }
    line[iVar5] = false;
    __sprintf_chk(format,1,0x28,"%%-%ds %%5.1f%%%%");
    __sprintf_chk((double)fVar9,outline,1,0x100,format,line);
    __fprintf_chk(stderr,1,&DAT_001061d9,outline);
  }
  uVar8 = *(ulong *)((long)clientp + 0x10);
LAB_0010353d:
  *(ulong *)((long)clientp + 8) = uVar8;
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}


/* ---- 0x1036d0: GetStr (68 bytes) ---- */

void GetStr(char **string,char *value)

{
  char *pcVar1;
  
  if (*string != (char *)0x0) {
    free(*string);
  }
  if ((value != (char *)0x0) && (*value != '\0')) {
    pcVar1 = strdup(value);
    *string = pcVar1;
    return;
  }
  *string = (char *)0x0;
  return;
}


/* ---- 0x103720: my_get_token (241 bytes) ---- */

char * my_get_token(char *line)

{
  char cVar1;
  ushort **ppuVar2;
  char *pcVar3;
  size_t __n;
  
  if ((line == (char *)0x0) && (line = my_get_token::save, my_get_token::save == (char *)0x0)) {
    return (char *)0x0;
  }
  cVar1 = *line;
  if (cVar1 == '\0') {
    my_get_token::save = line;
    return (char *)0x0;
  }
  ppuVar2 = __ctype_b_loc();
  while ((*(byte *)((long)*ppuVar2 + (long)cVar1 * 2 + 1) & 0x20) != 0) {
    cVar1 = line[1];
    line = line + 1;
    if (cVar1 == '\0') {
      my_get_token::save = line;
      return (char *)0x0;
    }
  }
  cVar1 = *line;
  my_get_token::save = line;
  if (cVar1 == '\0') {
    return (char *)0x0;
  }
  do {
    if ((*(byte *)((long)*ppuVar2 + (long)cVar1 * 2 + 1) & 0x20) != 0) {
      cVar1 = *my_get_token::save;
      pcVar3 = my_get_token::save;
      while (cVar1 != '\0') {
        pcVar3 = pcVar3 + 1;
        cVar1 = *pcVar3;
      }
      __n = (long)pcVar3 - (long)line;
      goto joined_r0x001037b2;
    }
    cVar1 = my_get_token::save[1];
    my_get_token::save = my_get_token::save + 1;
  } while (cVar1 != '\0');
  __n = (long)my_get_token::save - (long)line;
joined_r0x001037b2:
  if (__n == 0) {
    return (char *)0x0;
  }
  pcVar3 = (char *)malloc(__n + 1);
  if (pcVar3 != (char *)0x0) {
    pcVar3 = (char *)memcpy(pcVar3,line,__n);
    pcVar3[__n] = '\0';
  }
  return pcVar3;
}


/* ---- 0x103840: my_get_line (308 bytes) ---- */

char * my_get_line(FILE *fp)

{
  long lVar1;
  bool *pbVar2;
  char *pcVar3;
  uint *__dest;
  uint *puVar4;
  uint *puVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint *puVar9;
  long in_FS_OFFSET;
  bool bVar10;
  bool buf [4096];
  
  __dest = (uint *)0x0;
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  do {
    pcVar3 = fgets(buf,0x1000,(FILE *)fp);
    if (pcVar3 == (char *)0x0) goto LAB_00103953;
    puVar9 = __dest;
    if (__dest == (uint *)0x0) {
      __dest = (uint *)strdup(buf);
    }
    else {
      do {
        puVar4 = puVar9;
        uVar6 = *puVar4 + 0xfefefeff & ~*puVar4;
        uVar7 = uVar6 & 0x80808080;
        puVar9 = puVar4 + 1;
      } while (uVar7 == 0);
      bVar10 = (uVar6 & 0x8080) == 0;
      if (bVar10) {
        uVar7 = uVar7 >> 0x10;
      }
      if (bVar10) {
        puVar9 = (uint *)((long)puVar4 + 6);
      }
      pbVar2 = buf;
      do {
        puVar4 = (uint *)pbVar2;
        uVar8 = *puVar4 + 0xfefefeff & ~*puVar4;
        uVar6 = uVar8 & 0x80808080;
        pbVar2 = (bool *)(puVar4 + 1);
      } while (uVar6 == 0);
      bVar10 = (uVar8 & 0x8080) == 0;
      if (bVar10) {
        uVar6 = uVar6 >> 0x10;
      }
      puVar5 = puVar4 + 1;
      if (bVar10) {
        puVar5 = (uint *)((long)puVar4 + 6);
      }
      __dest = (uint *)realloc(__dest,(long)puVar9 +
                                      (long)puVar5 +
                                      (-(long)__dest - (ulong)CARRY1((byte)uVar7,(byte)uVar7)) +
                                      ((-5 - (ulong)CARRY1((byte)uVar6,(byte)uVar6)) - (long)buf));
      if (__dest == (uint *)0x0) goto LAB_00103953;
      strcat((char *)__dest,buf);
    }
    pcVar3 = strchr((char *)__dest,10);
  } while (pcVar3 == (char *)0x0);
  *pcVar3 = '\0';
LAB_00103953:
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return (char *)__dest;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}


/* ---- 0x103980: helpf (267 bytes) ---- */

void helpf(char *fmt,...)

{
  long lVar1;
  char in_AL;
  undefined8 in_RCX;
  undefined8 in_RDX;
  undefined8 in_RSI;
  undefined8 in_R8;
  undefined8 in_R9;
  long in_FS_OFFSET;
  undefined8 in_XMM0_Qa;
  undefined8 in_XMM1_Qa;
  undefined8 in_XMM2_Qa;
  undefined8 in_XMM3_Qa;
  undefined8 in_XMM4_Qa;
  undefined8 in_XMM5_Qa;
  undefined8 in_XMM6_Qa;
  undefined8 in_XMM7_Qa;
  va_list ap;
  undefined1 local_b8 [8];
  undefined8 local_b0;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_78;
  undefined8 local_68;
  undefined8 local_58;
  undefined8 local_48;
  undefined8 local_38;
  undefined8 local_28;
  undefined8 local_18;
  
  if (in_AL != '\0') {
    local_88 = in_XMM0_Qa;
    local_78 = in_XMM1_Qa;
    local_68 = in_XMM2_Qa;
    local_58 = in_XMM3_Qa;
    local_48 = in_XMM4_Qa;
    local_38 = in_XMM5_Qa;
    local_28 = in_XMM6_Qa;
    local_18 = in_XMM7_Qa;
  }
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  local_b0 = in_RSI;
  local_a8 = in_RDX;
  local_a0 = in_RCX;
  local_98 = in_R8;
  local_90 = in_R9;
  if (fmt != (char *)0x0) {
    ap[0].overflow_arg_area = &stack0x00000008;
    ap[0].reg_save_area = local_b8;
    ap[0].gp_offset = 8;
    ap[0].fp_offset = 0x30;
    fwrite("curl: ",1,6,stderr);
    __vfprintf_chk(stderr,1,fmt,ap);
  }
  fwrite("curl: try \'curl --help\' for more information\n",1,0x2d,stderr);
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}


/* ---- 0x103a90: file2string (403 bytes) ---- */

char * file2string(FILE *file)

{
  bool *pbVar1;
  long lVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  char *pcVar6;
  char *__ptr;
  long lVar7;
  uint *puVar8;
  uint *puVar9;
  long lVar10;
  ulong uVar11;
  bool *pbVar12;
  undefined8 *puVar13;
  int iVar14;
  long in_FS_OFFSET;
  bool bVar15;
  byte bVar16;
  bool abStack_150 [8];
  bool buffer [256];
  
  bVar16 = 0;
  lVar7 = 0;
  __ptr = (char *)0x0;
  lVar2 = *(long *)(in_FS_OFFSET + 0x28);
  while( true ) {
    abStack_150[0] = true;
    abStack_150[1] = true;
    abStack_150[2] = true;
    abStack_150[3] = false;
    abStack_150[4] = false;
    abStack_150[5] = false;
    abStack_150[6] = false;
    abStack_150[7] = false;
    pcVar6 = fgets(buffer,0x100,(FILE *)file);
    if (pcVar6 == (char *)0x0) break;
    abStack_150[0] = true;
    abStack_150[1] = true;
    abStack_150[2] = true;
    abStack_150[3] = false;
    abStack_150[4] = false;
    abStack_150[5] = false;
    abStack_150[6] = false;
    abStack_150[7] = false;
    pcVar6 = strchr(buffer,0xd);
    if (pcVar6 != (char *)0x0) {
      *pcVar6 = '\0';
    }
    abStack_150[0] = true;
    abStack_150[1] = true;
    abStack_150[2] = true;
    abStack_150[3] = false;
    abStack_150[4] = false;
    abStack_150[5] = false;
    abStack_150[6] = false;
    abStack_150[7] = false;
    pcVar6 = strchr(buffer,10);
    pbVar1 = buffer;
    if (pcVar6 != (char *)0x0) {
      *pcVar6 = '\0';
      pbVar1 = buffer;
    }
    do {
      puVar8 = (uint *)pbVar1;
      uVar4 = *puVar8 + 0xfefefeff & ~*puVar8;
      uVar5 = uVar4 & 0x80808080;
      pbVar1 = (bool *)(puVar8 + 1);
    } while (uVar5 == 0);
    bVar15 = (uVar4 & 0x8080) == 0;
    if (bVar15) {
      uVar5 = uVar5 >> 0x10;
    }
    puVar9 = puVar8 + 1;
    if (bVar15) {
      puVar9 = (uint *)((long)puVar8 + 6);
    }
    lVar10 = (long)puVar9 + ((-3 - (ulong)CARRY1((byte)uVar5,(byte)uVar5)) - (long)buffer);
    iVar3 = (int)lVar10;
    iVar14 = (int)lVar7 + iVar3;
    if (__ptr == (char *)0x0) {
      abStack_150[0] = true;
      abStack_150[1] = true;
      abStack_150[2] = true;
      abStack_150[3] = false;
      abStack_150[4] = false;
      abStack_150[5] = false;
      abStack_150[6] = false;
      abStack_150[7] = false;
      __ptr = (char *)malloc((long)(iVar3 + 1));
    }
    else {
      abStack_150[0] = true;
      abStack_150[1] = true;
      abStack_150[2] = true;
      abStack_150[3] = false;
      abStack_150[4] = false;
      abStack_150[5] = false;
      abStack_150[6] = false;
      abStack_150[7] = false;
      __ptr = (char *)realloc(__ptr,(long)(iVar14 + 1));
    }
    uVar11 = lVar10 + 1;
    pbVar1 = (bool *)(__ptr + lVar7);
    uVar5 = (uint)uVar11;
    if (uVar5 < 8) {
      if ((uVar11 & 4) == 0) {
        if (uVar5 != 0) {
          *pbVar1 = buffer[0];
          if ((uVar11 & 2) != 0) {
            *(undefined2 *)(pbVar1 + ((uVar11 & 0xffffffff) - 2)) =
                 *(undefined2 *)(buffer + ((uVar11 & 0xffffffff) - 2));
          }
        }
      }
      else {
        *(undefined4 *)pbVar1 = buffer._0_4_;
        *(undefined4 *)(pbVar1 + ((uVar11 & 0xffffffff) - 4)) =
             *(undefined4 *)(buffer + ((uVar11 & 0xffffffff) - 4));
      }
    }
    else {
      *(ulong *)pbVar1 = CONCAT44(buffer._4_4_,buffer._0_4_);
      *(undefined8 *)(pbVar1 + ((uVar11 & 0xffffffff) - 8)) =
           *(undefined8 *)(buffer + ((uVar11 & 0xffffffff) - 8));
      lVar7 = (long)pbVar1 - (long)((ulong)(pbVar1 + 8) & 0xfffffffffffffff8);
      pbVar12 = buffer + -lVar7;
      puVar13 = (undefined8 *)((ulong)(pbVar1 + 8) & 0xfffffffffffffff8);
      for (uVar11 = (ulong)(uVar5 + (int)lVar7 >> 3); uVar11 != 0; uVar11 = uVar11 - 1) {
        *puVar13 = *(undefined8 *)pbVar12;
        pbVar12 = pbVar12 + ((ulong)bVar16 * -2 + 1) * 8;
        puVar13 = puVar13 + (ulong)bVar16 * -2 + 1;
      }
    }
    lVar7 = (long)iVar14;
  }
  if (lVar2 != *(long *)(in_FS_OFFSET + 0x28)) {
    abStack_150[0] = true;
    abStack_150[1] = true;
    abStack_150[2] = true;
    abStack_150[3] = false;
    abStack_150[4] = false;
    abStack_150[5] = false;
    abStack_150[6] = false;
    abStack_150[7] = false;
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return __ptr;
}


/* ---- 0x103c50: SetHTTPrequest (43 bytes) ---- */

int SetHTTPrequest(HttpReq req,HttpReq *store)

{
  fwrite("You can only select one HTTP request!\n",1,0x26,stderr);
  return 2;
}


/* ---- 0x103c80: parseconfig (633 bytes) ---- */

int parseconfig(char *filename,Configurable *config)

{
  long lVar1;
  char cVar2;
  int iVar3;
  size_t sVar4;
  FILE *__stream;
  char *line;
  char *nextarg;
  Configurable *in_RCX;
  char *__ptr;
  long in_FS_OFFSET;
  char *local_160;
  bool usedarg;
  bool filebuffer [256];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  if ((filename == (char *)0x0) || (*filename == '\0')) {
    local_160 = (char *)curl_getenv(&DAT_001061e4);
    if (local_160 == (char *)0x0) goto LAB_00103e4d;
    sVar4 = strlen(local_160);
    if (0xf9 < sVar4) {
      free(local_160);
      goto LAB_00103e4d;
    }
    filename = filebuffer;
    in_RCX = (Configurable *)&DAT_001061e9;
    __sprintf_chk(filename,1,0x100,&DAT_001061e9,local_160,&DAT_001062ac,".curlrc");
    if (filebuffer[0] == true) goto LAB_00103e8a;
LAB_00103d26:
    __stream = fopen(filename,"r");
  }
  else {
    local_160 = (char *)0x0;
    if (*filename != '-') goto LAB_00103d26;
LAB_00103e8a:
    __stream = stdin;
    if (((bool *)filename)[1] != false) goto LAB_00103d26;
  }
  if (__stream != (FILE *)0x0) {
    while (line = my_get_line((FILE *)__stream), line != (char *)0x0) {
      if ((*line != '#') && (nextarg = my_get_token(line), nextarg != (char *)0x0)) {
        __ptr = nextarg;
        if (*nextarg == '-') goto LAB_00103da8;
        if (::config.url != (char *)0x0) {
          free(::config.url);
        }
        cVar2 = *nextarg;
        ::config.url = nextarg;
        while (__ptr = nextarg, cVar2 == '-') {
LAB_00103da8:
          nextarg = my_get_token((char *)0x0);
          while (nextarg == (char *)0x0) {
            do {
              free(line);
              line = my_get_line((FILE *)__stream);
              if (line == (char *)0x0) {
                getparameter(__ptr + 1,(char *)0x0,&usedarg,in_RCX);
                free(__ptr);
                if (usedarg == false) goto LAB_00103ed3;
                line = (char *)0x0;
                nextarg = (char *)0x0;
                goto LAB_00103ec0;
              }
            } while (*line == '#');
            nextarg = my_get_token(line);
          }
          iVar3 = getparameter(__ptr + 1,nextarg,&usedarg,in_RCX);
          free(__ptr);
          if (usedarg != false) {
LAB_00103ec0:
            free(nextarg);
            break;
          }
          if (iVar3 != 0) break;
          cVar2 = *nextarg;
        }
      }
LAB_00103ed3:
      free(line);
    }
    if (__stream != stdin) {
      fclose(__stream);
    }
  }
  if (local_160 != (char *)0x0) {
    free(local_160);
  }
LAB_00103e4d:
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}


/* ---- 0x103f00: getparameter (2609 bytes) ---- */

int getparameter(char *flag,char *nextarg,bool *usedarg,Configurable *config)

{
  char cVar1;
  long lVar2;
  int iVar3;
  int iVar4;
  size_t sVar5;
  curl_slist *pcVar6;
  char *pcVar7;
  undefined8 uVar8;
  Configurable *pCVar9;
  Configurable *pCVar10;
  long lVar11;
  undefined **ppuVar12;
  Configurable *pCVar13;
  int iVar14;
  long in_FS_OFFSET;
  Configurable *local_5b8;
  HttpPost *local_5a8;
  time_t now;
  stat statbuf;
  LongShort aliases [50];
  
  iVar14 = -1;
  lVar2 = *(long *)(in_FS_OFFSET + 0x28);
  cVar1 = *flag;
  ppuVar12 = &PTR_DAT_00117020;
  pCVar13 = (Configurable *)aliases;
  for (lVar11 = 0x96; lVar11 != 0; lVar11 = lVar11 + -1) {
    pCVar13->useragent = (char *)*ppuVar12;
    ppuVar12 = ppuVar12 + 1;
    pCVar13 = (Configurable *)&pCVar13->cookie;
  }
  local_5a8 = (HttpPost *)flag;
  if (cVar1 == '-') {
    pcVar7 = flag + 1;
    sVar5 = strlen(pcVar7);
    local_5a8 = (HttpPost *)0x0;
    pCVar10 = (Configurable *)aliases;
    iVar4 = iVar14;
    iVar3 = 0;
    do {
      while( true ) {
        iVar14 = iVar3;
        pCVar13 = (Configurable *)pCVar10->cookie;
        iVar3 = strnequal(pCVar13,pcVar7,(long)(int)sVar5);
        if (iVar3 == 0) break;
        iVar4 = strequal();
        if (iVar4 != 0) {
          local_5a8 = (HttpPost *)aliases[iVar14].letter;
          goto LAB_00103f5b;
        }
        if (local_5a8 != (HttpPost *)0x0) {
          helpf("option --%s is ambiguous\n",pcVar7);
          iVar14 = 2;
          goto LAB_0010404b;
        }
        local_5a8 = (HttpPost *)pCVar10->useragent;
        pCVar10 = (Configurable *)&pCVar10->postfields;
        iVar4 = iVar14;
        iVar3 = iVar14 + 1;
        if (iVar14 + 1 == 0x32) goto LAB_00104184;
      }
      iVar3 = iVar14 + 1;
      pCVar10 = (Configurable *)&pCVar10->postfields;
      iVar14 = iVar4;
    } while (iVar3 != 0x32);
LAB_00104184:
    if (iVar14 == -1) {
      helpf("unknown option -%s.\n",flag);
      iVar14 = 2;
      goto LAB_0010404b;
    }
  }
LAB_00103f5b:
  local_5b8 = (Configurable *)nextarg;
  do {
    if (local_5a8 == (HttpPost *)0x0) {
      pCVar10 = (Configurable *)0x0;
    }
    else {
      pCVar10 = (Configurable *)(ulong)(uint)(int)*(char *)&local_5a8->next;
    }
    *usedarg = false;
    if (iVar14 == -1) {
      iVar14 = 0;
      pCVar9 = (Configurable *)aliases;
      while (*(char *)&((HttpPost *)pCVar9->useragent)->next != (char)pCVar10) {
        iVar14 = iVar14 + 1;
        pCVar9 = (Configurable *)&pCVar9->postfields;
        if (iVar14 == 0x32) {
          helpf("unknown option -%c.\n");
          goto LAB_001040d8;
        }
      }
    }
    if (local_5b8 == (Configurable *)0x0) {
      if (aliases[iVar14].extraparam != false) {
        helpf("option -%s/--%s requires an extra argument!\n",aliases[iVar14].letter,
              aliases[iVar14].lname);
        iVar14 = 2;
        goto LAB_0010404b;
      }
    }
    else if (aliases[iVar14].extraparam != false) {
      *usedarg = true;
    }
    switch((int)pCVar10 - 0x23U & 0xff) {
    case 0:
      ::config.progressmode = (bool)(::config.progressmode ^ 1);
      break;
    default:
      if ((char)pCVar10 == '\0') {
        helpf("Unknown option\n");
        iVar14 = 2;
      }
      else {
        helpf("Unknown option \'%c\'\n");
        iVar14 = 2;
      }
      goto LAB_0010404b;
    case 0xf:
      ::config.ssl_version = 2;
      break;
    case 0x10:
      ::config.ssl_version = 3;
      break;
    case 0x15:
      if ((*(char *)&local_5b8->useragent == '-') &&
         (*(char *)((long)&local_5b8->useragent + 1) == '\0')) {
        ::config.errors = stdout;
      }
      else {
        pCVar13 = local_5b8;
        ::config.errors = (FILE *)fopen((char *)local_5b8,"wt");
      }
      break;
    case 0x16:
      ::config.crlf = true;
      break;
    case 0x1e:
      pCVar13 = &::config;
      GetStr(&::config.useragent,(char *)local_5b8);
      break;
    case 0x1f:
      ::config.conf = ::config.conf ^ 0x1000000;
      break;
    case 0x20:
      pCVar13 = local_5b8;
      lVar11 = strtol((char *)local_5b8,(char **)0x0,10);
      ::config.use_resume = true;
      ::config.resume_from = (int)lVar11;
      break;
    case 0x21:
      pCVar13 = (Configurable *)&::config.headerfile;
      GetStr(&::config.headerfile,(char *)local_5b8);
      break;
    case 0x22:
      pcVar7 = strchr((char *)local_5b8,0x3a);
      if (pcVar7 != (char *)0x0) {
        *pcVar7 = '\0';
        GetStr(&::config.cert_passwd,pcVar7 + 1);
      }
      pCVar13 = (Configurable *)&::config.cert;
      GetStr(&::config.cert,(char *)local_5b8);
      break;
    case 0x23:
      pCVar10 = (Configurable *)&::config.httppost;
      pCVar13 = local_5b8;
      iVar14 = curl_formparse();
      if (iVar14 != 0) {
LAB_001040d8:
        iVar14 = 2;
        goto LAB_0010404b;
      }
      if ((::config.httpreq != HTTPREQ_POST) && (::config.httpreq != HTTPREQ_UNSPEC))
      goto LAB_00104736;
      ::config.httpreq = HTTPREQ_POST;
      break;
    case 0x25:
      pcVar6 = (curl_slist *)curl_slist_append();
      pCVar13 = (Configurable *)::config.headers;
      ::config.headers = pcVar6;
      break;
    case 0x26:
      ::config.conf = ::config.conf ^ 0x900;
      if ((::config.httpreq & ~HTTPREQ_HEAD) == HTTPREQ_UNSPEC) {
        ::config.httpreq = HTTPREQ_HEAD;
      }
      else {
LAB_00104736:
        iVar14 = SetHTTPrequest((HttpReq)pCVar13,(HttpReq *)pCVar10);
        if (iVar14 != 0) goto LAB_001040d8;
      }
      break;
    case 0x28:
      pCVar13 = local_5b8;
      iVar14 = parseconfig((char *)local_5b8,pCVar10);
      ::config.configread = true;
      if (iVar14 != 0) goto LAB_0010404b;
      break;
    case 0x29:
      ::config.conf = ::config.conf ^ 0x800000;
      break;
    case 0x2a:
      hugehelp();
      iVar14 = 2;
      goto LAB_0010404b;
    case 0x2b:
      ::config.nobuffer = (bool)(::config.nobuffer ^ 1);
      break;
    case 0x2c:
      ::config.remotefile = (bool)(::config.remotefile ^ 1);
      break;
    case 0x2d:
      pCVar13 = (Configurable *)&::config.ftpport;
      GetStr(&::config.ftpport,(char *)local_5b8);
      break;
    case 0x2e:
      if (*(char *)&local_5b8->useragent == '-') {
        local_5b8 = (Configurable *)((long)&local_5b8->useragent + 1);
        pcVar6 = (curl_slist *)curl_slist_append();
        pCVar13 = (Configurable *)::config.postquote;
        ::config.postquote = pcVar6;
      }
      else {
        pcVar6 = (curl_slist *)curl_slist_append();
        pCVar13 = (Configurable *)::config.quote;
        ::config.quote = pcVar6;
      }
      break;
    case 0x30:
      ::config.showerror = (bool)(::config.showerror ^ 1);
      break;
    case 0x31:
      pCVar13 = (Configurable *)&::config.infile;
      ::config.conf = ::config.conf | 0x4000;
      GetStr(&::config.infile,(char *)local_5b8);
      break;
    case 0x32:
      pCVar13 = (Configurable *)&::config.proxyuserpwd;
      GetStr(&::config.proxyuserpwd,(char *)local_5b8);
      break;
    case 0x33:
      uVar8 = curl_version();
      __printf_chk(1,"curl 7.1 (x86_64-pc-linux-gnu) %s\n",uVar8);
      iVar14 = 2;
      goto LAB_0010404b;
    case 0x35:
      pCVar13 = (Configurable *)&::config.customrequest;
      pCVar10 = local_5b8;
      GetStr(&::config.customrequest,(char *)local_5b8);
      if ((::config.httpreq != HTTPREQ_UNSPEC) && (::config.httpreq != HTTPREQ_CUSTOM))
      goto LAB_00104736;
      ::config.httpreq = HTTPREQ_CUSTOM;
      break;
    case 0x36:
      pCVar13 = local_5b8;
      lVar11 = strtol((char *)local_5b8,(char **)0x0,10);
      ::config.low_speed_limit = (int)lVar11;
      if (::config.low_speed_time == 0) {
        ::config.low_speed_time = 0x1e;
      }
      break;
    case 0x3e:
      ::config.conf = ::config.conf ^ 0x100000;
      break;
    case 0x3f:
      if (*(char *)&local_5b8->useragent == '@') {
        local_5b8 = (Configurable *)((long)&local_5b8->useragent + 1);
      }
      else {
        pcVar7 = strchr((char *)local_5b8,0x3d);
        if (pcVar7 != (char *)0x0) {
          pCVar13 = (Configurable *)&::config.cookie;
          GetStr(&::config.cookie,(char *)local_5b8);
          break;
        }
      }
      pCVar13 = (Configurable *)&::config.cookiefile;
      GetStr(&::config.cookiefile,(char *)local_5b8);
      break;
    case 0x40:
      ::config.use_resume = (bool)(::config.use_resume ^ 1);
      break;
    case 0x41:
      if (*(char *)&local_5b8->useragent == '@') {
        local_5b8 = (Configurable *)((long)&local_5b8->useragent + 1);
        pCVar13 = (Configurable *)&DAT_001062f9;
        pCVar10 = local_5b8;
        iVar14 = strequal();
        pCVar9 = stdin;
        if (iVar14 == 0) {
          pCVar10 = (Configurable *)0x1061c2;
          pCVar13 = local_5b8;
          pCVar9 = (Configurable *)fopen((char *)local_5b8,"r");
        }
        if (pCVar9 != (Configurable *)0x0) {
          ::config.postfields = file2string((FILE *)pCVar9);
          pCVar13 = stdin;
          if (pCVar9 != stdin) {
            fclose((FILE *)stdin);
          }
          goto LAB_00103ffe;
        }
        ::config.postfields = (char *)0x0;
      }
      else {
        pCVar13 = (Configurable *)&::config.postfields;
        pCVar10 = local_5b8;
        GetStr(&::config.postfields,(char *)local_5b8);
LAB_00103ffe:
        if (::config.postfields != (char *)0x0) {
          ::config.conf = ::config.conf | 0x8000;
        }
      }
      if ((::config.httpreq & ~HTTPREQ_SIMPLEPOST) != HTTPREQ_UNSPEC) goto LAB_00104736;
      ::config.httpreq = HTTPREQ_SIMPLEPOST;
      break;
    case 0x42:
      pcVar7 = strstr((char *)local_5b8,";auto");
      if (pcVar7 != (char *)0x0) {
        ::config.conf = ::config.conf | 0x10;
        *pcVar7 = '\0';
      }
      pCVar13 = (Configurable *)&::config.referer;
      GetStr(&::config.referer,(char *)local_5b8);
      break;
    case 0x43:
      ::config.conf = ::config.conf ^ 0x1000;
      break;
    case 0x45:
      uVar8 = curl_version();
      __printf_chk(1,
                   "curl 7.1 (x86_64-pc-linux-gnu) %s\nUsage: curl [options...] <url>\nOptions: (H) means HTTP/HTTPS only, (F) means FTP only\n -a/--append        Append to target file when uploading (F)\n -A/--user-agent <string> User-Agent to send to server (H)\n -b/--cookie <name=string/file> Cookie string or file to read cookies from (H)\n -B/--use-ascii     Use ASCII/text transfer\n -c/--continue      Resume a previous transfer where we left it\n -C/--continue-at <offset> Specify absolute resume offset\n -d/--data          POST data (H)\n -D/--dump-header <file> Write the headers to this file\n -e/--referer       Referer page (H)\n -E/--cert <cert:passwd> Specifies your certificate file and password (HTTPS)\n -f/--fail          Fail silently (no output at all) on errors (H)\n -F/--form <name=content> Specify HTTP POST data (H)\n -h/--help          This help text\n -H/--header <line> Custom header to pass to server. (H)\n -i/--include       Include the HTTP-header in the output (H)\n -I/--head          Fetch document info only (HTTP HEAD/FTP SIZE)\n -K/--config        Specify which config file to read\n -l/--list-only     List only names of an FTP directory (F)\n -L/--location      Follow Location: hints (H)\n -m/--max-time <seconds> Maximum time allowed for the transfer\n -M/--manual        Display huge help text\n -n/--netrc         Read .netrc for user name and password\n -N/--no-buffer     Disables the buffering of the output stream\n -o/--output <file> Write output to <file> instead of stdout\n -O/--remote-name   Write output to a file named as the remote file\n -P/--ftpport <address> Use PORT with address instead of PASV when ftping (F)\n -q                 When used as the first parameter disables .curlrc\n -Q/--quote <cmd>   Send QUOTE command to FTP before file transfer (F)\n -r/--range <range> Retrieve a byte range from a HTTP/1.1 or FTP server\n -s/--silent        Silent mode. Don\'t output anything\n -S/--show-error    Show error. With -s, make curl show errors when they occur\n -t/--upload        Transfer/upload stdin to remote site\n -T/--upload-file..." /* TRUNCATED STRING LITERAL */
                   ,uVar8);
      iVar14 = 2;
      goto LAB_0010404b;
    case 0x46:
      ::config.conf = ::config.conf ^ 0x100;
      break;
    case 0x49:
      ::config.conf = ::config.conf ^ 0x10000;
      break;
    case 0x4a:
      pCVar13 = local_5b8;
      lVar11 = strtol((char *)local_5b8,(char **)0x0,10);
      ::config.timeout = (long)(int)lVar11;
      break;
    case 0x4b:
      ::config.conf = ::config.conf ^ 0x400000;
      break;
    case 0x4c:
      pCVar13 = (Configurable *)&::config.outfile;
      GetStr(&::config.outfile,(char *)local_5b8);
      break;
    case 0x4e:
      break;
    case 0x4f:
      pCVar13 = (Configurable *)&::config.range;
      GetStr(&::config.range,(char *)local_5b8);
      break;
    case 0x50:
      ::config.conf = ::config.conf | 0x10000400;
      ::config.showerror = (bool)(::config.showerror ^ 1);
      break;
    case 0x51:
      ::config.conf = ::config.conf ^ 0x4000;
      break;
    case 0x52:
      pCVar13 = (Configurable *)&::config.userpwd;
      GetStr(&::config.userpwd,(char *)local_5b8);
      break;
    case 0x53:
      ::config.conf = ::config.conf ^ 0x20;
      break;
    case 0x54:
      if (*(char *)&local_5b8->useragent == '@') {
        local_5b8 = (Configurable *)((long)&local_5b8->useragent + 1);
        pCVar13 = (Configurable *)&DAT_001062f9;
        iVar14 = strequal();
        pCVar10 = stdin;
        if (iVar14 == 0) {
          pCVar13 = local_5b8;
          pCVar10 = (Configurable *)fopen((char *)local_5b8,"r");
        }
        if (pCVar10 == (Configurable *)0x0) {
          ::config.writeout = (char *)0x0;
        }
        else {
          ::config.writeout = file2string((FILE *)pCVar10);
          pCVar13 = stdin;
          if (pCVar10 != stdin) {
            fclose((FILE *)stdin);
          }
        }
      }
      else {
        pCVar13 = (Configurable *)&::config.writeout;
        GetStr(&::config.writeout,(char *)local_5b8);
      }
      break;
    case 0x55:
      pCVar13 = (Configurable *)&::config.proxy;
      GetStr(&::config.proxy,(char *)local_5b8);
      break;
    case 0x56:
      pCVar13 = local_5b8;
      lVar11 = strtol((char *)local_5b8,(char **)0x0,10);
      ::config.low_speed_time = (int)lVar11;
      if (::config.low_speed_limit == 0) {
        ::config.low_speed_limit = 1;
      }
      break;
    case 0x57:
      cVar1 = *(char *)&local_5b8->useragent;
      if (cVar1 == '-') {
        local_5b8 = (Configurable *)((long)&local_5b8->useragent + 1);
        ::config.timecond = TIMECOND_IFUNMODSINCE;
      }
      else if (cVar1 == '=') {
        local_5b8 = (Configurable *)((long)&local_5b8->useragent + 1);
        ::config.timecond = TIMECOND_LASTMOD;
      }
      else {
        ::config.timecond = TIMECOND_IFMODSINCE;
        local_5b8 = (Configurable *)((long)&local_5b8->useragent + (ulong)(cVar1 == '+'));
      }
      time((time_t *)0x0);
      pCVar13 = local_5b8;
      ::config.condtime = curl_getdate();
      if (::config.condtime == -1) {
        pCVar13 = (Configurable *)0x1;
        iVar14 = __xstat(1,(char *)local_5b8,(stat *)&statbuf);
        if (iVar14 == -1) {
          ::config.timecond = TIMECOND_NONE;
        }
        else {
          ::config.condtime = statbuf.st_mtim.tv_sec;
        }
      }
    }
    local_5a8 = (HttpPost *)((long)&local_5a8->next + 1);
  } while ((*(char *)&local_5a8->next != '\0') && (iVar14 = -1, *usedarg == false));
  iVar14 = 0;
LAB_0010404b:
  if (lVar2 == *(long *)(in_FS_OFFSET + 0x28)) {
    return iVar14;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}


/* ---- 0x104960: main_init (7 bytes) ---- */

/* WARNING: Unknown calling convention */

CURLcode main_init(void)

{
  return CURLE_OK;
}


/* ---- 0x104970: main_free (5 bytes) ---- */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void main_free(void)

{
  return;
}


/* ---- 0x104980: SetHTTPrequest (24 bytes) ---- */

int SetHTTPrequest(HttpReq req,HttpReq *store)

{
  int iVar1;
  
  if ((*store != HTTPREQ_UNSPEC) && (*store != req)) {
    iVar1 = SetHTTPrequest(req,store);
    return iVar1;
  }
  *store = req;
  return 0;
}


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

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void hugehelp(void)

{
  puts(&DAT_00107180);
  puts(&DAT_001099a8);
  puts(&DAT_0010c1d8);
  puts(
      "\n   or specify them with the -u flag like\n\n        curl -u name:passwd ftp://machine.domain:port/full/path/to/file\n\n HTTP\n\n   The HTTP URL doesn\'t support user and password in the URL string. Curl\n   does support that anyway to provide a ftp-style interface and thus you can\n   pick a file like:\n\n        curl http://name:passwd@machine.domain/full/path/to/file\n\n   or specify user and password separately like in\n\n        curl -u name:passwd http://machine.domain/full/path/to/file\n\n   NOTE! Since HTTP URLs don\'t support user and password, you can\'t use that\n   style when using Curl via a proxy. You _must_ use the -u style fetch\n   during such circumstances.\n\n HTTPS\n\n   Probably most commonly used with private certificates, as explained below.\n\n GOPHER\n\n   Curl features no password support for gopher.\n\nPROXY\n\n Get an ftp file using a proxy named my-proxy that uses port 888:\n\n        curl -x my-proxy:888 ftp://ftp.leachsite.com/README\n\n Get a file from a HTTP server that requires user and password, using the\n same proxy as above:\n\n        curl -u user:passwd -x my-proxy:888 http://www.get.this/\n\n Some proxies require special authentication. Specify by using -U as above:\n\n        curl -U user:passwd -x my-proxy:888 http://www.get.this/\n\n See also the environment variables Curl support that offer further proxy\n control.\n\nRANGES\n\n  With HTTP 1.1 byte-ranges were introduced. Using this, a client can request\n  to get only one or more subparts of a specified document. Curl supports\n  this with the -r flag.\n\n  Get the first 100 bytes of a document:\n\n        curl -r 0-99 http://www.get.this/\n\n  Get the last 500 bytes of a document:\n\n        curl -r -500 http://www.get.this/\n\n  Curl also supports simple ranges for FTP files as well. Then you can only\n  specify start and stop position.\n\n  Get the first 100 bytes of a document using FTP:\n\n        curl -r 0-99 ftp://www.get.this/README  \n\nUPLOADING\n\n FTP\n\n  Upload all data on stdin to a specified ftp site:\n\n        curl -t ftp://ftp.upload.com/myfile\n\n  Upload data from a specifi..." /* TRUNCATED STRING LITERAL */
      );
  puts(
      "\n        curl --dump-header headers www.example.com\n\n  ... you can then in a second connect to that (or another) site, use the\n  cookies from the \'headers\' file like:\n\n        curl -b headers www.example.com\n\n  Note that by specifying -b you enable the \"cookie awareness\" and with -L\n  you can make curl follow a location: (which often is used in combination\n  with cookies). So that if a site sends cookies and a location, you can\n  use a non-existing file to trig the cookie awareness like:\n\n        curl -L -b empty-file www.example.com\n\n  The file to read cookies from must be formatted using plain HTTP headers OR\n  as netscape\'s cookie file. Curl will determine what kind it is based on the\n  file contents.\n\nPROGRESS METER\n\n  The progress meter exists to show a user that something actually is\n  happening. The different fields in the output have the following meaning:\n\n  % Total    % Received % Xferd  Average Speed          Time             Curr.\n                                 Dload  Upload Total    Current  Left    Speed\n  0  151M    0 38608    0     0   9406      0  4:41:43  0:00:04  4:41:39  9287\n\n  From left-to-right:\n   %             - percentage completed of the whole transfer\n   Total         - total size of the whole expected transfer\n   %             - percentage completed of the download\n   Received      - currently downloaded amount of bytes\n   %             - percentage completed of the upload\n   Xferd         - currently uploaded amount of bytes\n   Average Speed\n   Dload         - the average transfer speed of the download\n   Average Speed\n   Upload        - the average transfer speed of the upload\n   Time Total    - expected time to complete the operation\n   Time Current  - time passed since the invoke\n   Time Left     - expected time left to completetion\n   Curr.Speed    - the average transfer speed the last 5 seconds (the first\n                   5 seconds of a transfer is based on less time of course.)\n\n  The -# option will display a totally different progress bar that doesn\'t\n  need much explanati..." /* TRUNCATED STRING LITERAL */
      );
  puts(
      " check the other way around by prepending it with a dash \'-\'.\n\nDICT\n\n  For fun try\n\n        curl dict://dict.org/m:curl\n        curl dict://dict.org/d:heisenbug:jargon\n        curl dict://dict.org/d:daniel:web1913\n\n  Aliases for \'m\' are \'match\' and \'find\', and aliases for \'d\' are \'define\'\n  and \'lookup\'. For example,\n\n        curl dict://dict.org/find:curl\n\n  Commands that break the URL description of the RFC (but not the DICT\n  protocol) are\n\n        curl dict://dict.org/show:db\n        curl dict://dict.org/show:strat\n\n  Authentication is still missing (but this is not required by the RFC)\n\nLDAP\n\n  If you have installed the OpenLDAP library, curl can take advantage of it\n  and offer ldap:// support.\n\n  LDAP is a complex thing and writing an LDAP query is not an easy task. I do\n  advice you to dig up the syntax description for that elsewhere, RFC 1959 if\n  no other place is better.\n\n  To show you an example, this is now I can get all people from my local LDAP\n  server that has a certain sub-domain in their email address:\n\n        curl -B \"ldap://ldap.frontec.se/o=frontec??sub?mail=*sth.frontec.se\"\n\n  If I want the same info in HTML format, I can get it by not using the -B\n  (enforce ASCII) flag.\n\nENVIRONMENT VARIABLES\n\n  Curl reads and understands the following environment variables:\n\n        HTTP_PROXY, HTTPS_PROXY, FTP_PROXY, GOPHER_PROXY\n\n  They should be set for protocol-specific proxies. General proxy should be\n  set with\n        \n        ALL_PROXY\n\n  A comma-separated list of host names that shouldn\'t go through any proxy is\n  set in (only an asterisk, \'*\' matches all hosts)\n\n        NO_PROXY\n\n  If a tail substring of the domain-path for a host matches one of these\n  strings, transactions with that node will not be proxied.\n\n\n  The usage of the -x/--proxy flag overrides the environment variables.\n\nNETRC\n\n  Unix introduced the .netrc concept a long time ago. It is a way for a user\n  to specify name and password for commonly visited ftp sites in a file so\n  that you don\'t have to type them in each time you vi..." /* TRUNCATED STRING LITERAL */
      );
  return;
}


/* ---- 0x104a60: glob_word (323 bytes) ---- */

int glob_word(char *pattern,int pos)

{
  byte bVar1;
  URLGlob *pUVar2;
  char cVar3;
  int iVar4;
  char *pcVar5;
  char *pcVar6;
  char *pcVar7;
  
  pcVar5 = glob_buffer;
  bVar1 = *pattern;
  pUVar2 = glob_expand;
  while( true ) {
    glob_expand = pUVar2;
    if (((bVar1 & 0xdf) == 0x5b) || (bVar1 == 0)) {
      *pcVar5 = '\0';
      iVar4 = pUVar2->size;
      pcVar5 = strdup(glob_buffer);
      pUVar2->literal[iVar4 / 2] = pcVar5;
      pUVar2->size = iVar4 + 1;
      cVar3 = *pattern;
      if (cVar3 == '\0') {
        return 1;
      }
      if (cVar3 != '{') {
        if (cVar3 == '[') {
          iVar4 = glob_range(pattern + 1,pos + 1);
          return iVar4;
        }
        puts("internal error");
                    /* WARNING: Subroutine does not return */
        exit(2);
      }
      iVar4 = glob_set(pattern + 1,pos + 1);
      return iVar4;
    }
    iVar4 = pos;
    if ((bVar1 & 0xdf) == 0x5d) break;
    pcVar6 = pattern + 1;
    iVar4 = pos + 1;
    if (bVar1 == 0x5c) {
      cVar3 = pattern[1];
      if (cVar3 == '\0') break;
      pcVar7 = pattern + 2;
      iVar4 = pos + 2;
      pattern = pcVar6;
      pcVar6 = pcVar7;
    }
    else {
      cVar3 = *pattern;
    }
    *pcVar5 = cVar3;
    bVar1 = pattern[1];
    pcVar5 = pcVar5 + 1;
    pattern = pcVar6;
    pos = iVar4;
    pUVar2 = glob_expand;
  }
  __printf_chk(1,"illegal character at position %d\n",iVar4);
                    /* WARNING: Subroutine does not return */
  exit(3);
}


/* ---- 0x104bc0: glob_set (400 bytes) ---- */

int glob_set(char *pattern,int pos)

{
  short sVar1;
  URLGlob *pUVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  char **ppcVar6;
  char *pcVar7;
  short sVar8;
  
  pUVar2 = glob_expand;
  iVar5 = glob_expand->size;
  iVar4 = iVar5 / 2;
  glob_expand->pattern[iVar4].type = UPTSet;
  *(undefined4 *)((long)&pUVar2->pattern[iVar4].content + 8) = 0;
  ppcVar6 = (char **)malloc(0);
  pcVar7 = glob_buffer;
  pUVar2->pattern[iVar4].content.Set.elements = ppcVar6;
  pUVar2->size = iVar5 + 1;
  do {
    cVar3 = *pattern;
    if ('}' < cVar3) goto switchD_00104c45_caseD_5e;
    if (cVar3 < '[') {
      if (cVar3 == '\0') {
        pcVar7 = "error: unmatched brace at pos %d\n";
        goto LAB_00104d0e;
      }
      if (cVar3 == ',') goto switchD_00104c45_caseD_7d;
      goto switchD_00104c45_caseD_5e;
    }
    switch(cVar3) {
    case '[':
    case '{':
      pcVar7 = "error: nested braces not supported %d\n";
      goto LAB_00104d0e;
    case '\\':
      if (pcVar7[1] == '\0') goto switchD_00104c45_caseD_5d;
      cVar3 = pattern[1];
      pos = pos + 1;
      pattern = pattern + 1;
    default:
switchD_00104c45_caseD_5e:
      *pcVar7 = cVar3;
      pos = pos + 1;
      pcVar7 = pcVar7 + 1;
      pattern = pattern + 1;
      break;
    case ']':
switchD_00104c45_caseD_5d:
      pcVar7 = "error: illegal pattern at pos %d\n";
LAB_00104d0e:
      __printf_chk(1,pcVar7,pos);
                    /* WARNING: Subroutine does not return */
      exit(3);
    case '}':
switchD_00104c45_caseD_7d:
      *pcVar7 = '\0';
      ppcVar6 = (char **)realloc(pUVar2->pattern[iVar4].content.Set.elements,
                                 (long)(pUVar2->pattern[iVar4].content.Set.size + 1) << 3);
      pUVar2->pattern[iVar4].content.Set.elements = ppcVar6;
      if (ppcVar6 == (char **)0x0) {
        puts("out of memory in set pattern");
                    /* WARNING: Subroutine does not return */
        exit(0x1b);
      }
      sVar1 = pUVar2->pattern[iVar4].content.Set.size;
      pos = pos + 1;
      pcVar7 = strdup(glob_buffer);
      sVar8 = sVar1 + 1;
      ppcVar6[sVar1] = pcVar7;
      pUVar2->pattern[iVar4].content.Set.size = sVar8;
      if (*pattern == '}') {
        iVar5 = glob_word(pattern + 1,pos);
        return iVar5 * sVar8;
      }
      pcVar7 = glob_buffer;
      pattern = pattern + 1;
    }
  } while( true );
}


/* ---- 0x104d60: glob_range (503 bytes) ---- */

int glob_range(char *pattern,int pos)

{
  char cVar1;
  char cVar2;
  short sVar3;
  ushort *puVar4;
  URLGlob *pUVar5;
  int iVar6;
  int iVar7;
  ushort **ppuVar8;
  char *pcVar9;
  int iVar10;
  
  pUVar5 = glob_expand;
  iVar10 = glob_expand->size;
  glob_expand->size = iVar10 + 1;
  iVar10 = iVar10 / 2;
  ppuVar8 = __ctype_b_loc();
  if (((*ppuVar8)[*pattern] & 0x400) == 0) {
    if (((*ppuVar8)[*pattern] & 0x800) == 0) {
      pcVar9 = "error: illegal character in range specification at pos %d\n";
      goto LAB_00104f43;
    }
    pUVar5->pattern[iVar10].content.Set.size = 0;
    pUVar5->pattern[iVar10].type = UPTNumRange;
    iVar6 = __isoc99_sscanf(pattern,"%d-%d]",&pUVar5->pattern[iVar10].content,
                            (undefined1 *)((long)&pUVar5->pattern[iVar10].content + 4));
    if ((iVar6 == 2) &&
       (iVar6 = pUVar5->pattern[iVar10].content.NumRange.min_n,
       iVar6 < pUVar5->pattern[iVar10].content.NumRange.max_n)) {
      if (*pattern == '0') {
        puVar4 = *ppuVar8;
        if ((*(byte *)((long)puVar4 + 0x61) & 8) != 0) {
          sVar3 = pUVar5->pattern[iVar10].content.Set.size;
          pcVar9 = pattern + 1;
          do {
            pUVar5->pattern[iVar10].content.Set.size =
                 ((sVar3 + 1) - (short)(pattern + 1)) + (short)pcVar9;
            cVar1 = *pcVar9;
            pcVar9 = pcVar9 + 1;
          } while ((*(byte *)((long)puVar4 + (long)cVar1 * 2 + 1) & 8) != 0);
          iVar6 = pUVar5->pattern[iVar10].content.NumRange.min_n;
        }
      }
      pUVar5->pattern[iVar10].content.NumRange.ptr_n = iVar6;
      pcVar9 = strchr(pattern,0x5d);
      iVar10 = pUVar5->pattern[iVar10].content.NumRange.max_n;
      iVar7 = glob_word(pcVar9 + 1,((int)(pcVar9 + 1) - (int)pattern) + pos);
      return iVar7 * ((iVar10 - iVar6) + 1);
    }
  }
  else {
    pUVar5->pattern[iVar10].type = UPTCharRange;
    iVar6 = __isoc99_sscanf(pattern,"%c-%c]",&pUVar5->pattern[iVar10].content,
                            (undefined1 *)((long)&pUVar5->pattern[iVar10].content + 1));
    if (iVar6 == 2) {
      cVar1 = pUVar5->pattern[iVar10].content.CharRange.min_c;
      cVar2 = pUVar5->pattern[iVar10].content.CharRange.max_c;
      if ((cVar1 < cVar2) && ((int)cVar2 - (int)cVar1 < 0x1a)) {
        cVar2 = pUVar5->pattern[iVar10].content.CharRange.max_c;
        pUVar5->pattern[iVar10].content.CharRange.ptr_c = cVar1;
        iVar10 = glob_word(pattern + 4,pos + 4);
        return iVar10 * (((int)cVar2 - (int)cVar1) + 1);
      }
    }
  }
  pcVar9 = "error: illegal pattern or range specification after pos %d\n";
LAB_00104f43:
  __printf_chk(1,pcVar9,pos);
                    /* WARNING: Subroutine does not return */
  exit(3);
}


/* ---- 0x104f70: glob_url (116 bytes) ---- */

int glob_url(URLGlob **glob,char *url,int *urlnum)

{
  int iVar1;
  size_t sVar2;
  
  sVar2 = strlen(url);
  if (sVar2 < 0x1001) {
    glob_expand = (URLGlob *)malloc(0x130);
    glob_expand->size = 0;
    iVar1 = glob_word(url,1);
    *urlnum = iVar1;
    *glob = glob_expand;
    return 0;
  }
  puts("Illegally sized URL");
  return 3;
}


/* ---- 0x104ff0: next_url (502 bytes) ---- */

char * next_url(URLGlob *glob)

{
  char cVar1;
  short sVar2;
  URLPatternType UVar3;
  int iVar4;
  size_t sVar5;
  char **ppcVar6;
  int iVar7;
  uint uVar8;
  char *pcVar9;
  char *pcVar10;
  
  iVar4 = glob->size;
  if (next_url::beenhere != 0) {
    iVar7 = iVar4 / 2;
    if (1 < iVar4) {
      ppcVar6 = glob->literal + (long)iVar7 * 3;
      do {
        iVar4 = *(int *)(ppcVar6 + 7);
        if (iVar4 == 2) {
          cVar1 = *(char *)((long)ppcVar6 + 0x42) + '\x01';
          *(char *)((long)ppcVar6 + 0x42) = cVar1;
          if (cVar1 <= *(char *)((long)ppcVar6 + 0x41)) goto LAB_001051d4;
          *(undefined1 *)((long)ppcVar6 + 0x42) = *(undefined1 *)(ppcVar6 + 8);
        }
        else if (iVar4 == 3) {
          iVar4 = *(int *)((long)ppcVar6 + 0x4c) + 1;
          *(int *)((long)ppcVar6 + 0x4c) = iVar4;
          if (iVar4 <= *(int *)((long)ppcVar6 + 0x44)) goto LAB_001051d4;
          *(undefined4 *)((long)ppcVar6 + 0x4c) = *(undefined4 *)(ppcVar6 + 8);
        }
        else {
          if (iVar4 != 1) goto LAB_001050a0;
          sVar2 = *(short *)((long)ppcVar6 + 0x4a) + 1;
          *(short *)((long)ppcVar6 + 0x4a) = sVar2;
          if (sVar2 != *(short *)(ppcVar6 + 9)) {
LAB_001051d4:
            iVar4 = glob->size;
            goto LAB_00105020;
          }
          *(undefined2 *)((long)ppcVar6 + 0x4a) = 0;
        }
        ppcVar6 = ppcVar6 + -3;
      } while (ppcVar6 !=
               (char **)((long)glob + (ulong)(iVar7 - 1) * -0x18 + (long)iVar7 * 0x18 + -0x18));
    }
    return (char *)0x0;
  }
  next_url::beenhere = 1;
LAB_00105020:
  uVar8 = 0;
  pcVar9 = glob_buffer;
  if (0 < iVar4) {
    do {
      while (iVar4 = (int)uVar8 >> 1, (uVar8 & 1) == 0) {
        pcVar10 = glob->literal[iVar4];
        uVar8 = uVar8 + 1;
        strcpy(pcVar9,pcVar10);
        sVar5 = strlen(pcVar10);
        pcVar9 = pcVar9 + sVar5;
        if (glob->size <= (int)uVar8) goto LAB_001050e7;
      }
      UVar3 = glob->pattern[iVar4].type;
      if (UVar3 == UPTCharRange) {
        pcVar10 = pcVar9 + 1;
        *pcVar9 = glob->pattern[iVar4].content.CharRange.ptr_c;
      }
      else if (UVar3 == UPTNumRange) {
        __sprintf_chk(pcVar9,1,0xffffffffffffffff,&DAT_001149b0,
                      (int)glob->pattern[iVar4].content.Set.size,
                      glob->pattern[iVar4].content.NumRange.ptr_n);
        sVar5 = strlen(pcVar9);
        pcVar10 = pcVar9 + sVar5;
      }
      else {
        if (UVar3 != UPTSet) {
LAB_001050a0:
          __printf_chk(1,"internal error: invalid pattern type (%d)\n");
                    /* WARNING: Subroutine does not return */
          exit(2);
        }
        strcpy(pcVar9,glob->pattern[iVar4].content.Set.elements
                      [glob->pattern[iVar4].content.Set.ptr_s]);
        sVar5 = strlen(glob->pattern[iVar4].content.Set.elements
                       [glob->pattern[iVar4].content.Set.ptr_s]);
        pcVar10 = pcVar9 + sVar5;
      }
      uVar8 = uVar8 + 1;
      pcVar9 = pcVar10;
    } while ((int)uVar8 < glob->size);
  }
LAB_001050e7:
  *pcVar9 = '\0';
  pcVar9 = strdup(glob_buffer);
  return pcVar9;
}


/* ---- 0x105220: match_url (443 bytes) ---- */

char * match_url(char *filename,URLGlob glob)

{
  short sVar1;
  URLPatternType UVar2;
  char **ppcVar3;
  char cVar4;
  int iVar5;
  ushort **ppuVar6;
  size_t sVar7;
  char *__dest;
  char *pcVar8;
  
  cVar4 = *filename;
  if (cVar4 == '\0') {
    pcVar8 = glob_buffer;
  }
  else {
    __dest = glob_buffer;
    do {
      while (cVar4 == '#') {
        ppuVar6 = __ctype_b_loc();
        cVar4 = filename[1];
        if (((*(byte *)((long)*ppuVar6 + (long)cVar4 * 2 + 1) & 8) == 0) || (cVar4 == '0')) {
          puts("illegal matching expression");
                    /* WARNING: Subroutine does not return */
          exit(3);
        }
        iVar5 = cVar4 + -0x31;
        if (glob.size / 2 <= iVar5) {
          puts("match against nonexisting pattern");
                    /* WARNING: Subroutine does not return */
          exit(3);
        }
        ppcVar3 = glob.pattern[iVar5].content.Set.elements;
        UVar2 = glob.pattern[iVar5].type;
        if (UVar2 == UPTCharRange) {
          pcVar8 = __dest + 1;
          *__dest = (char)((ulong)ppcVar3 >> 0x10);
        }
        else if (UVar2 == UPTNumRange) {
          __sprintf_chk(__dest,1,0xffffffffffffffff,&DAT_001149b0,
                        (int)glob.pattern[iVar5].content.Set.size,
                        glob.pattern[iVar5].content.NumRange.ptr_n,
                        *(undefined8 *)(glob.pattern + iVar5),ppcVar3,
                        *(undefined8 *)((long)&glob.pattern[iVar5].content + 8));
          sVar7 = strlen(__dest);
          pcVar8 = __dest + sVar7;
        }
        else {
          if (UVar2 != UPTSet) {
            __printf_chk(1,"internal error: invalid pattern type (%d)\n");
                    /* WARNING: Subroutine does not return */
            exit(2);
          }
          sVar1 = glob.pattern[iVar5].content.Set.ptr_s;
          strcpy(__dest,ppcVar3[sVar1]);
          sVar7 = strlen(ppcVar3[sVar1]);
          pcVar8 = __dest + sVar7;
        }
        cVar4 = filename[2];
        filename = filename + 2;
        __dest = pcVar8;
        if (cVar4 == '\0') goto LAB_0010532e;
      }
      filename = filename + 1;
      *__dest = cVar4;
      pcVar8 = __dest + 1;
      cVar4 = *filename;
      __dest = pcVar8;
    } while (cVar4 != '\0');
  }
LAB_0010532e:
  *pcVar8 = '\0';
  pcVar8 = strdup(glob_buffer);
  return pcVar8;
}


/* ---- 0x105400: __libc_csu_init (101 bytes) ---- */

void __libc_csu_init(EVP_PKEY_CTX *param_1,undefined8 param_2,undefined8 param_3)

{
  long lVar1;
  
  _init(param_1);
  lVar1 = 0;
  do {
    (*(code *)(&__frame_dummy_init_array_entry)[lVar1])((ulong)param_1 & 0xffffffff,param_2,param_3)
    ;
    lVar1 = lVar1 + 1;
  } while (lVar1 != 1);
  return;
}


/* ---- 0x105470: __libc_csu_fini (5 bytes) ---- */

void __libc_csu_fini(void)

{
  return;
}


/* ---- 0x105478: _fini (13 bytes) ---- */

void _fini(void)

{
  return;
}


WARN  Decompiling 00119000, pcode error at 00119000: Unable to disassemble EXTERNAL block location: 00119000 (DecompileCallback)  
/* ---- 0x119000: free (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void free(void *__ptr)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* free@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119008, pcode error at 00119008: Unable to disassemble EXTERNAL block location: 00119008 (DecompileCallback)  
/* ---- 0x119008: __vfprintf_chk (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void __vfprintf_chk(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* __vfprintf_chk@@GLIBC_2.3.4 */
  halt_baddata();
}


WARN  Decompiling 00119010, pcode error at 00119010: Unable to disassemble EXTERNAL block location: 00119010 (DecompileCallback)  
/* ---- 0x119010: _ITM_deregisterTMCloneTable (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void _ITM_deregisterTMCloneTable(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


WARN  Decompiling 00119018, pcode error at 00119018: Unable to disassemble EXTERNAL block location: 00119018 (DecompileCallback)  
/* ---- 0x119018: strcpy (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * strcpy(char *__dest,char *__src)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* strcpy@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119020, pcode error at 00119020: Unable to disassemble EXTERNAL block location: 00119020 (DecompileCallback)  
/* ---- 0x119020: puts (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int puts(char *__s)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* puts@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119028, pcode error at 00119028: Unable to disassemble EXTERNAL block location: 00119028 (DecompileCallback)  
/* ---- 0x119028: isatty (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int isatty(int __fd)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* isatty@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119030, pcode error at 00119030: Unable to disassemble EXTERNAL block location: 00119030 (DecompileCallback)  
/* ---- 0x119030: curl_easy_perform (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void curl_easy_perform(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


WARN  Decompiling 00119038, pcode error at 00119038: Unable to disassemble EXTERNAL block location: 00119038 (DecompileCallback)  
/* ---- 0x119038: curl_slist_append (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void curl_slist_append(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


WARN  Decompiling 00119040, pcode error at 00119040: Unable to disassemble EXTERNAL block location: 00119040 (DecompileCallback)  
/* ---- 0x119040: fclose (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int fclose(FILE *__stream)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* fclose@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119048, pcode error at 00119048: Unable to disassemble EXTERNAL block location: 00119048 (DecompileCallback)  
/* ---- 0x119048: strlen (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

size_t strlen(char *__s)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* strlen@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119050, pcode error at 00119050: Unable to disassemble EXTERNAL block location: 00119050 (DecompileCallback)  
/* ---- 0x119050: __stack_chk_fail (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void __stack_chk_fail(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* __stack_chk_fail@@GLIBC_2.4 */
  halt_baddata();
}


WARN  Decompiling 00119058, pcode error at 00119058: Unable to disassemble EXTERNAL block location: 00119058 (DecompileCallback)  
/* ---- 0x119058: strchr (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * strchr(char *__s,int __c)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* strchr@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119060, pcode error at 00119060: Unable to disassemble EXTERNAL block location: 00119060 (DecompileCallback)  
/* ---- 0x119060: strrchr (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * strrchr(char *__s,int __c)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* strrchr@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119068, pcode error at 00119068: Unable to disassemble EXTERNAL block location: 00119068 (DecompileCallback)  
/* ---- 0x119068: maprintf (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void maprintf(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


WARN  Decompiling 00119070, pcode error at 00119070: Unable to disassemble EXTERNAL block location: 00119070 (DecompileCallback)  
/* ---- 0x119070: fputc (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int fputc(int __c,FILE *__stream)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* fputc@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119078, pcode error at 00119078: Unable to disassemble EXTERNAL block location: 00119078 (DecompileCallback)  
/* ---- 0x119078: __libc_start_main (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void __libc_start_main(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* __libc_start_main@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119080, pcode error at 00119080: Unable to disassemble EXTERNAL block location: 00119080 (DecompileCallback)  
/* ---- 0x119080: fgets (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * fgets(char *__s,int __n,FILE *__stream)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* fgets@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119088, pcode error at 00119088: Unable to disassemble EXTERNAL block location: 00119088 (DecompileCallback)  
/* ---- 0x119088: __gmon_start__ (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void __gmon_start__(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


WARN  Decompiling 00119090, pcode error at 00119090: Unable to disassemble EXTERNAL block location: 00119090 (DecompileCallback)  
/* ---- 0x119090: strtol (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

long strtol(char *__nptr,char **__endptr,int __base)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* strtol@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119098, pcode error at 00119098: Unable to disassemble EXTERNAL block location: 00119098 (DecompileCallback)  
/* ---- 0x119098: memcpy (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void * memcpy(void *__dest,void *__src,size_t __n)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* memcpy@@GLIBC_2.14 */
  halt_baddata();
}


WARN  Decompiling 001190a0, pcode error at 001190a0: Unable to disassemble EXTERNAL block location: 001190a0 (DecompileCallback)  
/* ---- 0x1190a0: time (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

time_t time(time_t *__timer)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* time@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 001190a8, pcode error at 001190a8: Unable to disassemble EXTERNAL block location: 001190a8 (DecompileCallback)  
/* ---- 0x1190a8: fileno (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int fileno(FILE *__stream)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* fileno@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 001190b0, pcode error at 001190b0: Unable to disassemble EXTERNAL block location: 001190b0 (DecompileCallback)  
/* ---- 0x1190b0: __xstat (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int __xstat(int __ver,char *__filename,stat *__stat_buf)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* __xstat@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 001190b8, pcode error at 001190b8: Unable to disassemble EXTERNAL block location: 001190b8 (DecompileCallback)  
/* ---- 0x1190b8: malloc (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void * malloc(size_t __size)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* malloc@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 001190c0, pcode error at 001190c0: Unable to disassemble EXTERNAL block location: 001190c0 (DecompileCallback)  
/* ---- 0x1190c0: __isoc99_sscanf (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void __isoc99_sscanf(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* __isoc99_sscanf@@GLIBC_2.7 */
  halt_baddata();
}


WARN  Decompiling 001190c8, pcode error at 001190c8: Unable to disassemble EXTERNAL block location: 001190c8 (DecompileCallback)  
/* ---- 0x1190c8: curl_easy_init (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void curl_easy_init(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


WARN  Decompiling 001190d0, pcode error at 001190d0: Unable to disassemble EXTERNAL block location: 001190d0 (DecompileCallback)  
/* ---- 0x1190d0: curl_getenv (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void curl_getenv(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


WARN  Decompiling 001190d8, pcode error at 001190d8: Unable to disassemble EXTERNAL block location: 001190d8 (DecompileCallback)  
/* ---- 0x1190d8: realloc (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void * realloc(void *__ptr,size_t __size)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* realloc@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 001190e0, pcode error at 001190e0: Unable to disassemble EXTERNAL block location: 001190e0 (DecompileCallback)  
/* ---- 0x1190e0: __printf_chk (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void __printf_chk(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* __printf_chk@@GLIBC_2.3.4 */
  halt_baddata();
}


WARN  Decompiling 001190e8, pcode error at 001190e8: Unable to disassemble EXTERNAL block location: 001190e8 (DecompileCallback)  
/* ---- 0x1190e8: curl_version (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void curl_version(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


WARN  Decompiling 001190f0, pcode error at 001190f0: Unable to disassemble EXTERNAL block location: 001190f0 (DecompileCallback)  
/* ---- 0x1190f0: curl_slist_free_all (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void curl_slist_free_all(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


WARN  Decompiling 001190f8, pcode error at 001190f8: Unable to disassemble EXTERNAL block location: 001190f8 (DecompileCallback)  
/* ---- 0x1190f8: fopen (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

FILE * fopen(char *__filename,char *__modes)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* fopen@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119100, pcode error at 00119100: Unable to disassemble EXTERNAL block location: 00119100 (DecompileCallback)  
/* ---- 0x119100: strcat (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * strcat(char *__dest,char *__src)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* strcat@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119108, pcode error at 00119108: Unable to disassemble EXTERNAL block location: 00119108 (DecompileCallback)  
/* ---- 0x119108: curl_easy_setopt (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void curl_easy_setopt(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


WARN  Decompiling 00119110, pcode error at 00119110: Unable to disassemble EXTERNAL block location: 00119110 (DecompileCallback)  
/* ---- 0x119110: curl_getdate (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void curl_getdate(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


WARN  Decompiling 00119118, pcode error at 00119118: Unable to disassemble EXTERNAL block location: 00119118 (DecompileCallback)  
/* ---- 0x119118: exit (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void exit(int __status)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* exit@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119120, pcode error at 00119120: Unable to disassemble EXTERNAL block location: 00119120 (DecompileCallback)  
/* ---- 0x119120: fwrite (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

size_t fwrite(void *__ptr,size_t __size,size_t __n,FILE *__s)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* fwrite@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119128, pcode error at 00119128: Unable to disassemble EXTERNAL block location: 00119128 (DecompileCallback)  
/* ---- 0x119128: __fprintf_chk (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void __fprintf_chk(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* __fprintf_chk@@GLIBC_2.3.4 */
  halt_baddata();
}


WARN  Decompiling 00119130, pcode error at 00119130: Unable to disassemble EXTERNAL block location: 00119130 (DecompileCallback)  
/* ---- 0x119130: _ITM_registerTMCloneTable (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void _ITM_registerTMCloneTable(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


WARN  Decompiling 00119138, pcode error at 00119138: Unable to disassemble EXTERNAL block location: 00119138 (DecompileCallback)  
/* ---- 0x119138: curl_easy_cleanup (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void curl_easy_cleanup(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


WARN  Decompiling 00119140, pcode error at 00119140: Unable to disassemble EXTERNAL block location: 00119140 (DecompileCallback)  
/* ---- 0x119140: strdup (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * strdup(char *__s)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* strdup@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119148, pcode error at 00119148: Unable to disassemble EXTERNAL block location: 00119148 (DecompileCallback)  
/* ---- 0x119148: strequal (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void strequal(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


WARN  Decompiling 00119150, pcode error at 00119150: Unable to disassemble EXTERNAL block location: 00119150 (DecompileCallback)  
/* ---- 0x119150: curl_formparse (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void curl_formparse(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


WARN  Decompiling 00119158, pcode error at 00119158: Unable to disassemble EXTERNAL block location: 00119158 (DecompileCallback)  
/* ---- 0x119158: strstr (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * strstr(char *__haystack,char *__needle)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* strstr@@GLIBC_2.2.5 */
  halt_baddata();
}


WARN  Decompiling 00119160, pcode error at 00119160: Unable to disassemble EXTERNAL block location: 00119160 (DecompileCallback)  
/* ---- 0x119160: strnequal (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void strnequal(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


WARN  Decompiling 00119168, pcode error at 00119168: Unable to disassemble EXTERNAL block location: 00119168 (DecompileCallback)  
/* ---- 0x119168: __ctype_b_loc (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

ushort ** __ctype_b_loc(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* __ctype_b_loc@@GLIBC_2.3 */
  halt_baddata();
}


WARN  Decompiling 00119170, pcode error at 00119170: Unable to disassemble EXTERNAL block location: 00119170 (DecompileCallback)  
/* ---- 0x119170: __sprintf_chk (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void __sprintf_chk(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* __sprintf_chk@@GLIBC_2.3.4 */
  halt_baddata();
}


WARN  Decompiling 00119178, pcode error at 00119178: Unable to disassemble EXTERNAL block location: 00119178 (DecompileCallback)  
/* ---- 0x119178: __cxa_finalize (1 bytes) ---- */

/* WARNING: Control flow encountered bad instruction data */

void __cxa_finalize(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* __cxa_finalize@@GLIBC_2.2.5 */
  halt_baddata();
}


INFO  ANALYZING changes made by post scripts: file:///D:/ghidra/rugra/examples/curl (HeadlessAnalyzer)  
INFO  REPORT: Post-analysis succeeded for file: file:///D:/ghidra/rugra/examples/curl (HeadlessAnalyzer)  
INFO  REPORT: Save succeeded for: /curl (curl_proj:/curl) (HeadlessAnalyzer)  
INFO  REPORT: Import succeeded (HeadlessAnalyzer)  
