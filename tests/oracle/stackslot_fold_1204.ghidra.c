/* ---- 0x12cf30: ap_parse_vhost_addrs (189 bytes) ---- */

long ap_parse_vhost_addrs(undefined8 param_1,char *param_2,long param_3)

{
  undefined2 uVar1;
  short sVar2;
  undefined8 uVar3;
  long lVar4;
  long in_FS_OFFSET;
  char *local_40;
  undefined8 *local_38;
  long local_30;
  
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = (undefined8 *)(param_3 + 0x60);
  local_40 = param_2;
  do {
    if (*local_40 == '\0') {
      *local_38 = 0;
      lVar4 = 0;
      if (*(long *)(param_3 + 0x60) != 0) {
        sVar2 = *(short *)(*(long *)(param_3 + 0x60) + 0x10);
        lVar4 = 0;
        if (sVar2 != 0) {
          *(short *)(param_3 + 0x30) = sVar2;
        }
      }
      goto LAB_0012cfc6;
    }
    uVar1 = *(undefined2 *)(param_3 + 0x30);
    uVar3 = ap_getword_conf(param_1,&local_40);
    lVar4 = FUN_0012c960(param_1,uVar3,&local_38,uVar1);
  } while (lVar4 == 0);
  *local_38 = 0;
LAB_0012cfc6:
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    return lVar4;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
