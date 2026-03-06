void function(int param_2, long param_4) {
    char bVar1;
    char bVar2;
    long lVar7;
    long lVar21;
    int iVar25;
    long lVar32;
    int iVar34;
    long lVar92;
    long lVar93;
    int iVar95;
    int iVar96;
    int iVar97;
    int iVar98;
    int iVar99;
    int iVar101;
    char bVar102;
    char bVar103;
    char bVar104;
    char bVar108;
    int iVar112;
    int iVar114;
    long lVar116;
    long lVar117;
    long lVar118;
    long lVar120;
    long lVar121;
    long lVar122;
    long lVar123;
    long lVar124;
    char bVar125;

    lVar124 = (rdi - 8);

    (*lVar124) = r15;

    iVar95 = 0x26;

    lVar124 -= 8;

    (*lVar124) = r14;

    lVar124 -= 8;

    (*lVar124) = r13;

    lVar124 -= 8;

    (*lVar124) = param_4;

    lVar124 -= 8;

    (*lVar124) = rsi;

    lVar124 -= 8;

    (*lVar124) = param_4;

    lVar124 -= 0x228;

    lVar116 = (lVar124 + 0x218);

    iVar97 = 0;

    bVar102 = 1;

    bVar103 = 0;

    bVar104 = 0;

    iVar97 = 0;

    lVar117 = (lVar124 + 0x48);

    iVar97 = 0;

    bVar102 = 1;

    bVar103 = 0;

    bVar104 = 0;

    iVar97 = 0;

    (*DAT_17520) = iVar97;

    iVar97 = DAT_17528;

    MCloneTable();

    iVar97 = 0;

    bVar102 = 1;

    bVar103 = 0;

    bVar104 = 0;

    iVar97 = 0;

    _ITM_deregisterTMCloneTable();

    iVar112 = (iVar101 - 1);

    lVar118 = (param_4 + 8);

    iVar96 = 2;

    mon_start__();

    iVar114 = 0;

    bVar102 = 1;

    bVar103 = 0;

    bVar104 = 0;

    if (bVar108) {
        iVar97 = 0;

        bVar102 = 1;

        bVar103 = 0;

        bVar104 = bVar1;

        parseconfig.constprop.0();

        iVar114 = iVar97;

        bVar104 = bVar1;

        if (bVar108) {
            lVar120 = (lVar124 + lVar32);

            iVar95 ^= lVar121;

            bVar104 = bVar2;

            lVar124 += iVar34;

            iVar101 = (*lVar124);

            lVar124 += lVar92;

            iVar98 = (*lVar124);

            lVar124 += lVar92;

            iVar99 = (*lVar124);

            lVar124 += lVar92;

        } else {
            iVar97 = (iVar101 + lVar93);

            iVar101 = iVar25;

            lVar122 = (lVar124 + lVar21);

            iVar99 = 0;

            bVar102 = 1;

            bVar103 = 0;

            bVar104 = bVar1;

            iVar99 = 0;

            lVar123 = (lVar124 + lVar7);

            iVar98 = iVar25;

            iVar101 = iVar25;

        }
    } else {
        lVar118 = (param_4 + 8);

        bVar125 = (bVar108 - 0x2d);

    }
    iVar97 = 0;

    bVar102 = 1;

    bVar103 = 0;

    bVar104 = bVar1;

    parseconfig.constprop.0();

}
