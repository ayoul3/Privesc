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
If you want to change the TSO command giving special privileges, alter line 334

### Usage
 ```  
 Look for magic SVC on TSO :  
     ex 'ELV.SVC'
 Get Special using SVC 233 and placing C1C1C1C1 in register 10: 
     ex 'ELV.SVC' 'NUM=233 10=C1C1C1C1 DSN=TEST.PDS
```  
### Credit
Got the idea from Mark Wilson @ich408i   
https://share.confex.com/share/120/webprogram/Handout/Session12275/2013%20Share%20Pen%20Testing.pdf
http://www.cbttape.org/xephon/xephonr/rac0005.pdf  
http://www.mzelden.com/mvsfiles/iplinfo.txt  


## ELV.SELF
Incognito on z/OS...Coming soon
