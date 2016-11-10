# Privilege escalation on z/OS

Some scripts to quickly escalate on z/OS given certain misconfigurations.  
These techniques have been around for a while, I just stringed some code together to have something easy to use in a pentest.

## ELV.APF    
### Description
This tool will list APF authorized libraries by browsing control blocks in memory. For each library it returns the access right of the current user.  
Given a library with ALTER/UPDATE access, the script compiles an ASM program into that library and executes it to give the SPECIAL privilege to the current user.
the ASM program updates the ACEE block in memory to give temporary SPECIAL privilege, which are made permanent by a regular ALU user SPECIAL.
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
Comign soon...
