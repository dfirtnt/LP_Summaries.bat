REM WELDS = Windows Event Log DFIR Summaries
REM Script Created by Andrew Skatoff @DFIR_TNTR
REM This script collects high level summaries of events of interest as derived from "SANS Know Normal Find Evil" poster AND the JP Cert Lateral Movement paper.

ECHO  group by NTLM users - EventID:4624 >> WELDS.txt
LogParser.exe -q:ON -stats:OFF -i:EVT "SELECT COUNT(*) AS CNT, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType, EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP   INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND AuthPackage LIKE '%%NtLmSsp%%' AND Username NOT LIKE '%%$' GROUP BY Username, Domain, LogonType, AuthPackage, Workstation, ProcessName, SourceIP ORDER BY CNT ASC"   -filemode:0
ECHO Show what eventids in event log sorted by count >> WELDS.txt
LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) AS CNT, EventID   INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' GROUP BY EventID ORDER BY CNT ASC"   -filemode:0
ECHO group by user >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select extract_token(strings, 0, '|') as user, count(*) as CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Microsoft-Windows-TerminalServices-ECHOoteConnectionManager%%4Operational.evtx' WHERE EventID = 1149 GROUP BY user ORDER BY CNT ASC"   -filemode:0
ECHO group by application >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select COUNT(*) as CNT, extract_token(strings, 1, '|') as file  INTO WELDS.txt FROM'Microsoft-Windows-Windows Firewall With Advanced Security%%4Firewall.evtx' WHERE EventID = 2011 GROUP BY file ORDER BY CNT ASC"   -filemode:0 
ECHO group by rulename  >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select COUNT(*) as CNT, extract_token(strings, 1, '|') as rulename  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Microsoft-Windows-Windows Firewall With Advanced Security%%4Firewall.evtx' WHERE EventID = 2006 GROUP BY rulename ORDER BY CNT ASC"   -filemode:0
ECHO group by changedapp >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select COUNT(*) as CNT, extract_token(strings, 3, '|') as changedapp  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Microsoft-Windows-Windows Firewall With Advanced Security%%4Firewall.evtx' WHERE EventID = 2006 GROUP BY changedapp ORDER BY CNT ASC"   -filemode:0
ECHO group by modifyingapp >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select COUNT(*) as CNT, extract_token(strings, 22, '|') as modifyingapp  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Microsoft-Windows-Windows Firewall With Advanced Security%%4Firewall.evtx' WHERE EventID = 2005 GROUP BY modifyingapp ORDER BY CNT ASC"   -filemode:0
ECHO group by local port >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select COUNT(*) as CNT, extract_token(strings, 7, '|') as localport  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Microsoft-Windows-Windows Firewall With Advanced Security%%4Firewall.evtx' WHERE EventID = 2005 GROUP BY localport ORDER BY CNT ASC"   -filemode:0
ECHO group by rulename  >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select COUNT(*) as CNT, extract_token(strings, 1, '|') as rulename  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Microsoft-Windows-Windows Firewall With Advanced Security%%4Firewall.evtx' WHERE EventID = 2005 GROUP BY rulename ORDER BY CNT ASC"   -filemode:0
ECHO group by servicename >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select COUNT(*) as CNT, extract_token(strings, 4, '|') as servicename  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Microsoft-Windows-Windows Firewall With Advanced Security%%4Firewall.evtx' WHERE EventID = 2005 GROUP BY servicename ORDER BY CNT ASC"   -filemode:0
ECHO group by apppath >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select COUNT(*) as CNT, extract_token(strings, 3, '|') as apppath  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Microsoft-Windows-Windows Firewall With Advanced Security%%4Firewall.evtx' WHERE EventID = 2005 GROUP BY apppath ORDER BY CNT ASC"   -filemode:0
ECHO group by user >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select extract_token(strings, 1, '|') as user, count(*) as cnt  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Microsoft-Windows-TaskScheduler%%4Operational.evtx' WHERE EventID = 141 GROUP BY user ORDER BY CNT ASC"   -filemode:0


ECHO group by taskname >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select extract_token(strings, 0, '|') as taskname, count(*) as cnt  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Microsoft-Windows-TaskScheduler%%4Operational.evtx' WHERE EventID = 141 GROUP BY taskname ORDER BY CNT ASC"   -filemode:0


ECHO group by user >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select extract_token(strings, 1, '|') as user, count(*) as cnt  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Microsoft-Windows-TaskScheduler%%4Operational.evtx' WHERE EventID = 140 GROUP BY user ORDER BY CNT ASC"   -filemode:0



ECHO group by taskname >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select extract_token(strings, 0, '|') as taskname, count(*) as cnt  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Microsoft-Windows-TaskScheduler%%4Operational.evtx' WHERE EventID = 140 GROUP BY taskname ORDER BY CNT ASC"   -filemode:0

ECHO group by action >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select extract_token(strings, 1, '|') as taskaction, count(*) as cnt  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Microsoft-Windows-TaskScheduler%%4Operational.evtx' WHERE EventID = 200 GROUP BY taskaction ORDER BY CNT ASC"   -filemode:0

ECHO group by taskname >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select extract_token(strings, 0, '|') as taskname, count(*) as cnt  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Microsoft-Windows-TaskScheduler%%4Operational.evtx' WHERE EventID = 100 GROUP BY taskname ORDER BY CNT ASC"   -filemode:0



ECHO group by service name >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select COUNT(*) as CNT, extract_token(strings, 0, '|') as servicename  INTO WELDS.txt FROM System.evtx WHERE EventID = 7036 GROUP BY servicename ORDER BY CNT ASC"   -filemode:0


ECHO group by username  >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) AS CNT, extract_token(strings, 3, '|') AS Username  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5136' GROUP BY Username ORDER BY CNT ASC"   -filemode:0

ECHO group by domain  >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) AS CNT, extract_token(strings, 4, '|') AS Domain  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5136' GROUP BY Domain ORDER BY CNT ASC"   -filemode:0

ECHO group by objectdn  >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) AS CNT, extract_token(strings, 8, '|') AS objectdn  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5136' GROUP BY objectdn ORDER BY CNT ASC"   -filemode:0

ECHO group by objectclass >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) AS CNT, extract_token(strings, 10, '|') AS objectclass  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5136' GROUP BY objectclass ORDER BY CNT ASC"   -filemode:0

ECHO group by objectattrib >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) AS CNT, extract_token(strings, 11, '|') AS objectattrib  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5136' GROUP BY objectattrib ORDER BY CNT ASC"   -filemode:0

ECHO group by attribvalue >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) AS CNT, extract_token(strings, 13, '|') AS attribvalue  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5136' GROUP BY attribvalue ORDER BY CNT ASC"   -filemode:0



ECHO group by rule name >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select Count(*) as CNT, extract_token(strings, 2, '|') as rulename  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4948 GROUP BY rulename ORDER BY CNT ASC"   -filemode:0


ECHO group by rule name  >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select Count(*) as CNT, extract_token(strings, 2, '|') as rulename  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4946 GROUP BY rulename ORDER BY CNT ASC"   -filemode:0



ECHO group by username >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select EXTRACT_TOKEN(Strings, 1, '|') AS Username, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4776 AND Username NOT LIKE '%%$' GROUP BY Username ORDER BY CNT ASC"   -filemode:0
ECHO group by domain  >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select EXTRACT_TOKEN(Strings, 2, '|') AS Domain, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4776 GROUP BY Domain ORDER BY CNT ASC"   -filemode:0


ECHO group by users >> WELDS.txt
LogParser.exe -stats:OFF -i:EVT "SELECT EXTRACT_TOKEN(Strings, 5, '|') as Username, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Username NOT LIKE '%%$' GROUP BY Username ORDER BY CNT ASC"   -filemode:0

ECHO group by domain  >> WELDS.txt
LogParser.exe -stats:OFF -i:EVT "SELECT EXTRACT_TOKEN(Strings, 6, '|') as Domain, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4624 GROUP BY Domain ORDER BY CNT ASC"   -filemode:0

ECHO group by authpackage >> WELDS.txt
LogParser.exe -stats:OFF -i:EVT "SELECT EXTRACT_TOKEN(Strings, 9, '|') as AuthPackage, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4624 GROUP BY AuthPackage ORDER BY CNT ASC"   -filemode:0

ECHO group by LogonType >> WELDS.txt
LogParser.exe -stats:OFF -i:EVT "SELECT EXTRACT_TOKEN(Strings, 8, '|') as LogonType, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4624 GROUP BY LogonType ORDER BY CNT ASC"   -filemode:0

ECHO group by workstation name  >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT EXTRACT_TOKEN(Strings, 11, '|') as Workstation, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4624 GROUP BY Workstation ORDER BY CNT ASC"   -filemode:0
ECHO group Logons (4624) by process name 
LogParser.exe -stats:OFF -i:EVT "SELECT EXTRACT_TOKEN(Strings, 17, '|') as ProcName, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4624 GROUP BY ProcName ORDER BY CNT ASC"   -filemode:0
ECHO group by apppath >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select COUNT(*) as CNT, extract_token(strings, 3, '|') as apppath  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Microsoft-Windows-Windows Firewall With Advanced Security%%4Firewall.evtx' WHERE EventID = 2004 GROUP BY apppath ORDER BY CNT ASC"   -filemode:0
ECHO group by user >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT extract_token(strings, 0, '|') as user, COUNT(user) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4771 AND user NOT LIKE '%%$' GROUP BY user ORDER BY CNT ASC"   -filemode:0
ECHO group by user  >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT extract_token(strings, 0, '|') as user, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4769 AND user NOT LIKE '%%$' GROUP BY user ORDER BY CNT ASC"   -filemode:0
ECHO group by domain  >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT extract_token(strings, 1, '|') as domain, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4769 GROUP BY domain ORDER BY CNT ASC"   -filemode:0
ECHO group by service >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT extract_token(strings, 2, '|') as service, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4769 GROUP BY service ORDER BY CNT ASC"   -filemode:0
ECHO group by cipher >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT extract_token(strings, 5, '|') as cipher, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4769 GROUP BY cipher ORDER BY CNT ASC"   -filemode:0
ECHO group by user  >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT extract_token(strings, 0, '|') as user, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4768 AND user NOT LIKE '%%$' GROUP BY user ORDER BY CNT ASC"   -filemode:0
ECHO group by domain >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT extract_token(strings, 1, '|') as domain, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4768 GROUP BY domain ORDER BY CNT ASC"   -filemode:0
ECHO group by cipher >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT extract_token(strings, 7, '|') as cipher, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4768 GROUP BY cipher ORDER BY CNT ASC"   -filemode:0

ECHO group by process name - Process Creation 4688 >> WELDS.txt
LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) AS CNT, EXTRACT_TOKEN(Strings, 5, '|') AS Process  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4688 GROUP BY Process ORDER BY CNT ASC"   -filemode:0


ECHO group by username  - Process Creation 4688 >> WELDS.txt
ECHO LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) AS CNT, EXTRACT_TOKEN(Strings, 1, '|') AS Username  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4688 GROUP BY Username ORDER BY CNT ASC"   -filemode:0
ECHO group by username >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select EXTRACT_TOKEN(Strings, 1, '|') AS Username, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4672 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Username NOT LIKE '%%$' GROUP BY Username ORDER BY CNT ASC"   -filemode:0
ECHO group by domain  >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "Select EXTRACT_TOKEN(Strings, 2, '|') AS Domain, COUNT(*) AS CNT  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4672 AND Domain NOT IN ('NT AUTHORITY') GROUP BY Domain ORDER BY CNT ASC"   -filemode:0
ECHO group by accountname >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) as CNT, extract_token(strings, 1, '|') as accountname  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4648 GROUP BY accountname ORDER BY CNT ASC"   -filemode:0
ECHO group by used account >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) as CNT, extract_token(strings, 5, '|') as usedaccount  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4648 GROUP BY usedaccount ORDER BY CNT ASC"   -filemode:0
ECHO group by ntlm users >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) AS CNT, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 10, '|') as LogonType,EXTRACT_TOKEN(strings, 11, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 13, '|') AS Workstation, EXTRACT_TOKEN(Strings, 19, '|') AS SourceIP  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4625 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND AuthPackage LIKE '%%NtLmSsp%%' AND Username NOT LIKE '%%$' GROUP BY Username, Domain, LogonType, AuthPackage, Workstation, SourceIP ORDER BY CNT ASC"   -filemode:0
ECHO group by Username >> WELDS.txt
 LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) AS CNT, EXTRACT_TOKEN(Strings, 5, '|') as Username  INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4625 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Username NOT LIKE '%%$' GROUP BY Username ORDER BY CNT ASC"   -filemode:0
 

REM event id 4688
REM new process was created - powershell.exe and Group By args
LogParser.exe -stats:OFF -i:EVT "SELECT count(*) as CNT, EXTRACT_TOKEN(Strings, 5, '|') AS Process, EXTRACT_TOKEN(Strings, 8, '|') as Args INTO WELDS.txt FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE Process LIKE '%shell%' AND EventID = 4688 GROUP BY Process, Args ORDER BY Args ASC"  -filemode:0

ECHO 'ProcTree' - Parent and Child Processes - One Started the Other, but not always clear which one is parent is child. 
ECHO Ordered By Count
LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) AS CNT, EXTRACT_TOKEN(Strings, 5, '|') AS Proc1, extract_token(strings, 13, '|') as Proc2  INTO WELDS.txt  FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4688 AND (Proc1 LIKE '%.%' AND Proc2 LIKE '%.%') GROUP BY Proc1, Proc2 ORDER BY CNT ASC"
 
ECHO Ordered by Proc1
LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) AS CNT, EXTRACT_TOKEN(Strings, 5, '|') AS Proc1, extract_token(strings, 13, '|') as Proc2  INTO WELDS.txt  FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4688 AND (Proc1 LIKE '%.%' AND Proc2 LIKE '%.%') GROUP BY Proc1, Proc2 ORDER BY Proc1 ASC"

ECHO Event ID - 4688 0 Ordered by Proc1
LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) AS CNT, EXTRACT_TOKEN(Strings, 5, '|') AS Proc1, extract_token(strings, 13, '|') as Proc2, EXTRACT_TOKEN(Strings, 8, '|') as Args    FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4688 AND (Proc1 LIKE '%cmd%' OR Proc2 LIKE '%cmd%') GROUP BY Proc1, Proc2, Args ORDER BY Proc1 Args"

ECHO Event ID - 4688 0 Ordered by CNT
LogParser.exe -stats:OFF -i:EVT "SELECT COUNT(*) AS CNT, EXTRACT_TOKEN(Strings, 5, '|') AS Proc1, extract_token(strings, 13, '|') as Proc2, EXTRACT_TOKEN(Strings, 8, '|') as Args    FROM '.\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4688 AND (Proc1 LIKE '%cmd%' OR Proc2 LIKE '%cmd%') GROUP BY Proc1, Proc2, Args ORDER BY CNT"

