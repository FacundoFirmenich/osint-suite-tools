# FractalGo G15 — núcleo de custodia y comprobación de fuentes

**Módulos aislados en desarrollo. No es una nueva interfaz G15 y no modifica el HTML G14.**

El runtime local de la sesión falló con `InvalidArgumentError` incluso ante comandos mínimos. El código y sus pruebas se conservaron y ejecutaron mediante GitHub Actions en `fractalgo/g15-custody-prototype`. `master` permanece intacto. Este directorio no contiene expedientes, claves, documentos privados ni código copiado del paquete G14. No se ejecuta el código antiguo de este repositorio de referencia.

## Capacidades implementadas

### Bóveda de revisiones: `vault.py`

- AES-256-GCM antes de escribir contenido en SQLite. No se envían al motor SQL títulos, cuerpos documentales ni hashes del contenido en claro. Metadatos de actividad, identificadores aleatorios, tamaños, secuencia y hashes del ciphertext siguen siendo visibles.
- PBKDF2-HMAC-SHA256, sal aleatoria de 32 bytes y 600.000 iteraciones. Se usan las primitivas de `cryptography`, no criptografía inventada.
- AAD vincula cada revisión a su formato, bóveda, registro, secuencia, identificador y hash del padre.
- Revisión y actualización de cabeza en `BEGIN IMMEDIATE`. El hash esperado debe coincidir: no hay sobreescritura silenciosa entre escritores.
- Reintentos idempotentes con `record_id` y `request_id`; un mismo identificador no puede reaparecer con contenido distinto.
- Lectura de versiones anteriores, verificación de cadena y autenticación antes de devolver contenido.
- Copia coherente mediante `SQLite.backup`, sólo a un destino nuevo; se comprueba la restauración en pruebas.
- Bloqueo de la instancia y ficheros 0600 en POSIX. No se promete borrado forense de claves o datos en RAM.
- Recibo externo para detectar retroceso respecto de una revisión conocida. Una base antigua coherente requiere un anclaje independiente para detectar que no es la última; cifrado y hash no demuestran frescura.

### Comprobación de fuentes: `source_check.py`

Una ejecución consulta una única URL pública autorizada de forma explícita. No hay crawler, cookies, credenciales, proxies, redirecciones automáticas, extracción ni ejecución del contenido.

Se validan todas las direcciones DNS y la conexión utiliza una dirección numérica ya comprobada, conservando la validación TLS del nombre original. Hay límites de tamaño, MIME, conexión y lectura. Se requieren límites exteriores de proceso y red en un despliegue, especialmente para DNS y cabeceras.

La respuesta completa y sus metadatos se guardan en la bóveda. El estado devuelto distingue `FIRST_CAPTURE_REQUIRES_REVIEW`, `UNCHANGED_BYTES` y `CHANGE_REQUIRES_REVIEW`. Una nueva comprobación no se presenta como una fuente independiente ni aprueba conclusiones. Detalles en [SOURCES.md](SOURCES.md).

## Uso

Desde este directorio —o desde el ZIP de artefactos, que contiene estos archivos—:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -p 'test_*.py' -v

python vault.py init investigacion.sqlite
python vault.py list investigacion.sqlite
python vault.py verify investigacion.sqlite

python source_check.py investigacion.sqlite \
  https://docs.python.org/3.12/library/sqlite3.html \
  --allow-exact-url https://docs.python.org/3.12/library/sqlite3.html

python vault.py backup investigacion.sqlite --output respaldo.sqlite
```

La contraseña se solicita sin eco. Para almacenar un expediente, `put` recibe `--input` con su archivo real y devuelve un recibo. Para continuarlo, usar su `record_id` y `digest` con `--record` y `--expect`. El archivo original NO se borra. Para reconsultar una fuente, reutilizar el identificador del recibo con `--source-id`.

`get` requiere `--record` y un `--output` inexistente: crea una copia **en claro** y lo advierte. `--anchor` permite comprobar un recibo conservado fuera de la bóveda. Un recibo no es firma, identidad, autorización ni sello de tiempo externo.

## Evidencia de ejecución

El workflow ejecuta solamente este directorio, con permisos de lectura y sin secretos de usuario. `ci.py` realiza la batería en su proceso y la repite en otro proceso nuevo. Publica los resultados reales en `evidence/validation.json`, los dos logs, las dependencias y el manifiesto.

Si `FG_RUN_PUBLIC_SOURCE_PROBE=1`, `live_probe.py` realiza además dos GET a una página pública concreta de la documentación de Python y comprueba su guardado y recuperación cifrada. Su éxito o fallo se registra **separado** del resultado unitario. No publica los bytes del documento ni la clave temporal.

Los tests de red utilizan fixtures explícitas. No son observaciones científicas ni pruebas contra objetivos reales. El ensayo vivo verifica transferencia, custodia y recuperación; no añade evidencia al modelo de FractalGo.

La primera batería de custodia pasó 31 pruebas. Al ampliar a fuentes, pasaron 56 pruebas de contratos pero falló la consulta viva. Una prueba nueva reprodujo el defecto: se intentaba cambiar el timeout de un socket ya cerrado después de recibir `Content-Length` bytes. El commit fallido `325f5d08b71d9b31844c27bffd1cd13dfa2533ae` conserva esa evidencia. La corrección termina la lectura al recibir exactamente el cuerpo declarado, sin debilitar controles. Consultar el artifact del commit actual para el resultado definitivo; no hay cifras de aprobación prefijadas en el código.

## Qué sigue fuera de alcance

- No está integrado con el autosave de G14, IndexedDB o checkpoints heredados de localStorage. **Instalar este módulo no cifra automáticamente el trabajo que sigue guardando G14.**
- No se volvió a ejecutar la batería ancestral G14 ni se realizó QA de su interfaz. No hay nuevo HTML, captura visual o prueba móvil en esta ronda.
- La bóveda recibe bytes opacos: no valida el significado científico ni los contratos documentales completos. La integración deberá validar antes de guardar y después de restaurar.
- No hay scheduler de fuentes, revisión semántica, notificación, revocación de claves, servidor multiusuario ni sincronización.
- No hay nuevos datos científicos, entrenamiento neuronal, experimento multifractal o evaluación con participantes.

## Hallazgos estáticos en el G14 suministrado

1. `initDB` abre `fractalgo-desk-g08`. `persist` almacena `title`, `source` y `envelope` sin cifrar en IndexedDB.
2. `r4Checkpoint` conserva `r4Export()` en `localStorage['fractalgo-g04-checkpoint']`; el export contiene el volumen `truth` y eventos. Una bóveda de la mesa documental no basta si esta ruta sigue escribiendo en claro.
3. El control de conflicto de `persist` sólo comprueba una cabeza distinta si existe el registro. El caso de una eliminación concurrente debe impedir que un escritor obsoleto lo recree silenciosamente. El núcleo nuevo sí tiene un test específico para rechazarlo.

Son observaciones de código, no auditoría completa ni explotación dinámica de G14.

## Migración necesaria antes de afirmar protección integral

1. Inventariar y sustituir todos los writers persistentes, incluidos checkpoints y SQLite ordinario.
2. Mostrar estados separados: sesión volátil, bóveda bloqueada, desbloqueada, conflicto, fallo y migración pendiente. Confirmar guardado sólo tras COMMIT.
3. Validar con los contratos G07–G14, cifrar y realizar compare-and-swap.
4. Copiar primero a un destino nuevo; restaurar; comparar bytes y estado; sólo después ofrecer una limpieza separada y confirmada. No prometer borrado forense.
5. Conservar recibo independiente y las cuentas de genealogía/autoridad. Un nuevo archivo no reinicia deuda ni permisos.
6. Ensayar cierres durante escritura, dos escritores, cuota agotada, clave incorrecta, base corrupta, rollback y continuidad del cálculo.
7. Probar Web Crypto e IndexedDB en un navegador permitido y dispositivos reales. No introducir proveedores falsos para declarar éxito.

## Amenazas y límites

El directorio de la base se considera de confianza. No hay sandbox contra un administrador local, malware, lectura de RAM o sustituciones concurrentes de archivos por quien ya controla ese directorio. `trusted_schema=OFF` no vuelve inocuo cualquier archivo SQLite hostil.

Los originales, respaldos anteriores y archivos recuperados en claro permanecen fuera de la protección de esta bóveda. La contraseña tiene mínimo de longitud, no garantía de entropía. No hay recuperación si se pierde.

La API es append-only, pero el propietario del archivo puede borrarlo. La verificación completa antes de operar tiene coste creciente con la historia; no se reivindica memoria o cómputo constante. La dependencia fijada es reproducible, no una afirmación de que sea la última versión o esté libre de vulnerabilidades.

## Mapa integral de pendientes

| Línea | Estado de esta entrega | Gate todavía necesario |
|---|---|---|
| Custodia persistente | Núcleo cifrado con revisiones y backup | Integrar todas las rutas de guardado de G14 y migrarlas |
| Actualización de fuentes | Comprobación HTTPS bajo petición y cola cifrada | UI, cápsulas documentales, programación consentida y admisión humana |
| Colaboración | Conflictos locales de escritor controlados | Identidades, roles y revocación por operación, sincronización efectiva |
| Claves | Bloqueo y verificación con clave de bóveda | Rotación, recuperación declarada y revocación, sin falsas garantías sobre copias previas |
| Núcleo científico | Sin cambios ni nuevos resultados | Volumen, sondas, simientes y multifractalidad con evidencia nueva y controles comparables |
| KCH/SCA | Separación de captura, evidencia y ejecución | Adaptadores operativos con alcance y autoridad externos |
| UX y accesibilidad | Sin nuevas métricas humanas | Dispositivos físicos, lectores de pantalla, estudio de tareas con participantes |
| Seguridad | Contratos automatizados y ensayo de integración | Revisión independiente, dependencias y pruebas antes de material de alto riesgo |

## Fuentes primarias

- https://cryptography.io/en/latest/hazmat/primitives/aead/
- https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
- https://www.sqlite.org/lang_transaction.html
- https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.backup
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

La licencia de este directorio sigue la licencia raíz del repositorio. No se ha copiado aquí código ni documentación privada del paquete G14.
