# FractalGo — prototipo de custodia persistente G15

**Estado: módulo aislado. No es una nueva aplicación FractalGo completa y no cambia G14.**

El entorno de ejecución local de la sesión devolvió InvalidArgumentError antes de ejecutar incluso comandos mínimos. Se utiliza esta rama aislada del repositorio de referencia para conservar el código y ejecutar sus pruebas con GitHub Actions. No se suben expedientes, claves, documentos privados ni el paquete G14. La rama master permanece intacta. No se ejecutan los scripts antiguos del repositorio.

## Qué implementa

- Contenido cifrado con AES-256-GCM ANTES de escribirlo en SQLite. La base almacena identificadores opacos, tamaños implícitos, orden, nonces, ciphertext y hashes del ciphertext; no títulos ni índices de texto ni hashes del contenido en claro.
- PBKDF2-HMAC-SHA256, sal aleatoria de 32 bytes, 600.000 iteraciones. No se implementan primitivas criptográficas propias.
- Cada versión autentica como AAD el formato, la bóveda, el registro, su secuencia, el identificador de revisión y el hash del padre.
- Inserción de revisión y actualización de cabeza dentro de BEGIN IMMEDIATE. Una escritura exige el último hash esperado: un cliente antiguo no sobreescribe una revisión más nueva.
- Reintento idempotente con record_id + request_id: la misma solicitud devuelve su recibo; reutilizar el identificador con otro contenido se rechaza.
- Lectura de versiones anteriores sin borrarlas. Verificación de la cadena y los tags antes de devolver contenido.
- Copia coherente de la base cifrada mediante SQLite.backup. El destino debe ser nuevo.
- Bloqueo del objeto, permisos de archivo 0600 en POSIX y rechazo de enlaces simbólicos directos. No se promete borrado forense de claves o contenidos en RAM.
- Recibos externos que permiten detectar la restauración de un prefijo antiguo respecto de una versión que el usuario ya conservó. Sin recibo independiente, una base antigua válida puede seguir siendo válida: no hay garantía mágica de frescura.

## Qué NO implementa

No hay todavía autosave cifrado dentro de G14, sustitución de IndexedDB, control de los checkpoints localStorage heredados, integración con el servidor G14, servicio multiusuario, sincronización, renovación/revocación de claves, firma de recibos, vigilancia remota ni prueba humana.

Este módulo recibe bytes opacos. **No valida el significado científico ni el contrato documental completo de esos bytes.** La aplicación debe ejecutar sus validadores antes de guardar y después de restaurar; recuperar bytes exactos no aprueba sus conclusiones.

No hay datos científicos nuevos. Las pruebas usan cadenas explícitamente identificadas como fixtures de software, alteraciones de ciphertext y concurrencia controlada. No se presentan como resultados empíricos del proyecto.

## Uso local

Python 3.11 o posterior. La dependencia fijada es una versión experimental reproducible, no una afirmación de que sea la más reciente ni una certificación de seguridad.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r fractalgo_custody/requirements.txt
python -m unittest discover -s fractalgo_custody -p 'test_*.py' -v

# Crear bóveda; se solicita y confirma la contraseña sin eco.
python fractalgo_custody/vault.py init investigacion.sqlite

# Almacenar bytes exactos de una exportación G14. El archivo original NO se borra.
python fractalgo_custody/vault.py put investigacion.sqlite --input expediente.json

# El comando devuelve record_id y digest. Para la siguiente revisión,
# utilizar esos valores reales con --record y --expect.
python fractalgo_custody/vault.py list investigacion.sqlite
python fractalgo_custody/vault.py verify investigacion.sqlite
python fractalgo_custody/vault.py backup investigacion.sqlite --output respaldo.sqlite
```

`get` requiere `--record` y un `--output` que no exista. Escribe una copia **en claro** con permisos 0600 y lo advierte. No cifra otras copias que ya estaban en disco. Guardar en la bóveda no modifica ni elimina el archivo de entrada.

Para usar la API, importar `Vault` desde `vault.py`. `save` devuelve un `Receipt`; conservarlo fuera del almacén que se quiere vigilar. `read(..., anchor=recibo)` comprueba que la versión conocida siga formando parte de la historia.

## Amenazas y límites

- Un propietario del equipo, administrador, malware, extensión o proceso comprometido puede leer el estado mientras está desbloqueado. El directorio de la base se considera de confianza; no hay sandbox contra sustituciones concurrentes del filesystem por un atacante con esos permisos.
- La contraseña se utiliza para derivar una clave en memoria. Perderla implica perder acceso. Su mínimo de longitud no demuestra entropía.
- Las revisiones, los identificadores y tamaños revelan metadatos de actividad. AES-GCM no oculta el tamaño ni la existencia de la base.
- La API es append-only, pero quien controle directamente el fichero puede borrarlo o sustituirlo. AEAD detecta alteraciones de registros; una copia coherente antigua requiere un anclaje independiente para detectar rollback.
- El recibo es una referencia de integridad, no una firma, un sello de tiempo externo ni identidad del autor.
- Se comprueba la cadena completa antes de leer/escribir: coste creciente con las revisiones. No se reivindica memoria o cómputo constante.
- La biblioteca SQLite sigue siendo un parser de ficheros. trusted_schema=OFF reduce una superficie, no hace inocuo un archivo hostil ni protege frente a vulnerabilidades de sus dependencias.
- El backup es cifrado porque copia registros ya cifrados, no porque SQLite entero esté cifrado. Los metadatos del esquema son visibles.
- La compatibilidad Web Crypto/Node/Python de G14 NO ha sido revalidada por estos tests.

## Hallazgos estáticos sobre el HTML G14 suministrado

1. `initDB` abre `fractalgo-desk-g08`. `persist` escribe `title`, `source` y `envelope` sin cifrado en IndexedDB. Cifrar el export no modifica esa ruta.
2. `r4Checkpoint` conserva `r4Export()` en `localStorage['fractalgo-g04-checkpoint']`; ese objeto contiene `truth` y eventos. Una integración segura debe tratar también esa ruta, no sólo la mesa documental.
3. El control de conflicto de `persist` rechaza una cabeza distinta cuando el registro existe, pero su condición actual no rechaza automáticamente que el registro haya desaparecido mientras `expected` sigue apuntando a una versión anterior. Debe probarse el caso de eliminación concurrente y restauración obsoleta.

Son observaciones de código, no pruebas dinámicas de explotación ni una auditoría total.

## Gate de integración G14 → custodia

- Inventariar y sustituir TODOS los writers: IndexedDB, checkpoints localStorage y respaldo SQLite ordinario. No colocar un botón 'cifrar' mientras permanezca una ruta paralela inadvertida.
- Detener escritura persistente en claro antes de cargar información sensible. Mantener claramente diferenciados: sesión volátil, bóveda bloqueada, desbloqueada, conflicto, error, verificación y migración pendiente.
- Validar el expediente con los contratos G07–G14, cifrar y realizar compare-and-swap. Confirmar 'guardado' sólo después del COMMIT.
- Migrar primero copiando a un destino nuevo; desbloquear y restaurar; comparar bytes y estado; pedir confirmación separada para cualquier limpieza. No borrar respaldos ni prometer borrado forense.
- Conservar el recibo independiente. Un descendiente nuevo no reinicia deuda, autorización o procedencia.
- Probar dos escritores, cierre durante guardado, cuota agotada, contraseña errónea, base corrupta, rollback y continuidad del cálculo.
- Probar la ruta real en navegador con Web Crypto e IndexedDB habilitados, sin inyectar falsos proveedores para declarar éxito.

## Pendientes integrales, no sustituidos por este módulo

| Línea | Próximo resultado exigible |
|---|---|
| Custodia de trabajo | Integración real del módulo con TODOS los canales persistentes de G14; migración verificable. |
| Fuentes remotas | Catálogo y permiso por fuente, HTTPS, controles SSRF, límites, redirecciones comprobadas, cola de cambios; nunca actualización/admisión automática de conclusiones. |
| Colaboración | Identidad autenticada, roles por operación, concurrencia y revocación efectivas; una firma o un archivo compartido no las sustituye. |
| Núcleo FractalGo | Volumen y proyecciones, identificación, sondas y simientes conservados; ensayos futuros con evidencia externa y presupuestos comparables. |
| Interoperabilidad KCH/SCA | Adaptadores con scope/lease/permiso/autoridad separados; sin adjudicar autoridad a la simiente. |
| UX real | Tareas observadas con participantes, dispositivos físicos, Safari/iOS, teclado y lectores de pantalla. No tiempos o satisfacción inventados. |
| Seguridad externa | Revisión independiente de dependencias, modelo de amenazas y pruebas antes de usarlo con material de alto riesgo. |

## Reproducción y evidencia

`python fractalgo_custody/ci.py` ejecuta las pruebas y escribe resultados reales en `evidence/validation.json`, `unittest.txt`, `dependencies.txt` y un manifiesto. No se incluyen resultados precocinados.

El workflow ejecuta sólo este directorio, sin instalar ni invocar el código histórico. Tiene permisos de lectura y no utiliza secretos, documentos privados ni credenciales del usuario. La salida registra el commit realmente probado. El artifact contiene código y evidencia, nunca la base temporal o la contraseña de un usuario.

## Fuentes primarias

- AESGCM y autenticación de datos asociados: https://cryptography.io/en/latest/hazmat/primitives/aead/
- PBKDF2 y derivación: https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
- Transacciones SQLite: https://www.sqlite.org/lang_transaction.html
- Copias de seguridad SQLite en Python: https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.backup

La licencia de este directorio sigue la licencia raíz del repositorio. No se ha copiado aquí el código ni datos privados de G14.
