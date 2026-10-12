# Comprobación de fuentes y custodia — alcance real

`source_check.py` añade una consulta HTTPS explícita y una cola cifrada de revisiones. Es un módulo ejecutable desde Python, no un botón ya integrado en G14 y no un servicio de vigilancia programada.

## Flujo

1. Declarar la URL exacta y los límites de tipo/tamaño.
2. Desbloquear la bóveda. Si está bloqueada, no comienza ninguna solicitud externa.
3. Validar permiso, sintaxis y TODAS las direcciones DNS devueltas. No se aceptan direcciones locales, privadas, reservadas, multicast, mapeadas ni hosts literales.
4. Conectar a una dirección numérica previamente validada, sin volver a resolver el nombre durante la conexión. TLS valida el nombre original y su cadena mediante la biblioteca del sistema. Esto es fijación de la dirección por solicitud, no pinning permanente de certificados.
5. No seguir redirecciones, no enviar cookies o autorización, no utilizar variables de proxy ni ejecutar el contenido. Las respuestas comprimidas se rechazan; no se descomprimen paquetes arbitrarios.
6. Comprobar estado HTTP, tipo MIME, tamaño y completitud. Errores no significan que la fuente haya desaparecido o permanezca igual.
7. Comparar los bytes completos con la captura anterior y cifrar cuerpo y metadatos antes de guardarlos.
8. Emitir `FIRST_CAPTURE_REQUIRES_REVIEW`, `UNCHANGED_BYTES` o `CHANGE_REQUIRES_REVIEW`.

Una comprobación sin cambios crea un recibo nuevo de actividad, pero **no una nueva fuente independiente**. Detectar cambio tampoco aprueba automáticamente una nueva edición, una cita ni una conclusión. El estado conserva `scientific_evidence_admitted=false` y `execution_authority=NONE`.

La historia usa un identificador aleatorio. Para volver a comprobar la misma fuente, reutilizar el `record_id` del recibo anterior con `--source-id`. No se deriva públicamente la identidad del registro a partir de la URL.

## Uso

```bash
python fractalgo_custody/vault.py init trabajo.sqlite
python fractalgo_custody/source_check.py trabajo.sqlite \
  https://docs.python.org/3.12/library/sqlite3.html \
  --allow-exact-url https://docs.python.org/3.12/library/sqlite3.html
```

Para la siguiente comprobación, añadir `--source-id` con el identificador REAL devuelto por la primera. La contraseña se solicita sin eco; no se incluye en los argumentos.

El comando no publica el documento ni su contenido en el repositorio. Sí realiza una petición que el servidor remoto puede registrar. No debe usarse para inferir que la investigación es anónima.

## Deliberadamente restringido

Sólo HTTPS por puerto 443, sin query strings, fragmentos o credenciales. La URL debe estar codificada en ASCII; no se normalizan silenciosamente rutas ambiguas. Máximo absoluto 8 MiB, predeterminado 2 MiB. Se prueban hasta dos direcciones ya validadas.

No hay crawler, descubrimiento de enlaces, autenticación web, robots parser, tratamiento de captchas, extracción de PDF ni scraping con navegador. La lectura de una página no concede derechos de redistribución sobre ella.

Los límites temporales son de conexión/lectura. DNS y la lectura de cabeceras dependen del resolvedor y de la biblioteca: desplegar con un límite exterior de proceso y una política de salida de red. No se presenta como firewall ni sandbox.

El MIME y el estado 200 no autentican el significado del archivo. Un servidor puede responder con una página de bloqueo o un error semántico bajo 200; por eso toda captura nueva queda pendiente de revisión.

## Qué se prueba

Los tests unitarios usan respuestas ficticias etiquetadas como fixtures: redirecciones, destinos privados, truncamiento, compresión, error HTTP, concurrencia y guardado cifrado. No son mediciones científicas.

`live_probe.py` hace dos GET a una página pública concreta de la documentación de Python y prueba guardado, reapertura y recuperación exacta. Publica únicamente metadatos, hash y resultado del recorrido; nunca los bytes del documento ni las claves temporales. Registra éxito o fracaso por separado del resultado de las pruebas unitarias.

`ci.py` sólo ejecuta esa prueba de red cuando `FG_RUN_PUBLIC_SOURCE_PROBE=1`. La validación local ordinaria no realiza solicitudes externas.

## Integración pendiente con la aplicación

- Convertir las capturas revisadas en cápsulas documentales conservando el original y su método de extracción.
- Utilizar el flujo G11/G12 de nuevas ediciones y alcance afectado; no saltárselo porque el archivo llegó por red.
- Presentar cola de cambios, falta de acceso y última comprobación efectiva con estados distintos.
- Configurar periodicidad sólo por permiso explícito; no hay scheduler instalado por este módulo.
- Cubrir TODOS los lugares de persistencia antes de afirmar almacenamiento cifrado de toda la aplicación.
- Evaluar en navegador y con participantes la tarea completa de revisión, no sólo el endpoint.

## Antecedentes primarios

https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

https://docs.python.org/3/library/http.client.html

https://docs.python.org/3/library/ssl.html

Estas referencias no constituyen una auditoría independiente de este código.
