# NODO — Mensajería verificable

NODO es un sitio responsive creado con Rust y Dioxus. Funciona en navegadores de escritorio y móvil (macOS, Windows, Linux, Android e iOS); no es un instalador nativo. La interfaz ofrece español e inglés mediante el selector `ES`/`EN` y recuerda la selección en el navegador. Al abrir, pregunta si conectar MetaMask o continuar en demo. Rechazar o no tener wallet deja la demo disponible sin escrituras simuladas. Cuando la extensión está disponible, la conexión usa su proveedor EIP-1193 inyectado; MetaMask Connect EVM queda como fallback para los demás entornos, incluido el flujo móvil.

## Qué hace

- Al entrar, ofrece **Conectar wallet** o **Continuar en demo**. Sin wallet, presenta mensajes de muestra y notas locales de sesión, señaladas como **demo**; no se emite ninguna transacción ni se simula una escritura on-chain.
- Con wallet, solicita conexión a Ethereum Sepolia (`0xaa36a7`), indica cuenta y red, y reacciona a los cambios de cuenta/red.
- En **Nuevo mensaje**, puedes guardar cada contacto con nombre y dirección EVM, seleccionarlo en futuros mensajes, renombrarlo o eliminarlo. NODO persiste esa agenda en el almacenamiento local del mismo navegador/perfil; no puede importar la agenda de MetaMask ni sincronizar contactos entre dispositivos.
- Para leer o escribir registros on-chain, primero hay que desplegar `contracts/MessageBoard.sol` en Sepolia y pegar la dirección del contrato en **Estado de red → Configurar contrato**. El chat E2EE y las transferencias nativas no requieren ese contrato. No pegues ahí la URL RPC ni la dirección de tu cuenta MetaMask; la app comprueba que la dirección tenga bytecode de contrato en Sepolia.
- El historial de cadena combina mensajes recibidos y enviados de la cuenta activa, ordenados por identificador reciente.
- El contrato guarda solo un hash Keccak-256, remitente/destinatario, hora, estado e importe opcional en ETH de Sepolia. El cuerpo del mensaje no se envía al contrato; las direcciones, hashes, importes y tiempos sí son públicos y persistentes.
- El registro del contrato sigue siendo un anclaje de integridad, no el canal de entrega. La sección **Mensajería privada** añade chat E2EE con cola cifrada fuera de la cadena; el texto no se escribe en el contrato.
- La función payable `sendMessage` recibe ETH opcional. El destinatario puede reclamar una vez el pago; el remitente puede cancelar un mensaje no leído y recibir el reembolso si el pago no fue reclamado. El destinatario puede marcarlo como leído; el owner administra moderadores.
- Las reglas de owner, moderador, remitente y destinatario se imponen en el contrato con `require`, no solo en la interfaz.
- El usuario revisa el hash, la dirección y el importe antes de firmar en MetaMask. **Desconectar** oculta la cuenta en NODO hasta una nueva conexión explícita; no revoca los permisos persistentes de la wallet.

**Privacidad:** el hash del contrato no cifra un texto asociado. El chat privado usa Olm de Matrix (`vodozemac`), Triple-DH estilo X3DH y Double Ratchet; no es la implementación exacta de Signal X3DH ni una auditoría independiente de NODO. NODO no solicita, transmite ni guarda claves EVM privadas o frases semilla; MetaMask firma. La app aplica zeroization a buffers que controla, pero Rust/WASM, el allocator y algunos temporales internos del crate no ofrecen una garantía de borrado seguro de todas las copias de memoria. El contrato es educativo, no ha sido auditado y no debe usarse con fondos reales.

## Mensajería privada entre dos wallets

1. Abre NODO en dos perfiles/navegadores o cambia entre las dos cuentas MetaMask. Cada wallet crea un perfil de dispositivo local con una frase de desbloqueo de al menos 12 caracteres. El estado privado (claves Olm, ratchet y mensajes locales) se cifra con AES-256-GCM y PBKDF2-HMAC-SHA256 antes de guardarse en IndexedDB. Un Web Lock evita desbloquear el mismo perfil en dos pestañas simultáneas. Si borras los datos del navegador o pierdes esa frase, no hay recuperación ni copia de seguridad automática.
2. En cada cuenta pulsa **Vincular dispositivo** y aprueba la firma tipada EIP-712 de MetaMask en Sepolia. Es una firma fuera de la cadena: no despliega contrato, no transmite un mensaje ni requiere ETH de prueba/gas. La firma vincula una huella de clave de identidad al address de esa wallet. Esta primera versión solo verifica wallets EOA mediante recuperación de firma; wallets de contrato EIP-1271 no son compatibles.
3. Comparte la dirección pública de la otra wallet. Inspecciona su huella y confírmala antes de enviar. Si la huella cambia, NODO la marca como cambiada y no debe aceptarse sin volver a comprobarla con la otra persona por un canal independiente.
4. Guarda un nombre local para el contacto si quieres. Define tu **alias de identidad** y envía; tanto el cuerpo como ese alias viajan dentro del ciphertext. Al leer un mensaje, NODO muestra primero el nombre que tú guardaste localmente, y también el alias anunciado y la dirección wallet.
5. El destinatario abre NODO con su wallet, desbloquea y registra su perfil. Mientras la página está activa y el perfil desbloqueado, NODO renueva la presencia autenticada cada 15 segundos; cada lease del relay dura 45 segundos. Si el destinatario está offline, el ciphertext opaco queda en el buzón del relay y el emisor ve **esperando**; cuando vuelve y el lease se renueva, el buzón se sincroniza en segundo plano. No hay notificación push. El destinatario confirma el mensaje solo después de autenticar/descifrarlo y guardar el perfil local; envía un ACK ligado al hash Keccak del ciphertext. El emisor muestra **entregado** únicamente si el recibo del relay incluye el mismo hash, o muestra **rechazado**, **expirado** o un estado de integridad sin verificar/error si corresponde. El relay borra el ciphertext al aceptar el ACK y conserva solo el recibo mínimo hasta la expiración de siete días; sobres pendientes también expiran a los siete días y se purgan periódicamente. Una señal **online** es aproximada, no prueba que la persona esté mirando la pantalla; un ACK confirma descifrado y guardado, no que alguien haya abierto/leído el mensaje. Después de una respuesta, ambas partes reutilizan la sesión ratchet; mientras una sesión inicial espera esa primera respuesta, cada nuevo mensaje inicial usa otra prekey de un solo uso. Si expira una reserva de prekey mientras un mensaje inicial espera en la cola local, **Reintentar** genera un nuevo sobre con una nueva sesión/prekey, sin reutilizar la reserva antigua.

**Protocolo y límites:** se usa Olm de Matrix mediante `vodozemac`: Triple-DH/X3DH-style y Double Ratchet, no el protocolo Signal X3DH exacto. El formato Olm genera sus propias claves de mensaje e IV aleatorios autenticados; la aplicación no añade un nonce criptográfico paralelo. El payload incluye wallet/dispositivo de origen y destino, hora, ID único, alias y cuerpo cifrados. El relay sí puede observar wallets, dispositivos, IP, tiempos, tamaños y patrones de entrega; estos metadatos no son anónimos. El rate limiter actual es un guard básico en memoria por IP y por instancia; no protege contra abuso distribuido y debe endurecerse con cuotas compartidas/edge antes de un lanzamiento público sensible. Un alias es una etiqueta declarada por el usuario, no prueba de identidad. La identidad se comprueba mediante firma wallet–clave y huella del protocolo; confirma la huella por un canal aparte al primer uso.

La entrega E2EE no necesita ETH ni una transacción de contrato. Solo el botón opcional **Anclar hash en Sepolia** publica un hash de ciphertext y los metadatos visibles del contrato, y requiere ETH de prueba para gas. El texto claro y el alias no se anclan. NODO muestra el anclaje como confirmado solo cuando recibe un receipt exitoso; un hash pendiente no se presenta como confirmado. El servicio backend/base de datos de NODO conserva datos de desarrollo y producción compartidos: usa cuentas y mensajes sintéticos al probarlo.

## Desarrollo del sitio

### Conversaciones locales, actualización y retención

El panel lateral de registros incluye **Conversaciones privadas · locales**. Al desbloquear tu perfil se carga el índice cifrado de wallets con las que has conversado; elegir una abre su historial privado, no el texto de sus registros on-chain. La agenda local proporciona el nombre si lo guardaste. La actualización de presencia y mensajes mantiene montado el chat, su borrador y el scroll; al cambiar de interlocutor se separa el historial y se limpia el borrador anterior para evitar enviarlo a otra wallet.

El historial visible conserva una ventana móvil de **72 horas desde el envío**. NODO elimina los cuerpos anteriores, sus alias de mensaje y el ciphertext de reintento del perfil cifrado actual; no guarda un archivo, dump ni botón de recuperación. El índice de conversaciones y el estado necesario para futuros mensajes permanecen, junto con metadatos compactos y acotados para evitar replay/repetir ACK, sin el cuerpo eliminado. La limpieza ocurre al desbloquear, guardar y durante mantenimiento periódico aun sin autenticación del relay; si el navegador está cerrado, se aplica al siguiente desbloqueo. El límite de seguridad de cantidad también mantiene acotado el uso de memoria.

Además del límite temporal, el navegador conserva hasta 500 mensajes y 200 interlocutores. Los metadatos locales anti-replay son registros exactos de hasta 500 sobres vivos, sin texto/ciphertext, que caducan con el TTL del relay más 60 segundos. Si se llena ese almacén, NODO muestra el motivo y deja nuevos sobres cifrados pendientes sin avanzar el ratchet ni fabricar ACK hasta que haya capacidad. Las fechas de envío inválidas o demasiado futuras se muestran como no disponibles; el orden/retención usa la recepción local en ese caso, no una hora local presentada falsamente como la del emisor.

Este es borrado lógico de NODO con zeroization de los buffers que controla, **no una garantía de borrado forense**: el navegador, disco, copias temporales o el dispositivo de la otra persona pueden conservar restos/copias. Los registros públicos de Sepolia tampoco pueden eliminarse. La cola del relay mantiene su propia política de siete días; un mensaje que llega después de su ventana local no recupera su cuerpo en el historial ni se presenta como recién leído.

### Enviar ETH de prueba en Sepolia

El panel independiente **Transferir ETH de Sepolia** utiliza la wallet del interlocutor elegido y un importe positivo de hasta 18 decimales. Revisa la dirección y el importe, luego confirma la solicitud explícita de MetaMask. Es una transferencia nativa directa: no necesita `MessageBoard`, anclaje ni mensaje, y requiere ETH de prueba para el importe y el gas. Las wallets, hora e importe quedan públicos en Sepolia. La app distingue transacción pendiente, confirmada y revertida y permite consultar el receipt/explorador; no reintenta envíos automáticamente. Enviar o recibir mensajes, seleccionar un chat o actualizar la bandeja nunca dispara una transferencia.

### Ejecutar la aplicación y el relay en una computadora local

Este flujo crea una base MySQL **local y aislada**, inicia el relay Rust y sirve el bundle web en el mismo origen. No requiere copiar sus datos. Usa Docker Engine/Desktop con Docker Compose v2, Git, Rust estable, target WebAssembly y Dioxus CLI 0.7.10. No necesitas instalar MySQL por separado si usas Compose; para usar MetaMask, instala la extensión en dos perfiles de navegador distintos.

Clona el repositorio privado usando la URL HTTPS que aparece en GitHub en el botón **Code** (reemplaza los marcadores por los valores de tu repo):

```sh
git clone <URL-HTTPS-del-repositorio>
cd <directorio-del-repositorio>
```

Crea la configuración local a partir del ejemplo. En macOS/Linux:

```sh
cp .env.example .env
```

En Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Los valores incluidos solo sirven para desarrollo local; no los reutilices en producción. `.env` está ignorado por Git. No guardes ahí frases semilla, claves EVM, ni credenciales del proyecto administrado. La plantilla expone MySQL solo en `127.0.0.1:3307`; el relay y la web quedan en `127.0.0.1:3000`. Si el puerto 3307 está ocupado, cambia `NODO_MYSQL_PORT` en `.env`; para otro puerto web, ajusta solo el lado izquierdo de `127.0.0.1:3000:3000` en `compose.local.yaml`.

Compila el cliente web desde el código. Instala el target y CLI una vez:

```sh
rustup target add wasm32-unknown-unknown
cargo install dioxus-cli --locked --version 0.7.10
```

Desde la raíz del proyecto, genera el bundle estático:

```sh
# macOS/Linux, si se desea limpiar el bundle previo:
rm -rf dist
# Windows PowerShell, como alternativa:
# Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue

dx bundle --web --release --out-dir dist
```

Arranca la DB y el relay desde la raíz:

```sh
docker compose -f compose.local.yaml up --build
```

La primera compilación descarga dependencias e inicializa el volumen MySQL; puede tardar. El relay aplica automáticamente las migraciones SQL pendientes al conectarse a `nodo_local`. Cuando los servicios estén activos, abre **http://127.0.0.1:3000/**; **http://127.0.0.1:3000/_app/health** comprueba el relay y su conexión a MySQL. Para seguir los logs en otra terminal usa `docker compose -f compose.local.yaml logs -f relay`. `Ctrl+C` detiene el primer plano; `docker compose -f compose.local.yaml down` detiene los contenedores y **conserva** la base en su volumen. Solo para borrar íntegramente la DB local, ejecuta `docker compose -f compose.local.yaml down -v`; ese comando elimina permanentemente los datos de ese volumen.

**Alternativa: ejecutar el relay desde Rust.** Con Docker Compose, levanta solo la DB (`docker compose -f compose.local.yaml up -d db`) y compila el bundle como arriba. El archivo `.env` de ejemplo ofrece una base local en el puerto 3307. En macOS/Linux:

```sh
export DATABASE_URL='mysql://nodo_local:nodo_local_dev_only@127.0.0.1:3307/nodo_local'
export PORT=3000
export WEB_ROOT=dist/public
cargo run --locked --manifest-path server/Cargo.toml
```

En Windows PowerShell:

```powershell
$env:DATABASE_URL = 'mysql://nodo_local:nodo_local_dev_only@127.0.0.1:3307/nodo_local'
$env:PORT = '3000'
$env:WEB_ROOT = 'dist/public'
cargo run --locked --manifest-path server/Cargo.toml
```

`DATABASE_URL` es obligatoria. El servidor enlaza `0.0.0.0` internamente; si lo ejecutas nativamente, no expongas el puerto a redes no confiables y limita el acceso con el firewall. En Compose, el puerto publicado del host queda enlazado a loopback.

### Esquema de base de datos incluido en GitHub

El código SQL que define el schema está en [`migrations/`](migrations/); no incluye registros reales. SQLx compila esas migraciones en el relay y ejecuta las pendientes (`sqlx::migrate!("../migrations").run(&pool)`) al iniciar, contra la base especificada por `DATABASE_URL`. No hace falta importar los SQL manualmente. Las cuatro migraciones versionadas son:

| Archivo | Efecto principal |
| --- | --- |
| `0001_relay.sql` | Crea `relay_challenges`, `relay_sessions`, `relay_devices`, `relay_one_time_prekeys` y `relay_envelopes`, con claves, hashes, firmas públicas, índices y ciphertext opaco. |
| `0002_single_use_prekey_claims.sql` | Añade vencimiento del binding y reserva/consumo de prekeys vinculados de forma única al envelope. |
| `0003_delivery_presence_ack.sql` | Añade leases temporales de presencia, hash Keccak del ciphertext y estado de entrega/ACK. |
| `0004_envelope_id_tombstones.sql` | Crea `relay_envelope_ids` para impedir que se reutilice un UUID cuando se purga la fila del envelope. |

El relay guarda ciphertext y metadatos de transporte (wallets/dispositivos, horas/expiraciones, hashes de tokens y mensajes, presencia y estado); **no guarda el cuerpo en texto plano ni claves privadas**. Las claves/ratchets y el historial legible del usuario pertenecen al perfil cifrado local del navegador, no a estas tablas.

### Prueba local con dos perfiles MetaMask

1. Inicia el Compose local y abre la misma URL (`http://127.0.0.1:3000`) en **dos perfiles de navegador separados**, cada uno con una cuenta MetaMask distinta. Dos pestañas de un mismo perfil comparten IndexedDB y no sustituyen este aislamiento.
2. En ambas cuentas selecciona Sepolia, conecta la wallet, crea/desbloquea el perfil local y elige **Vincular dispositivo**. Revisa y aprueba la firma tipada EIP-712 de MetaMask. La firma vincula la identidad; es una firma fuera de cadena, no una transacción, y no cuesta gas.
3. Intercambia las direcciones públicas por un canal aparte; compara y confirma las huellas de identidad antes de enviar un mensaje sintético. Deja la segunda app abierta y desbloqueada para recibir. El emisor cifra localmente; el relay/MySQL local almacena el sobre cifrado; el receptor descifra en su propio perfil. Comprueba el texto y las marcas UTC en ambos lados, así como el estado/ACK de entrega.
4. Para probar la cola offline, cierra o bloquea el perfil receptor, envía un mensaje de prueba, luego vuelve a abrirlo y renueva su presencia. No uses datos personales ni mensajes sensibles para la primera validación.

El chat E2EE y la vinculación EIP-712 no necesitan ETH de prueba ni contrato `MessageBoard`; el chat solo requiere las wallets para firmar y la cadena Sepolia elegida en MetaMask. Solo el anclaje opcional de un hash, desplegar/interactuar con el contrato y la transferencia nativa requieren transacciones aprobadas y ETH de prueba para gas (y, si corresponde, el importe). La red Sepolia es pública: direcciones, importes, horas y hashes anclados son visibles. **No ha quedado registrada aquí una verificación live de entrega entre dos perfiles MetaMask; haz primero la prueba sintética anterior y no interpretes los tests unitarios como evidencia live.**

### Comprobaciones de desarrollo

Desde la raíz del repositorio:

```sh
cargo fmt --manifest-path Cargo.toml
cargo fmt --manifest-path server/Cargo.toml
cargo check --locked --manifest-path Cargo.toml
cargo check --locked --target wasm32-unknown-unknown --manifest-path Cargo.toml
cargo test --locked --manifest-path Cargo.toml
cargo test --locked --manifest-path server/Cargo.toml
```

## Pruebas y despliegue de prueba

Las pruebas del contrato usan Foundry:

```sh
forge test
```

Para una prueba en la red pública de **Sepolia** (solo ETH de prueba):

1. Instala MetaMask y habilita Sepolia. Obtén ETH de prueba desde un faucet vigente enlazado por la documentación de Ethereum; nunca uses fondos reales para probar.
2. Abre [Remix](https://remix.ethereum.org/), crea `MessageBoard.sol` y copia el contenido de `contracts/MessageBoard.sol`.
3. Compila con Solidity `0.8.24` o una versión posterior compatible con `pragma ^0.8.24`.
4. En **Deploy & Run**, selecciona **Injected Provider – MetaMask**, confirma que la wallet y Remix indiquen Sepolia, y despliega. Revisa la transacción y copia la dirección del contrato.
5. Abre NODO, conecta MetaMask en Sepolia, expande **Configurar contrato** y pega esa dirección. Recarga la bandeja; luego prueba con una cuenta destinataria y, opcionalmente, un importe pequeño de ETH de prueba.
6. Comprueba la transacción en [Etherscan Sepolia](https://sepolia.etherscan.io/). Las transacciones requieren aprobación explícita en MetaMask.

No se despliega automáticamente desde el sitio. El despliegue público requiere una firma en MetaMask y gasto de gas (en Sepolia, ETH de prueba). El contrato no ha sido auditado.

## Solución de problemas de conexión

Si NODO sigue en **DEMO** o muestra `Transport request timed out`, vuelve a la página NODO y pulsa **Conectar MetaMask** allí; abrir la extensión desde su icono no autoriza por sí solo al sitio. MetaMask recomienda iniciar `eth_requestAccounts` como respuesta directa al clic y desactivar el botón mientras la petición está pendiente; NODO sigue ese flujo ([guía oficial](https://metamask.github.io/mm-docs-v2/87-onboarding/wallet/get-started/access-accounts/)). Resuelve cualquier solicitud pendiente en la ventana de MetaMask y recarga la página si la solicitud anterior expiró. NODO usa directamente la extensión cuando Firefox/otro navegador inyecta el proveedor y conserva MetaMask Connect EVM como alternativa cuando no hay proveedor inyectado.

Las direcciones tienen tres usos distintos: la cuenta `0x…` de una persona sirve como **destinatario**; la dirección `0x…` del contrato `MessageBoard` desplegado va en **Configurar contrato**; la URL RPC solo se configura en la red de MetaMask. El contrato no puede inferirse de la dirección de una cuenta.

## Texto legible y horas de recepción

El historial de `MessageBoard` es un registro de compromisos: las dos wallets pueden ver el hash y la hora del bloque, pero la cadena no puede reconstruir el cuerpo plaintext de mensajes anteriores. Para que ambas personas lean el contenido, usa la sección **Chat privado E2EE**. El remitente conserva su cuerpo en el perfil local y el destinatario lo ve solo después de autenticarlo, descifrarlo y guardarlo en su dispositivo. El relay transporta únicamente ciphertext opaco y el contrato sigue guardando solo el hash.

Cada burbuja E2EE muestra `ENVIADO · DISPOSITIVO EMISOR · UTC`. El destinatario guarda `RECIBIDO EN ESTE DISPOSITIVO · UTC` al descifrar y persistir; el remitente muestra `RECIBIDO · ACK DEL RELAY VERIFICADO POR HASH · UTC` solo cuando el hash Keccak del recibo coincide con el ciphertext enviado. La hora del destinatario procede de su reloj local; la hora del emisor es la aceptación del ACK por el relay, no una prueba de que la persona abrió o leyó el mensaje. Los perfiles antiguos sin `received_at` muestran que la hora no está disponible, en vez de reutilizar la hora de envío.

Si el relay aún no confirma aceptación, el mensaje permanece en la cola local y el borrador no se borra. Un retry aceptado solo limpia el borrador si conserva el mismo cuerpo y destinatario. Cuando se pierde la respuesta del POST y no existe un `expires_at` guardado, el cliente usa la hora local de creación más siete días y 60 segundos como límite conservador: marca `expired`, libera la copia cifrada pendiente y no la retransmite. Esto no prueba que el relay aceptara ni entregara el mensaje.

La nueva política de 72 horas prevalece para el historial/outbox del navegador: normalmente elimina el cuerpo y la copia de reintento antes de ese límite de transporte de siete días. Los siete días siguen siendo el límite del relay y de sus recibos, no una promesa de retener texto local durante una semana. Si llega un mensaje fuera de la ventana local, no se restaura su cuerpo ni se inventa un recibo de entrega legible.

Tanto los ACK `delivered` como `rejected` incluyen el hash de los bytes ciphertext originales, calculado antes del descifrado. El relay lo verifica antes de purgar el cuerpo cifrado; un rechazo nunca crea una hora de recepción para el emisor. Si la representación de transporte no permite recuperar esos bytes, el cliente no envía un ACK de borrado sin hash y el sobre conserva su política de expiración. Las marcas UTC indican el formato y la fuente del reloj; no certifican una hora universal independiente del dispositivo o del relay.

## Referencias oficiales

- [Dioxus 0.7](https://dioxuslabs.com/learn/0.7/)
- [MetaMask Connect para EVM](https://docs.metamask.io/metamask-connect/evm/)
- [Solución de problemas de MetaMask Connect](https://docs.metamask.io/metamask-connect/troubleshooting/)
- [EIP-1193: Ethereum Provider JavaScript API](https://eips.ethereum.org/EIPS/eip-1193)
- [Redes de prueba de Ethereum y Sepolia](https://ethereum.org/en/developers/docs/networks/#sepolia)
- [Foundry](https://getfoundry.sh/)
- [RustCrypto: crate sha3](https://docs.rs/sha3/latest/sha3/)
- [ring](https://docs.rs/ring/latest/ring/)
