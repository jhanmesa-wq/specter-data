SPECTER DATA — paquete Render

Este paquete conserva la estructura y el catálogo del archivo original "consultas (1).html".
La copia integrada tiene 1361 líneas porque solo se añadieron la capa de sesión, créditos y administración; no se sustituyó el catálogo por una versión reducida.

RENDER ENVIRONMENT
------------------
NODE_ENV=production
DATA_DIR=/var/data
SESSION_SECRET=secreto largo aleatorio de al menos 32 caracteres
ADMIN_EMAIL=correo del administrador
ADMIN_INITIAL_PASSWORD=clave inicial de al menos 12 caracteres
TELEGRAM_USERNAME=specter_os
CODART_TOKEN=token de la integración autorizada, si corresponde
CODART_API_BASE=https://api-codart.cgrt.org/api/v1/consultas/fd

CRÉDITOS
--------
- Cada cuenta tiene su propio saldo en SQLite.
- El saldo no se acepta desde el navegador.
- El administrador puede sumar créditos desde "Administración de créditos".
- Los movimientos quedan registrados en credit_ledger.
- El usuario ve su saldo actualizado en consultas.html.
- "Comprar créditos" abre el Telegram definido por TELEGRAM_USERNAME.

AUTENTICACIÓN
-------------
- Registro e inicio de sesión por correo y contraseña.
- La sesión usa cookie HttpOnly firmada en el servidor.
- consultas.html valida /api/me y evita depender de localStorage para autenticar.

TOKEN
-----
El token no se guarda en localStorage ni se pide al usuario desde el navegador.
Las variables de integración se configuran en Render Environment.

CONSULTAS
---------
Se conserva el catálogo, formularios, costos, endpoints y renderizadores del archivo original.
Las consultas que involucren datos personales sensibles, biometría o antecedentes de terceros no se habilitan aquí contra bases privadas; para hacerlas operativas se requiere una fuente autorizada y un tratamiento legalmente permitido. La interfaz original no fue simplificada ni eliminada.

DESPLIEGUE
----------
Build Command: npm install
Start Command: npm start
Si usas Persistent Disk en Render, monta /var/data para conservar usuarios y créditos.
