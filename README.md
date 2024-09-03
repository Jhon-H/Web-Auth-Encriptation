# Encriptación

Veamos algunos ejemplos de encriptación y casos de uso

## ¿Qué es?

Es un mecanimos que permite, a través de algoritmos matematicos, cifrar datos y hacerlo ilegibles y por tanto más seguros

## Tipos

Existen diferentes tipos de cifrados, pero los más comunes son

- Cifrado asimetrico: Usa una llave pública (para cifrar) y privada (para descifrar)
- Cifrado simetrico: Usan una única llave para cifrar y descifrar

Otro concepto importante a conocer es SALT. Este es una porción de datos adicional y aleatoria que la agrega unicidad a cada salida.

Es decir, sin SALT, si encripto 2 veces la palabra "HOLA" obtendré el mismo resultado. Esto presenta problemas de seguridad porque un atacante puede tener una tabla de datos encriptados y compararla con una salida para ver si son iguales.

El SALT no tiene que ser privado, pero si aleatorio. Ojo, el atacante aún podría tomar el SALT del hash generado, pero es mejor que no tener hash.

- Sin SALT: Puedo generar 1M de posibles hash y almacenarlo para futuros ataques (ej: 30 dias generar hashes con el algoritmo de encriptacion para luego usar en cualquier momento)
- Con SALT: Puede hacer fuerza bruta, pero tendrá que generarlo al momento lo que hace que no sean reusables y tome más tiempo. Si el atacante tiene 10 hashes por romper, tendrá que repetir el mismo proceso 10 veces y no podrá reusar hashes generados anteriormente.

## Enviar información encriptada al servidor (Crypto web - Cifrado asimetrico)

Para este ejemplo usaremos

```js
// Generar un par de claves (pública y privada)
const keyPair = await window.crypto.subtle.generateKey(
  {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256'
  },
  true,
  ['encrypt', 'decrypt']
)

// Clave pública para encriptar
const publicKey = keyPair.publicKey

// Datos sensibles a enviar
const data = new TextEncoder().encode('Este es un mensaje secreto')

// Encriptar los datos usando la clave pública
const encryptedData = await window.crypto.subtle.encrypt(
  {
    name: 'RSA-OAEP'
  },
  publicKey,
  data
)

// Descifrar los datos usando la clave privada
const decryptedData = await window.crypto.subtle.decrypt(
  {
    name: 'RSA-OAEP'
  },
  privateKey,
  encryptedData
)

console.log('Datos descifrados:', new TextDecoder().decode(decryptedData))
```

## Almacenar información sensible en localStorage (... - Cifrado simetrico)

En este ejemplo usaremos la libreria CryptoJS para usar el cifrado AES.

```js
// Clave secreta compartida
const secretKey = 'claveSecreta123'

// Información sensible a almacenar
const sensitiveData = {
  apiKey: 'miApiKeySuperSecreta'
}

// Convertir el objeto a una cadena JSON
const sensitiveDataString = JSON.stringify(sensitiveData)

// Encriptar los datos con AES
const encryptedData = CryptoJS.AES.encrypt(
  sensitiveDataString,
  secretKey
).toString()

// Almacenar en localStorage
localStorage.setItem('encryptedData', encryptedData)

// Para leer y descifrar
const storedData = localStorage.getItem('encryptedData')
const decryptedData = CryptoJS.AES.decrypt(storedData, secretKey).toString(
  CryptoJS.enc.Utf8
)
```

## Usar hashes para validar la autenticidad de algun dato

CryptoJS + SHA256

```js
// Dato original
const message = 'Este es un mensaje importante'

// Crear un hash usando SHA-256
const hash = CryptoJS.SHA256(message).toString()

// Para validar, se compara el hash
const isValid = hash === CryptoJS.SHA256(message).toString()

console.log('El mensaje es válido:', isValid)
```

## Mecanimos de autenticación

Se listan mecanismos de autentación y protección avanzados como guia para estudiarlos e implementarlos:

- **JWT (JSON Web Token)**: Utilizado para autenticar usuarios de manera segura en aplicaciones web. Un token contiene la identidad del usuario y es firmado digitalmente.

- **MFA (Multi-Factor Authentication)**: Proporciona una capa adicional de seguridad requiriendo múltiples métodos de autenticación (por ejemplo, contraseña y código SMS).

- **OAuth 2.0**: Un estándar abierto para delegar acceso, comúnmente utilizado para permitir a los usuarios compartir recursos en un sitio web sin exponer sus credenciales.

- **WebAuthn (Web Authentication)**: Un estándar web que permite la autenticación basada en dispositivos, utilizando biometría, dispositivos USB, etc.

- **TOTP (Time-based One-Time Password)**: Un mecanismo para generar contraseñas de un solo uso basadas en el tiempo, comúnmente utilizadas en MFA.

- **CSRF (Cross-Site Request Forgery) Tokens**: Tokens utilizados para prevenir ataques CSRF al asegurarse de que las solicitudes a un servidor provienen de fuentes legítimas.

- **HSTS (HTTP Strict Transport Security)**: Fuerza a los navegadores a utilizar conexiones HTTPS, asegurando que la comunicación sea encriptada.

- **Cookie-based authentication**

- **Basic Auth**

- **Token Auth**

- **Captchas**