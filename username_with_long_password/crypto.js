
/**
 * Converts a utf8 string into Uint8Array
 * @param {string} str input string
 * @returns an ArrayBuffer represeting the string
 */
const stringToBytes = (str) => {
    const buf = new ArrayBuffer(str.length)
    const bufView = new Uint8Array(buf)
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i)
    }
    return buf
}

/**
 * Converts an ArrayBuffer into a string
 * @param {ArrayBuffer} buffer 
 * @returns a string
 */
const bytesToString = (buffer) => {
    return String.fromCharCode.apply(null, new Uint8Array(buffer))
}

/**
 * Converts a string full of bytes in hexadecimal format to a byte array
 * adapted from https://stackoverflow.com/questions/14603205/how-to-convert-hex-string-into-a-bytes-array-and-a-bytes-array-in-the-hex-strin
 * @param {string} hex string containing bytes represented as hex
 * @returns an ArrayBuffer represeting the string
 */
function hexStringToBytes (hex) {
    const buffer = new ArrayBuffer(hex.length / 2)
    const bufferView = new Uint8Array(buffer)
    for (let c = 0; c < hex.length; c += 2)
        bufferView[c / 2] = parseInt(hex.substr(c, 2), 16)
    return buffer
}

/**
 * Generates a symmetric encryption key
 * @returns a Promise, which delivers a CryptoKey
 */
const generateMasterKey = async () => {
    return window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    )
}

/**
 * Generates a symmetric encryption key from a password and a salt
 * @param {string} password a long password used to generate the key, the longer and more entropic the better
 * @param {string} salt can be anything, usually a username or password
 * @returns a Promise delivering a CryptoKey
 */
const getKeyFromPassword = async (password, salt) => {
    const enc = new TextEncoder();
    const ke1 = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        "PBKDF2",
        false,
        ["deriveBits", "deriveKey"],
    )

    let saltArray = enc.encode(salt)

    // now we use the first key to derive an AES key
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltArray,
            iterations: 400000, // at least 310000, see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
            hash: "SHA-256",
        },
        ke1,
        { name: "AES-GCM", length: 256 },
        true,
        ["wrapKey", "unwrapKey"]
    )
}

/**
 * Generates a pair of public and private keys used for signing (RSASSA-PKCS1-v1_5)
 * @param {string} seed a seed used to generate the keys, it is paramount that the seed is long enough (128 bits) and has entropy
 * @returns a Promise that provides an object with two CryptoKeys
 */
const generatePrivatePublicKeys = async (seed) => {
    // based on: https://gitlab.com/soapbox-pub/seeded-rsa
    // see also: https://stackoverflow.com/questions/72047474/how-to-generate-safe-rsa-keys-deterministically-using-a-seed/72047475#72047475

    // Seed the PRNG with a SHA-256 digest from the string
    const prng = forge.random.createInstance()
    prng.seedFileSync = () => {
        const md = forge.md.sha256.create()
        md.update(seed)
        return md.digest().toHex()
    }


    let bits = 2048 // reccommended y NIST, otherwise 3072, or 4096 would be even better, but too slow, https://en.wikipedia.org/wiki/Key_size
    const keys = forge.pki.rsa.generateKeyPair({ bits: bits, prng, workers: -1 })

    // RSASSA-PKCS1-v1_5, RSA-PSS, and ECDSA — are public-key cryptosystems that 
    // use the private key for signing and the public key for verification. 

    const rsaPublicKey = forge.pki.publicKeyToAsn1(keys.publicKey);
    const publicKeyData = stringToBytes(forge.asn1.toDer(rsaPublicKey).getBytes());

    const rsaPrivateKey = forge.pki.privateKeyToAsn1(keys.privateKey);
    const privateKeyInfo = forge.pki.wrapRsaPrivateKey(rsaPrivateKey);
    const privateKeyData = stringToBytes(forge.asn1.toDer(privateKeyInfo).getBytes());

    const algorithm = {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
    }

    const publicKey = await crypto.subtle.importKey(
        'spki',
        publicKeyData,
        algorithm,
        true,
        ['verify'],
    )

    const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        privateKeyData,
        algorithm,
        true,
        ['sign'],
    )

    return {
        publicKey,
        privateKey,
    }
}

/**
 * Extracts a key as a JSON object of type JWK
 * @param {CryptoKey} key key to be extracted
 * @returns a Promise that returns the JWK object
 */
const extractKey = async (key) => {
    return window.crypto.subtle.exportKey('jwk', key)
}

/**
 * Signs a message
 * @param {CryptoKey} privateKey 
 * @param {string} message to be signed
 * @returns a Promise that passes the signature as a string
 */
const sign = async (privateKey, message) => {
    const messageBytes = new TextEncoder().encode(message)

    const signatureBytes = await window.crypto.subtle.sign(
        'RSASSA-PKCS1-v1_5',
        privateKey,
        messageBytes
    )

    return bytesToString(signatureBytes)
}


/**
 * Wraps a key with another key, in other words, it encrypts a key using another one
 * @param {CryptoKey} keyToWrap the key to be wrapped (encrypted)
 * @param {CryptoKey} wrappingKey the key used to wrap/unwrap
 * @returns a Promise with an object containing `iv` (a Uint8Array) and `wrappedKey` (an ArrayBuffer)
 */
const wrapKey = async (keyToWrap, wrappingKey) => {
    let iv = generateIv()
    let wrappedKey = await window.crypto.subtle.wrapKey('raw', keyToWrap, wrappingKey, {
        name: "AES-GCM",
        iv,
    })
    return {
        wrappedKey,
        iv
    }
}

/**
 * Unwraps a key using another key
 * @param {CryptoKey} wrappedKey the key that is wrapped (encrypted)
 * @param {*} iv 
 * @param {CryptoKey} wrappingKey the key wraps
 * @returns 
 */
const unwrapKey = async (wrappedKey, iv, wrappingKey) => {
    return window.crypto.subtle.unwrapKey('raw', wrappedKey, wrappingKey, {
        name: "AES-GCM",
        iv,
    }, {
        name: "AES-GCM"
    }, true, ["encrypt", "decrypt"]) // TODO: maybe make it unexportable?
}

/**
 * Generates a random IV
 * @returns an array of 12 Uint8
 */
const generateIv = () => {
    return window.crypto.getRandomValues(new Uint8Array(12))
}

/**
 * Encrypts a message
 * @param {string} data message to be encoded
 * @param {CryptoKey} key simmetric encryption key
 * @returns 
 */
const encrypt = async (data, key) => {
    const encoder = new TextEncoder()
    const encodedText = encoder.encode(data)
    const iv = generateIv()
    const cipher = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        encodedText
    );
    return {
        cipher: bytesToString(cipher),
        iv: bytesToString(iv)
    }
}

/**
 * Decrypts a message
 * @param {string} cipher the message to be decrypted, as a string representing the bytes
 * @param {CryptoKey} key the CryptoKey
 * @param {string} iv the IV, as a string representing the bytes
 * @returns 
 */
const decrypt = async (cipher, key, iv) => {
    const encoded = await window.crypto.subtle.decrypt({
        name: 'AES-GCM',
        iv: stringToBytes(iv),
    }, key, stringToBytes(cipher))

    const decoder = new TextDecoder()
    return decoder.decode(encoded)
}

export {
    generateMasterKey,
    getKeyFromPassword,
    generatePrivatePublicKeys,
    wrapKey,
    unwrapKey,
    extractKey,
    sign,
    encrypt,
    decrypt,
    bytesToString,
    stringToBytes
}