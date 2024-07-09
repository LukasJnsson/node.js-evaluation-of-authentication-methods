

export default {
    stringToBytes (str) {
        const buf = new ArrayBuffer(str.length)
        const bufView = new Uint8Array(buf)
        for (let i = 0, strLen = str.length; i < strLen; i++) {
            bufView[i] = str.charCodeAt(i)
        }
        return buf
    },

    bytesToString (buffer) {
        return String.fromCharCode.apply(null, new Uint8Array(buffer))
    },

    async generateMasterKey () {
        return window.crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        )
    },

    async getKeyFromPassword (password, salt) {
        const enc = new TextEncoder();
        const ke1 = await window.crypto.subtle.importKey(
            "raw",
            enc.encode(password),
            "PBKDF2",
            false,
            ["deriveBits", "deriveKey"],
        )
    
        let saltArray = enc.encode(salt)
    
        return window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: saltArray,
                iterations: 400000,
                hash: "SHA-256",
            },
            ke1,
            { name: "AES-GCM", length: 256 },
            true,
            ["wrapKey", "unwrapKey"]
        )
    },

    async generatePrivatePublicKeys (seed) {
        const prng = forge.random.createInstance()
        prng.seedFileSync = () => {
            const md = forge.md.sha256.create()
            md.update(seed)
            return md.digest().toHex()
        }
    
        let bits = 2048
        const keys = forge.pki.rsa.generateKeyPair({ bits: bits, prng, workers: -1 })
    
        const rsaPublicKey = forge.pki.publicKeyToAsn1(keys.publicKey);
        const publicKeyData = this.stringToBytes(forge.asn1.toDer(rsaPublicKey).getBytes());
    
        const rsaPrivateKey = forge.pki.privateKeyToAsn1(keys.privateKey);
        const privateKeyInfo = forge.pki.wrapRsaPrivateKey(rsaPrivateKey);
        const privateKeyData = this.stringToBytes(forge.asn1.toDer(privateKeyInfo).getBytes());
    
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
    },

    async extractKey (key) {
        return window.crypto.subtle.exportKey('jwk', key)
    },

    async sign (privateKey, message) {
        const messageBytes = new TextEncoder().encode(message)
    
        const signatureBytes = await window.crypto.subtle.sign(
            'RSASSA-PKCS1-v1_5',
            privateKey,
            messageBytes
        )
        return this.bytesToString(signatureBytes)
    },

    async wrapKey (keyToWrap, wrappingKey) {
        let iv = this.generateIv()
        let wrappedKey = await window.crypto.subtle.wrapKey('raw', keyToWrap, wrappingKey, {
            name: "AES-GCM",
            iv,
        })
        return {
            wrappedKey,
            iv
        }
    },

    async unwrapKey (wrappedKey, iv, wrappingKey) {
        return window.crypto.subtle.unwrapKey('raw', wrappedKey, wrappingKey, {
            name: "AES-GCM",
            iv,
        }, {
            name: "AES-GCM"
        }, true, ["encrypt", "decrypt"])
    },

    generateIv () {
        return window.crypto.getRandomValues(new Uint8Array(12))
    },

    async encrypt (data, key) {
        const encoder = new TextEncoder()
        const encodedText = encoder.encode(data)
        const iv = this.generateIv()
        const cipher = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            encodedText
        );
        return {
            cipher: this.bytesToString(cipher),
            iv: this.bytesToString(iv)
        }
    },

    async ecrypt (cipher, key, iv) {
        const encoded = await window.crypto.subtle.decrypt({
            name: 'AES-GCM',
            iv: this.stringToBytes(iv),
        }, key, this.stringToBytes(cipher))
    
        const decoder = new TextDecoder()
        return decoder.decode(encoded)
    }
};