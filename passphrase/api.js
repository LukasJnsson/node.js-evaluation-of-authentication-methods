

export default {
    loggedIn: false,
    pKey: undefined,
    pKeyString: undefined,
    profile: undefined,
    mKey: undefined,
    challenge: '',
    lastMessage: undefined,

    async registerUser (publicKey, masterKey, userProfile) {
        this.mKey = masterKey
        this.pKeyString = publicKey.n
        this.pKey = await window.crypto.subtle.importKey('jwk', publicKey, {
            name: 'RSASSA-PKCS1-v1_5',
            hash: { name: 'SHA-256' }
        }, true, ['verify'])
        this.profile = userProfile
    },

    async loginStartChallenge (publicKey) {
        if (this.pKeyString != publicKey.n) throw new Error('p key does not exist')
        this.challenge = 'random text'
        return this.challenge
    },

    async completeChallenge (challenge, signature) {
        let encoder = new TextEncoder()
        let challengeBytes = encoder.encode(challenge)

        function str2bytes (str) {
            const buf = new ArrayBuffer(str.length)
            const bufView = new Uint8Array(buf)
            for (let i = 0, strLen = str.length; i < strLen; i++) {
                bufView[i] = str.charCodeAt(i)
            }
            return buf
        }

        let signatureBytes = str2bytes(signature)
        let verification = await window.crypto.subtle.verify(
            "RSASSA-PKCS1-v1_5",
            this.pKey,
            signatureBytes,
            challengeBytes
        )

        if (verification) {
            this.loggedIn = true
            return this.profile
        }
        else {
            this.loggedIn = false
            throw new Error('Verificaiton not possible')
        }
    },

    async getMasterKey () {
        if (!this.loggedIn) throw new Error('must be logged in!')
        return this.mKey
    },

    async sendMessage (message, iv) {
        if (!this.loggedIn) throw new Error('must be logged in!')
        return this.lastMessage = {
            message,
            iv
        }
    },

    async getMessage () {
        if (!this.loggedIn) throw new Error('must be logged in!')
        return this.lastMessage
    }
}