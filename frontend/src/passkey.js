

/**
 * Encodes data buffer into a Base64 string
 * @param {ArrayBuffer} data Data to encode of type ArrayBuffer or any typed array
 * @returns {string} Base64-encoded string
 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array
 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer
 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray
 * https://developer.mozilla.org/en-US/docs/Web/API/btoa
 */
function encodeBufferToBase64(data) {
    /**
     * Decodes a string into bytes
     */
    return btoa(String.fromCharCode(...new Uint8Array(data)));
};

/**
 * Encodes data buffer to Base64 URL-safe string
 * @param {ArrayBuffer} data Data to encode of type ArrayBuffer or any typed array
 * @returns {string} Base64 URL-safe encoded string
 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array
 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer
 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray
 * https://developer.mozilla.org/en-US/docs/Web/API/btoa
 */
export function encodeBufferToSafeBase64Url(data) {
    return encodeBufferToBase64(data)
        .replace(/=/g, "") // Remove equal sign
        .replace(/\+/g, "-") // Replace '+' with '-'
        .replace(/\//g, "_"); // Replace '/' with '_'
};

/**
 * Decodes Base64-encoded string to binary data
 * @param {string} data Base64-encoded string
 * @returns {Uint8Array} Decoded data of type Uint8Array
 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array
 * https://developer.mozilla.org/en-US/docs/Web/API/atob
 */
function decodeBase64StringToBinary(data) {
    /**
     * Decodes a string of Base64-encoded data into bytes
     */
    return Uint8Array.from(atob(data).split(""), (x) => x.charCodeAt(0));
};

/**
 * Decodes Base64 URL-encoded string to Base64 string and then to binary data
 * @param {string} data Base64 URL-encoded string
 * @returns {Uint8Array} Decoded data of type Uint8Array
 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array
 * https://developer.mozilla.org/en-US/docs/Web/API/atob
 */
export function decodeBase64UrlString(data) {
    return decodeBase64StringToBinary(data
        .replace(/-/g, "+")
        .replace(/_/g, "/"));
};

/**
 * Decodes buffer to UTF-8 text
 * @param {ArrayBuffer} buffer Buffer with UTF-8 encoded text
 * @returns {string} Decoded string
 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer
 * https://developer.mozilla.org/en-US/docs/Web/API/TextDecoder
 */
function decodeBufferToUTF8(buffer) {
    return new TextDecoder().decode(buffer);
};

/**
 * Compares ArrayBuffer objects byte by byte
 * @param {ArrayBuffer} firstBuff First buffer
 * @param {ArrayBuffer} secondBuff Second buffer
 * @returns {boolean} True if the buffers are equal otherwise false
 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer
 */
function bytesIsEqual(firstBuff, secondBuff) {
    let isEqual = true;
    const firstBytes = new Uint8Array(firstBuff);
    const secondBytes = new Uint8Array(secondBuff);

    if (firstBytes.byteLength !== secondBytes.byteLength) {
        isEqual = false
    };

    for (let i = 0; i < firstBytes.byteLength; i++) {
        if (firstBytes[i] !== secondBytes[i]) {
            isEqual =  false
        };
    };
    return isEqual;
};

/**
 * Concatenates Uint8Arrays
 * @param {Uint8Array} firstBytes First byte array
 * @param {Uint8Array} secondBytes Second byte array
 * @returns {Uint8Array} Uint8Array with the bytes of firstBytes and the bytes of secondBytes
 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array
 */
function concatUint8Array(firstBytes, secondBytes) {
    const array = new Uint8Array(firstBytes.byteLength + secondBytes.byteLength);
        array.set(new Uint8Array(firstBytes), 0);
        array.set(new Uint8Array(secondBytes), firstBytes.byteLength);
    return array;
};

/**
 * Concatenates ArrayBuffers
 * @param {ArrayBuffer} firstBuff First buffer
 * @param {ArrayBuffer} secondBuff Second buffer
 * @returns {ArrayBuffer} ArrayBuffer with the bytes of firstBuff and the bytes of secondBuff
 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array
 */
function concatArrayBuffer(firstBuff, secondBuff) {
    return concatUint8Array(new Uint8Array(firstBuff), new Uint8Array(secondBuff)).buffer;
};

/**
 * Decodes Distinguished Encoding Rules (DER) integer to the expected length
 * @param {Uint8Array} intBytes DER integer bytes
 * @param {Number} expectedLength Expected length of the array
 * @returns {Uint8Array} Decoded integer of type Uint8Array with the expected length
 */
function decodeDERInt(intBytes, expectedLength) {
    if (intBytes.byteLength === expectedLength) {
        return intBytes;
    };

    if (intBytes.byteLength < expectedLength) {
        return concatUint8Array(
            new Uint8Array(expectedLength - intBytes.byteLength).fill(0),intBytes);
    };
    return intBytes.slice(-32);
};

/**
 * Converts Distinguished Encoding Rules (DER)-encoded signature to 
 * Elliptic Curve Digital Signature Algorithm (ECDSA) signature. This 
 * is necessary because the signature received from the authenticator is 
 * in DER format, which needs to be converted into a raw format (r and s values) 
 * that the Web Cryptography API can work with for verification
 * @param {ArrayBuffer} DERSign DER-encoded signature
 * @returns {ArrayBuffer} Converted ECDSA signature
 */
function convertDERSignToECDSASign(DERSign) {
    const signatureBytes = new Uint8Array(DERSign);

    // Decode the 'r' component of the signature
    const rOffset = 4;
    const rLength = signatureBytes[3];
    const rEnd = rOffset + rLength;
    const derEncodedR = signatureBytes.slice(rOffset, rEnd);
    const rComponent = decodeDERInt(derEncodedR, 32);

    // Decode the 's' component of the signature
    const sOffset = rEnd + 2;
    const sEnd = signatureBytes.byteLength;
    const derEncodedS = signatureBytes.slice(sOffset, sEnd);
    const sComponent = decodeDERInt(derEncodedS, 32);

    // ECDSA signature
    return new Uint8Array([...rComponent, ...sComponent]).buffer;
};

/**
 * Verifies authentication assertion with the Web Authentication API
 * @param {AuthenticatorAssertionResponse} credential Credential object from the authenticator
 * @param {Object} options Verification options containing the challenge and public key
 * @throws {TypeError} If credential response is not of type AuthenticatorAssertionResponse
 * @throws {Error} If verification error
 */
export async function verifyWebAuthAuthentication(credential, options) {
    const authResponse = credential.response;
    const authData = new Uint8Array(authResponse.authenticatorData);

    // Validates that the current host equals the rp
    const rpIdHash = authData.slice(0, 32);
    const expectedRpIdHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(window.location.hostname));
    if (!bytesIsEqual(rpIdHash, expectedRpIdHash)) {
        throw new Error("Could not verify 'rpId hash'!");
    };

    const signature = convertDERSignToECDSASign(credential.response.signature);

    /**
     * This hash is part of the data that will be verified against the 
     * signature to ensure that the client data has not been tampered with
     */
    const clientDataHash = await crypto.subtle.digest("SHA-256", credential.response.clientDataJSON);
    
    /**
     * It ensures that both the authentication data and the client data 
     * are unaltered and authentic
     */
    const verificationData = concatArrayBuffer(authData, clientDataHash);

    /**
     * Imports the public key provided in the verification options into a 
     * format that the Web Cryptography API can use for signature verification
     */
    const publicKey = await crypto.subtle.importKey("spki", options.publicKey, {name: "ECDSA", namedCurve: "P-256"}, true, ["verify"]);

    /**
     * Uses the imported public key to verify the signature against the prepared 
     * verification data. This step checks if the signature is valid, ensuring that 
     * the signature matches the data and was indeed created using the private key 
     * corresponding to the imported public key
     */
    const verifiedSignature = await crypto.subtle.verify({name: "ECDSA", hash: "SHA-256"}, publicKey, signature, verificationData);

    if (!verifiedSignature) {
        throw new Error("Could not verify 'signature'!");
    };
};