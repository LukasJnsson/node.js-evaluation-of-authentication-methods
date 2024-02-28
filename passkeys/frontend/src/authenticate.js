
import { encodeBufferToSafeBase64Url, decodeBase64UrlString, verifyWebAuthAuthentication } from "./passkey";


export default {
  /**
   * Authenticate by sign up
   * @param {String} username username
   * @returns {Object} user
   */
  async signUp(username) {

    // Fetch users
    const response = await fetch('http://localhost:3001/api/v1/users');
    const users = await response.json();
  
    // Validate if username is unique
    const userExists = users.find(user => user.username === username);
      if (userExists) {
        throw new Error("Invalid credentials!");
    };
  
    // Fetch challange
    const getChallange = await fetch('http://localhost:3001/api/v1/challanges');
    const challengeArray = await getChallange.json();
    const challenge = new Uint8Array(challengeArray);

    /**
     * Web Authentication API (WebAuth) (create)
     * https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API
     */
    const publicKeyCredential = await navigator.credentials.create({
      publicKey: {
        rp: { name: "node.js-end-to-end-encrypted-platform" },
        user: {
          id: crypto.getRandomValues(new Uint8Array(32)),
          name: username,
          displayName: username,
        },
        pubKeyCredParams: [
          /**
           * Elliptic Curve Digital Signature Algorithm (ES256)
           */
          { alg: -7, type: 'public-key' },
          /**
           * RSA Signature Algorithm (RS256) (based on RSA cryptography)
           */
          { alg: -257, type: 'public-key' },
        ],
        challenge,
      }
    });
  
    const data = await fetch('http://localhost:3001/api/v1/users', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        credential_id: publicKeyCredential.id,
        username,
        public_key: encodeBufferToSafeBase64Url(publicKeyCredential.response.getPublicKey())
      })
    });
    const userData = await data.json();
    return userData;
  },

  /**
   * Authenticate by sign in
   * @returns {Object} id and username of user
   */
  async signIn() {
    const generateChallenge = await fetch('http://localhost:3001/api/v1/challanges');
    const challengeArray = await generateChallenge.json();
    const challenge = new Uint8Array(challengeArray);
  
    /**
     * Web Authentication API (WebAuth) (get)
     * https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API
     */
    const publicKeyCredential = await navigator.credentials.get({
      publicKey: {
        challenge,
      }
    });
  
    // Fetch user by id
    const response = await fetch(`http://localhost:3001/api/v1/users/${publicKeyCredential.id}`);
    const user = await response.json();
  
    // Verify authentication
    await verifyWebAuthAuthentication(publicKeyCredential, {
      publicKey: decodeBase64UrlString(user.public_key),
      challenge
    });
  
    return {
      username: user.username,
      credential_id: user.credential_id
    };
  }
};