document.getElementById('testPrfSupport').addEventListener('click', async () => {
    try {
        const newCredential = await navigator.credentials.create({
            publicKey: {
                challenge: new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).buffer,
                rp: { 
                    name: "example.com",
                    id: "localhost" // Ensure this matches your domain, use "localhost" for local testing
                },
                user: {
                    id: new Uint8Array(16),
                    name: "test_user@example.com",
                    displayName: "Test User",
                },
                pubKeyCredParams: [
                    { alg: -7, type: "public-key" }, // ES256
                    { alg: -257, type: "public-key" }, // RS256
                ],
                timeout: 60000,
                authenticatorSelection: { userVerification: "preferred" },
                extensions: {
                    prf: {
                        eval: {
                            first: new Uint8Array(32).fill(0).buffer,
                        },
                    },
                },
            },
        });

        const extensionResults = newCredential.getClientExtensionResults();
        const prfSupported = extensionResults.prf && extensionResults.prf.enabled;

        document.getElementById('result').textContent = `PRF supported: ${prfSupported ? 'Yes' : 'No'}`;
    } catch (error) {
        console.error('Error testing PRF support:', error);
        document.getElementById('result').textContent = 'PRF support test failed; see console for details.';
    }
});
