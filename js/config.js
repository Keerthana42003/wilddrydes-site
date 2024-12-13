window._config = {
    cognito: {
        userPoolId: 'us-east-1_IGEXrzYDb', // e.g. us-east-2_uXboG5pAb
        userPoolClientId: '307ojfc7r8vsogvrjf9l4vipef', // e.g. 25ddkmj4v6hfsfvruhpfi7n4hv
        userPoolClientsecret: 'a26eu54jn80kah5kgm30p6262ckvdo6klvo67389uk2ucqj7nqe', // Your Cognito App Client Secret
        region: 'us-east-1' // e.g. us-east-2
    },
    api: {
        invokeUrl: '' // e.g. https://rc7nyt4tql.execute-api.us-west-2.amazonaws.com/prod',
    }
};

// Generate the SECRET_HASH using Web Crypto API
async function generateSecretHash(username) {
    const clientId = window._config.cognito.userPoolClientId;
    const clientSecret = window._config.cognito.userPoolClientsecret;

    // Create the message by concatenating username and clientId
    const message = username + clientId;

    // Convert the message and secret to ArrayBuffer
    const encoder = new TextEncoder();
    const msgBuffer = encoder.encode(message);
    const secretBuffer = encoder.encode(clientSecret);

    // Generate the HMAC-SHA256 hash using the Web Crypto API
    const key = await window.crypto.subtle.importKey(
        'raw', 
        secretBuffer, 
        { name: 'HMAC', hash: { name: 'SHA-256' } }, 
        false, 
        ['sign']
    );

    const signature = await window.crypto.subtle.sign('HMAC', key, msgBuffer);

    // Convert the signature to Base64
    const hashArray = Array.from(new Uint8Array(signature));  // Convert buffer to byte array
    const base64Hash = btoa(String.fromCharCode(...hashArray));  // Convert byte array to Base64 string
    
    return base64Hash;
}

// Example of using the `SECRET_HASH` when calling Cognito API

async function initiateAuth(username, password) {
    const secretHash = await generateSecretHash(username);

    const params = {
        AuthFlow: 'USER_PASSWORD_AUTH',
        ClientId: window._config.cognito.userPoolClientId,
        AuthParameters: {
            USERNAME: username,
            PASSWORD: password,
            SECRET_HASH: secretHash  // Include the SECRET_HASH here
        }
    };

    const cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider();

    cognitoidentityserviceprovider.initiateAuth(params, function(err, data) {
        if (err) {
            console.log('Error:', err);
        } else {
            console.log('Success:', data);
        }
    });
}
