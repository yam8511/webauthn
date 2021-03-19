window.onload = async function () {
    document.getElementById("username").value = localStorage.getItem('username')
    let support = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    if (support) {
        document.getElementById('touch_id').hidden = false;
        getCredentials()
    }
    console.log("OK", support)
}

async function login() {
    let name = document.getElementById("username").value.trim();
    document.getElementById("username").value = name;
    console.group("登入請求")
    console.group("==== 取得登入憑證請求 ====")
    let body = await fetch(`/loginRequest?name=${name}`).then(res => res.json());
    // Response {
    //     "challenge": "CzBP0i80O0Ejie3dDsqv93TT2y5TXZXs6cLn_tbPfz4",
    //         "allowCredentials": [
    //             {
    //                 "id": "AV4jRghX3QBktapT8mUjS5fAWoxsK6gbsSWcQ0cbbLCptMdosnnX2gdA6eT0e8K5vHmIpRXiH_4wG6t2UpEdNh-H8I89",
    //                 "type": "public-key",
    //                 "transports": [
    //                     "internal"
    //                 ]
    //             }
    //         ],
    //             "timeout": 1800000,
    //                 "userVerification": "required",
    //                     "rpId": "sustaining-glittery-amusement.glitch.me"
    // }
    body.publicKey.challenge = bufferDecode(body.publicKey.challenge);
    if (body.publicKey.allowCredentials) {
        for (let cred of body.publicKey.allowCredentials) {
            cred.id = bufferDecode(cred.id);
        }
    }
    console.log(body);
    console.groupEnd()

    console.group("==== 取得裝置憑證 =====")
    let cred = await navigator.credentials.get(body)
    console.log(cred);
    console.groupEnd()

    console.group("==== 憑證(公鑰)傳給後端 ====")
    const credential = {
        id: cred.id,
        rawId: bufferEncode(cred.rawId),
        type: cred.type,
        response: {
            clientDataJSON: bufferEncode(cred.response.clientDataJSON),
            authenticatorData: bufferEncode(cred.response.authenticatorData),
            signature: bufferEncode(cred.response.signature),
            userHandle: bufferEncode(cred.response.userHandle),
        },
    };
    console.log(credential);
    console.groupEnd()
    // req = {
    //     "id": "AV4jRghX3QBktapT8mUjS5fAWoxsK6gbsSWcQ0cbbLCptMdosnnX2gdA6eT0e8K5vHmIpRXiH_4wG6t2UpEdNh-H8I89",
    //     "type": "public-key",
    //     "rawId": "AV4jRghX3QBktapT8mUjS5fAWoxsK6gbsSWcQ0cbbLCptMdosnnX2gdA6eT0e8K5vHmIpRXiH_4wG6t2UpEdNh-H8I89",
    //     "response": {
    //         "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQ3pCUDBpODBPMEVqaWUzZERzcXY5M1RUMnk1VFhaWHM2Y0xuX3RiUGZ6NCIsIm9yaWdpbiI6Imh0dHBzOi8vc3VzdGFpbmluZy1nbGl0dGVyeS1hbXVzZW1lbnQuZ2xpdGNoLm1lIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
    //         "authenticatorData": "CGsrs2AerhC-Iw59CBHQt3JmbLKcK2Qcc8FELDSKlrEFYFN4jg",
    //         "signature": "MEQCIEFXOBmTXx55CCR_ISOLzeQMMppm5-tx0m6KZQ2noiYVAiAlyzfvW01gUIv6ZcdiMbYLCm_OIF56DPJk3t33Z6Odhg",
    //         "userHandle": "H5YOT7IUFs2elFkpt_mI6KGnMXSGb7SYPHRirnPZX7I"
    //     }
    // }

    await fetch(`/loginResponse?name=${name}`, {
        method: 'POST',
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(credential)
    });
    console.groupEnd()
}

async function getCredentials() {
    let name = document.getElementById("username").value.trim();
    document.getElementById("username").value = name;
    let body = await fetch(`/getKeys?name=${name}`).then(res => res.json());
    console.log(body)

    document.getElementById('keys').innerHTML = ''

    if (body.length > 0) {
        body.map(cred => {
            console.log(cred)
            let li = document.createElement('li')
            li.innerHTML = `<h2 onclick="remove('${cred.ID}')">${cred.ID}</h2>
                    <code>${cred.PublicKey}</code>`
            document.getElementById('keys').appendChild(li)
        })
    }
}

async function remove(id) {
    let name = document.getElementById("username").value.trim();
    document.getElementById("username").value = name;
    let c = window.prompt("確定刪除？", "false")
    console.log("confirm", c)
    if (c == "y" || c == "Y" || c == "true") {
        let body = await fetch(`/removeKeys?name=${name}&cred=${encodeURIComponent(id)}`).then(res => res.json());
    }
    getCredentials()
}

async function register() {
    let name = document.getElementById("username").value.trim();
    document.getElementById("username").value = name;

    // ======= 開始註冊憑證 =======
    // ======= 開始註冊憑證 =======
    // ======= 開始註冊憑證 =======
    console.log("Register -> ", name)
    let body = await fetch(`/registerRequest?name=${name}`).then(res => res.json());

    console.group("註冊請求")

    console.group("PUB KEY 參數")
    console.log(body)
    console.log("======= 轉碼中 ========")
    let cred_opt = {
        publicKey: {
            user: {
                ...body.publicKey.user,
            },
            ...body.publicKey
        }
    }
    // base64編碼的部分，要額外解成 ArrayBuffer
    cred_opt.publicKey.user.id = bufferDecode(cred_opt.publicKey.user.id);
    cred_opt.publicKey.challenge = bufferDecode(cred_opt.publicKey.challenge);
    if (cred_opt.publicKey.excludeCredentials) {
        for (let cred of cred_opt.publicKey.excludeCredentials) {
            cred.id = bufferDecode(cred.id);
        }
    }
    console.log(cred_opt)
    console.groupEnd()


    // ========= 產生憑證指紋 =========
    // ========= 產生憑證指紋 =========
    // ========= 產生憑證指紋 =========

    const cred = await navigator.credentials.create(cred_opt);
    console.group("產生憑證(公鑰)")
    console.info(cred)
    console.groupEnd()
    // PublicKeyCredential {
    //     rawId: ArrayBuffer(77),
    //     response: AuthenticatorAttestationResponse{
    //         attestationObject: ArrayBuffer(239),
    //         clientDataJSON: ArrayBuffer(137),
    //     },
    //     id: "AXXIt9rfa3CRPZ2FFXGR5UXqQbq6nb97ZaqlAW8X5wHARcB0A0…IzMZP4R-vd9q4rSRzFtxdZDjqVQV7Y1ERP3ovznxhtS1Ad978",
    //     type: "public-key"
    // }

    // 回傳給後端，完成憑證註冊
    console.group("憑證(公鑰)傳給後端")
    const credential = {
        id: cred.id,
        rawId: bufferEncode(cred.rawId),
        type: cred.type,
        response: {
            clientDataJSON: bufferEncode(cred.response.clientDataJSON),
            attestationObject: bufferEncode(cred.response.attestationObject),
        }
    };
    console.info(credential)
    await fetch(`/registerResponse?name=${name}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(credential),
    })
    localStorage.setItem(`credId`, credential.id);
    localStorage.setItem(`username`, name);
    console.groupEnd()

    console.groupEnd()


    getCredentials()
}

// Don't drop any blanks
// decode
function bufferDecode(value) {
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

// Encode an ArrayBuffer into a base64 string.
function bufferEncode(value) {
    value = new Uint8Array(value)
    return base64js.fromByteArray(value)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}
