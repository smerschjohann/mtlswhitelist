package mtlswhitelist

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

func (a *MTlsOrWhitelist) serveLoginPage(rw http.ResponseWriter, req *http.Request) {
	redirect := req.URL.Query().Get("redirect")
	html := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>2FA Authentication</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f0f2f5; }
        .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
        h1 { margin-top: 0; color: #1c1e21; font-size: 1.5rem; }
        form { display: flex; flex-direction: column; gap: 1rem; }
        label { font-weight: bold; color: #4b4f56; }
        input { padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; }
        button { padding: 0.75rem; border: none; border-radius: 4px; background: #1877f2; color: white; font-size: 1rem; font-weight: bold; cursor: pointer; }
        button:hover { background: #166fe5; }
        button.secondary { background: #e4e6eb; color: #4b4f56; margin-top: 0.5rem; }
        button.secondary:hover { background: #d8dadf; }
        .error { color: #d93025; margin-bottom: 1rem; display: none; }
    </style>
</head>
<body>
    <div class="card">
        <h1>2FA Verification</h1>
        <div id="error" class="error"></div>
        <form action="verify-totp" method="post">
            <input type="hidden" name="redirect" value="` + redirect + `">
            <label for="code">TOTP Code</label>
            <input type="text" id="code" name="code" placeholder="123456" autofocus>
            <button type="submit">Verify with TOTP</button>
        </form>
        <button class="secondary" onclick="loginPasskey()">Login with Passkey</button>
    </div>

    <script>
        async function loginPasskey() {
            const errorDiv = document.getElementById('error');
            errorDiv.style.display = 'none';
            try {
                const response = await fetch('webauthn/challenge');
                const text = await response.text();
                if (!response.ok) {
                    throw new Error(text);
                }
                const options = JSON.parse(text);
                
                // Convert base64 to ArrayBuffer
                options.publicKey.challenge = Uint8Array.from(atob(options.publicKey.challenge), c => c.charCodeAt(0));
                if (options.publicKey.allowCredentials) {
                    options.publicKey.allowCredentials.forEach(c => {
                        c.id = Uint8Array.from(atob(c.id), c => c.charCodeAt(0));
                    });
                }

                const credential = await navigator.credentials.get(options);
                
                // Send response back
                const verifResponse = await fetch('webauthn/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        id: credential.id,
                        rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                        type: credential.type,
                        response: {
                            authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                            clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                            signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))),
                            userHandle: credential.response.userHandle ? btoa(String.fromCharCode(...new Uint8Array(credential.response.userHandle))) : null
                        }
                    })
                });

                if (verifResponse.ok) {
                    window.location.href = "` + redirect + `";
                } else {
                    const errText = await verifResponse.text();
                    throw new Error("Verification failed: " + errText);
                }
            } catch (err) {
                console.error(err);
                errorDiv.innerText = err.message;
                errorDiv.style.display = 'block';
            }
        }
    </script>
</body>
</html>`
	rw.Header().Set("Content-Type", "text/html")
	rw.Write([]byte(html))
}

func (a *MTlsOrWhitelist) serveRegisterPage(rw http.ResponseWriter, req *http.Request) {
	var cn, sn, ip string
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		cn = req.TLS.PeerCertificates[0].Subject.CommonName
		sn = req.TLS.PeerCertificates[0].SerialNumber.String()
	}
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		ip = req.RemoteAddr
	}

	totpSecret := a.generateTOTPSecret()
	identity := cn
	if identity == "" {
		identity = ip
	}

	issuer := url.QueryEscape(a.rawConfig.TwoFactor.RPName)
	label := url.QueryEscape(fmt.Sprintf("%s:%s", a.rawConfig.TwoFactor.RPName, identity))
	otpAuthURL := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s", label, totpSecret, issuer)

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>2FA Registration</title>
    <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
    <style>
        body { font-family: -apple-system, system-ui, sans-serif; padding: 2rem; background: #f0f2f5; line-height: 1.5; color: #1c1e21; }
        .card { background: white; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); max-width: 600px; margin: 0 auto; }
        .info { background: #e7f3ff; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; border-left: 5px solid #1877f2; }
        .step { margin-bottom: 2rem; border-bottom: 1px solid #eee; padding-bottom: 1.5rem; }
        .step:last-child { border-bottom: none; }
        h1 { color: #1877f2; margin-top: 0; }
        h2 { font-size: 1.25rem; margin-top: 0; }
        pre, code { background: #f4f4f4; padding: 0.5rem; border-radius: 4px; overflow-x: auto; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
        code { padding: 0.2rem 0.4rem; }
        button { padding: 0.75rem 1.5rem; border: none; border-radius: 6px; background: #1877f2; color: white; font-weight: bold; cursor: pointer; transition: background 0.2s; }
        button:hover { background: #166fe5; }
        .qr-container { display: flex; justify-content: center; margin: 1rem 0; padding: 1rem; background: white; border-radius: 8px; border: 1px solid #ddd; }
        .secret-box { display: flex; align-items: center; justify-content: space-between; background: #f8f9fa; padding: 0.75rem; border-radius: 6px; border: 1px solid #ddd; margin: 1rem 0; }
    </style>
</head>
<body>
    <div class="card">
        <h1>2FA Setup</h1>
        
        <div class="info">
            <strong>Detected Identity:</strong> <code>%s</code><br>
            <small>CN: %s, SN: %s, IP: %s</small>
        </div>

        <div class="step">
            <h2>Option A: TOTP (App)</h2>
            <p>1. Scan this code with your Authenticator app (e.g. Google Authenticator, Authy, Bitwarden):</p>
            <div class="qr-container" id="qrcode"></div>
            <p>2. Or enter the secret manually:</p>
            <div class="secret-box">
                <code id="totpSecret">%s</code>
            </div>
        </div>

        <div class="step">
            <h2>Option B: Passkey</h2>
            <p>Register a hardware key or biometric login for this browser/device:</p>
            <button onclick="registerPasskey()">Register Passkey</button>
        </div>

        <div id="result" style="display:none; margin-top: 2rem;">
            <h3>Configuration Snippet:</h3>
            <p>Add this to your <code>dynamic.yaml</code> file:</p>
            <pre id="configData"></pre>
        </div>
    </div>

    <script>
        // Generate QR Code
        new QRCode(document.getElementById("qrcode"), {
            text: "%s",
            width: 200,
            height: 200,
            colorDark : "#000000",
            colorLight : "#ffffff",
            correctLevel : QRCode.CorrectLevel.M
        });

        async function registerPasskey() {
            try {
                const challenge = new Uint8Array(32);
                window.crypto.getRandomValues(challenge);
                
                const options = {
                    publicKey: {
                        challenge: challenge,
                        rp: { name: "%s", id: "%s" },
                        user: { id: window.crypto.getRandomValues(new Uint8Array(16)), name: "%s", displayName: "%s" },
                        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                        timeout: 60000,
                        authenticatorSelection: { userVerification: "preferred" }
                    }
                };

                const credential = await navigator.credentials.create(options);
                const publicKey = btoa(String.fromCharCode(...new Uint8Array(credential.response.getPublicKey())));
                const credentialId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));

                const result = {
                    credentialId: credentialId,
                    publicKey: publicKey,
                    alg: -7
                };

                const snippet = '"' + "%s" + '":\n  - totp: "' + document.getElementById('totpSecret').innerText + '"\n  - ' + JSON.stringify(result, null, 2).replace(/\n/g, '\n    ');
                showConfig(snippet);
            } catch (err) {
                alert("Passkey Error: " + err.message);
            }
        }

        function showConfig(snippet) {
            document.getElementById('configData').innerText = snippet;
            document.getElementById('result').style.display = 'block';
            document.getElementById('result').scrollIntoView({ behavior: 'smooth' });
        }

        // Initial snippet with just TOTP
        showConfig('"' + "%s" + '":\n  - totp: "' + "%s" + '"');
    </script>
</body>
</html>
`, identity, cn, sn, ip, totpSecret, otpAuthURL, a.rawConfig.TwoFactor.RPName, a.rawConfig.TwoFactor.RPID, identity, identity, identity, identity, totpSecret)
	rw.Write([]byte(html))
}

func (a *MTlsOrWhitelist) generateTOTPSecret() string {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		// crypto/rand doesn't fail usually
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}
