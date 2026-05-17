import { useMemo, useRef, useState, useEffect } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:3000";
const WS_API_KEY = import.meta.env.VITE_WS_API_KEY || "";

const tabs = [
  { id: "classic", label: "Classic" },
  { id: "symmetric", label: "Symmetric" },
  { id: "asymmetric", label: "Asymmetric" },
  { id: "signatures", label: "Signatures" },
  { id: "secure", label: "Secure Chat" },
  { id: "hash", label: "Hash" }
];

const classicOptions = [
  { id: "caesar", label: "Caesar" },
  { id: "vigenere", label: "Vigenere" },
  { id: "affine", label: "Affine" },
  { id: "playfair", label: "Playfair" },
  { id: "hill", label: "Hill" },
  { id: "otp", label: "OTP" }
];

const symmetricOptions = [
  { id: "rc4", label: "RC4" },
  { id: "des", label: "DES" },
  { id: "aes", label: "AES" },
  { id: "rijndael", label: "Rijndael" },
  { id: "twofish", label: "Twofish" },
  { id: "serpent", label: "Serpent" },
  { id: "rc6", label: "RC6" }
];

const hashOptions = [
  { id: "md5", label: "MD5" },
  { id: "sha256", label: "SHA-256" },
  { id: "sha512", label: "SHA-512" },
  { id: "hmac", label: "HMAC-SHA256" }
];

const signatureOptions = [
  { id: "rsa-pss", label: "RSA-PSS (educatif)" },
  { id: "rsa-pkcs1v15", label: "RSA PKCS#1 v1.5" },
  { id: "dsa", label: "DSA" },
  { id: "ecdsa", label: "ECDSA" },
  { id: "elgamal", label: "ElGamal" }
];

function textToBase64(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  bytes.forEach((value) => {
    binary += String.fromCharCode(value);
  });
  return btoa(binary);
}

function base64ToText(value) {
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach((value) => {
    binary += String.fromCharCode(value);
  });
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function toWsUrl(apiBase, room, name) {
  const url = new URL(apiBase);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/ws/secure";
  url.searchParams.set("room", room);
  url.searchParams.set("name", name);
  if (WS_API_KEY) {
    url.searchParams.set("api_key", WS_API_KEY);
  }
  return url.toString();
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let b = BigInt(base) % BigInt(modulus);
  let e = BigInt(exponent);
  const m = BigInt(modulus);

  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % m;
    }
    e >>= 1n;
    b = (b * b) % m;
  }

  return result;
}

async function apiPost(path, body) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    let errorMessage = `Erreur ${response.status}`;
    try {
      const payload = await response.json();
      errorMessage = payload.message || payload.error || errorMessage;
    } catch (err) {
      // ignore parse errors
    }
    throw new Error(errorMessage);
  }

  return response.json();
}

function Field({ label, helper, children }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {helper ? <em>{helper}</em> : null}
    </label>
  );
}

function ResultCard({ title, content }) {
  if (!content) {
    return null;
  }

  return (
    <section className="result-card">
      <div className="result-header">
        <h3>{title}</h3>
        <button
          type="button"
          onClick={() => navigator.clipboard.writeText(content)}
        >
          Copier
        </button>
      </div>
      <pre>{content}</pre>
    </section>
  );
}

function ClassicPanel() {
  const [algo, setAlgo] = useState("caesar");
  const [mode, setMode] = useState("encrypt");
  const [text, setText] = useState("Bonjour le monde");
  const [shift, setShift] = useState(3);
  const [key, setKey] = useState("CLE");
  const [aValue, setAValue] = useState(5);
  const [bValue, setBValue] = useState(8);
  const [hill, setHill] = useState({ a11: 3, a12: 3, a21: 2, a22: 5 });
  const [otpText, setOtpText] = useState("");
  const [otpKey, setOtpKey] = useState("");
  const [result, setResult] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const [analysisTool, setAnalysisTool] = useState("caesar-bruteforce");
  const [analysisText, setAnalysisText] = useState("QPWKALQPWKALQPWKAL");
  const [sequenceLen, setSequenceLen] = useState(3);
  const [maxKeyLen, setMaxKeyLen] = useState(12);
  const [estimateLen, setEstimateLen] = useState(3);
  const [analysisResult, setAnalysisResult] = useState("");
  const [analysisError, setAnalysisError] = useState("");
  const [analysisLoading, setAnalysisLoading] = useState(false);

  const otpLabel = mode === "encrypt" ? "plaintext_base64" : "ciphertext_base64";

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    setResult("");
    setLoading(true);

    try {
      let path = "";
      let payload = {};

      if (algo === "otp") {
        path = `/classic/otp/${mode}`;
        payload = {
          [otpLabel]: otpText,
          key_base64: otpKey
        };
      } else if (algo === "caesar") {
        path = `/classic/caesar/${mode}`;
        payload = { text, shift: Number(shift) };
      } else if (algo === "vigenere") {
        path = `/classic/vigenere/${mode}`;
        payload = { text, key };
      } else if (algo === "affine") {
        path = `/classic/affine/${mode}`;
        payload = { text, a: Number(aValue), b: Number(bValue) };
      } else if (algo === "playfair") {
        path = `/classic/playfair/${mode}`;
        payload = { text, key };
      } else if (algo === "hill") {
        path = `/classic/hill/${mode}`;
        payload = {
          text,
          key: [
            [Number(hill.a11), Number(hill.a12)],
            [Number(hill.a21), Number(hill.a22)]
          ]
        };
      }

      const data = await apiPost(path, payload);
      setResult(JSON.stringify(data, null, 2));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const runAnalysis = async (event) => {
    event.preventDefault();
    setAnalysisError("");
    setAnalysisResult("");
    setAnalysisLoading(true);

    try {
      let path = "";
      let payload = {};

      if (analysisTool === "caesar-bruteforce") {
        path = "/classic/caesar/bruteforce";
        payload = { text: analysisText };
      } else if (analysisTool === "kasiski") {
        path = "/classic/analysis/kasiski";
        payload = {
          text: analysisText,
          sequence_len: Number(sequenceLen),
          max_key_len: Number(maxKeyLen)
        };
      } else if (analysisTool === "vigenere-ic") {
        path = "/classic/analysis/vigenere/key-length";
        payload = { text: analysisText, max_length: Number(maxKeyLen) };
      } else if (analysisTool === "vigenere-estimate") {
        path = "/classic/analysis/vigenere/estimate-key";
        payload = { text: analysisText, key_length: Number(estimateLen) };
      }

      const data = await apiPost(path, payload);
      setAnalysisResult(JSON.stringify(data, null, 2));
    } catch (err) {
      setAnalysisError(err.message);
    } finally {
      setAnalysisLoading(false);
    }
  };

  return (
    <section className="panel">
      <form onSubmit={submit} className="card">
        <div className="row">
          <Field label="Algorithme">
            <select value={algo} onChange={(event) => setAlgo(event.target.value)}>
              {classicOptions.map((option) => (
                <option key={option.id} value={option.id}>
                  {option.label}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Mode">
            <select value={mode} onChange={(event) => setMode(event.target.value)}>
              <option value="encrypt">Chiffrement</option>
              <option value="decrypt">Dechiffrement</option>
            </select>
          </Field>
        </div>

        {algo !== "otp" ? (
          <Field label="Texte">
            <textarea value={text} onChange={(event) => setText(event.target.value)} />
          </Field>
        ) : null}

        {algo === "caesar" ? (
          <Field label="Decalage">
            <input
              type="number"
              value={shift}
              onChange={(event) => setShift(event.target.value)}
            />
          </Field>
        ) : null}

        {algo === "vigenere" || algo === "playfair" ? (
          <Field label="Cle">
            <input value={key} onChange={(event) => setKey(event.target.value)} />
          </Field>
        ) : null}

        {algo === "affine" ? (
          <div className="row">
            <Field label="a">
              <input
                type="number"
                value={aValue}
                onChange={(event) => setAValue(event.target.value)}
              />
            </Field>
            <Field label="b">
              <input
                type="number"
                value={bValue}
                onChange={(event) => setBValue(event.target.value)}
              />
            </Field>
          </div>
        ) : null}

        {algo === "hill" ? (
          <div className="grid-2">
            <Field label="a11">
              <input
                type="number"
                value={hill.a11}
                onChange={(event) => setHill({ ...hill, a11: event.target.value })}
              />
            </Field>
            <Field label="a12">
              <input
                type="number"
                value={hill.a12}
                onChange={(event) => setHill({ ...hill, a12: event.target.value })}
              />
            </Field>
            <Field label="a21">
              <input
                type="number"
                value={hill.a21}
                onChange={(event) => setHill({ ...hill, a21: event.target.value })}
              />
            </Field>
            <Field label="a22">
              <input
                type="number"
                value={hill.a22}
                onChange={(event) => setHill({ ...hill, a22: event.target.value })}
              />
            </Field>
          </div>
        ) : null}

        {algo === "otp" ? (
          <>
            <Field label={otpLabel} helper="Entree en base64">
              <textarea value={otpText} onChange={(event) => setOtpText(event.target.value)} />
            </Field>
            <Field label="key_base64" helper="Cle en base64 (meme taille que le message)">
              <textarea value={otpKey} onChange={(event) => setOtpKey(event.target.value)} />
            </Field>
          </>
        ) : null}

        <button type="submit" disabled={loading}>
          {loading ? "Traitement..." : "Executer"}
        </button>
        {error ? <p className="error">{error}</p> : null}
      </form>

      <ResultCard title="Resultat" content={result} />

      <form onSubmit={runAnalysis} className="card">
        <h3>Outils d'analyse</h3>
        <Field label="Outil">
          <select
            value={analysisTool}
            onChange={(event) => setAnalysisTool(event.target.value)}
          >
            <option value="caesar-bruteforce">Force brute Caesar</option>
            <option value="kasiski">Test de Kasiski</option>
            <option value="vigenere-ic">IC par longueur (Vigenere)</option>
            <option value="vigenere-estimate">Estimer la cle (Vigenere)</option>
          </select>
        </Field>

        <Field label="Texte a analyser">
          <textarea
            value={analysisText}
            onChange={(event) => setAnalysisText(event.target.value)}
          />
        </Field>

        {analysisTool === "kasiski" ? (
          <div className="row">
            <Field label="Longueur sequence">
              <input
                type="number"
                min={2}
                value={sequenceLen}
                onChange={(event) => setSequenceLen(event.target.value)}
              />
            </Field>
            <Field label="Longueur max cle">
              <input
                type="number"
                min={2}
                value={maxKeyLen}
                onChange={(event) => setMaxKeyLen(event.target.value)}
              />
            </Field>
          </div>
        ) : null}

        {analysisTool === "vigenere-ic" ? (
          <Field label="Longueur max cle">
            <input
              type="number"
              min={1}
              value={maxKeyLen}
              onChange={(event) => setMaxKeyLen(event.target.value)}
            />
          </Field>
        ) : null}

        {analysisTool === "vigenere-estimate" ? (
          <Field label="Longueur cle">
            <input
              type="number"
              min={1}
              value={estimateLen}
              onChange={(event) => setEstimateLen(event.target.value)}
            />
          </Field>
        ) : null}

        <button type="submit" disabled={analysisLoading}>
          {analysisLoading ? "Analyse..." : "Analyser"}
        </button>
        {analysisError ? <p className="error">{analysisError}</p> : null}
      </form>

      <ResultCard title="Resultat analyse" content={analysisResult} />
    </section>
  );
}

function SymmetricPanel() {
  const [algo, setAlgo] = useState("rc4");
  const [mode, setMode] = useState("encrypt");
  const [plaintext, setPlaintext] = useState("message secret");
  const [ciphertext, setCiphertext] = useState("");
  const [key, setKey] = useState("0123456789abcdef");
  const [iv, setIv] = useState("abcdef9876543210");
  const [result, setResult] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    setResult("");
    setLoading(true);

    try {
      let path = "";
      let payload = {};

      if (algo === "rc4") {
        path = `/symmetric/rc4/${mode}`;
        payload =
          mode === "encrypt"
            ? { plaintext, key }
            : { ciphertext_hex: ciphertext, key };
      } else {
        path = `/symmetric/${algo}/${mode}`;
        payload =
          mode === "encrypt"
            ? { plaintext, key, iv }
            : { ciphertext_hex: ciphertext, key, iv };
      }

      const data = await apiPost(path, payload);
      setResult(JSON.stringify(data, null, 2));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const showIv = algo !== "rc4";

  return (
    <section className="panel">
      <form onSubmit={submit} className="card">
        <div className="row">
          <Field label="Algorithme">
            <select value={algo} onChange={(event) => setAlgo(event.target.value)}>
              {symmetricOptions.map((option) => (
                <option key={option.id} value={option.id}>
                  {option.label}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Mode">
            <select value={mode} onChange={(event) => setMode(event.target.value)}>
              <option value="encrypt">Chiffrement</option>
              <option value="decrypt">Dechiffrement</option>
            </select>
          </Field>
        </div>

        {mode === "encrypt" ? (
          <Field label="Texte">
            <textarea
              value={plaintext}
              onChange={(event) => setPlaintext(event.target.value)}
            />
          </Field>
        ) : (
          <Field label="ciphertext_hex" helper="Hexadecimal">
            <textarea
              value={ciphertext}
              onChange={(event) => setCiphertext(event.target.value)}
            />
          </Field>
        )}

        <Field
          label="Cle"
          helper={
            algo === "rc4"
              ? "Libre"
              : "DES=8 bytes, RC6=16 bytes, autres=16/24/32 bytes"
          }
        >
          <input value={key} onChange={(event) => setKey(event.target.value)} />
        </Field>

        {showIv ? (
          <Field label="IV" helper={algo === "des" ? "8 bytes" : "16 bytes"}>
            <input value={iv} onChange={(event) => setIv(event.target.value)} />
          </Field>
        ) : null}

        <button type="submit" disabled={loading}>
          {loading ? "Traitement..." : "Executer"}
        </button>
        {error ? <p className="error">{error}</p> : null}
      </form>

      <ResultCard title="Resultat" content={result} />
    </section>
  );
}

function AsymmetricPanel() {
  const [algo, setAlgo] = useState("rsa-oaep");
  const [bits, setBits] = useState(2048);
  const [publicKey, setPublicKey] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [peerPublicKey, setPeerPublicKey] = useState("");
  const [mode, setMode] = useState("encrypt");
  const [message, setMessage] = useState("Bonjour RSA");
  const [ciphertext, setCiphertext] = useState("");
  const [pValue, setPValue] = useState("23");
  const [gValue, setGValue] = useState("5");
  const [alicePrivate, setAlicePrivate] = useState("6");
  const [bobPrivate, setBobPrivate] = useState("15");
  const [elgamalPrivate, setElgamalPrivate] = useState("6");
  const [elgamalMessage, setElgamalMessage] = useState("12345");
  const [elgamalEphemeral, setElgamalEphemeral] = useState("7");
  const [elgamalC1, setElgamalC1] = useState("");
  const [elgamalC2, setElgamalC2] = useState("");
  const [result, setResult] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const keygen = async () => {
    setError("");
    setResult("");
    setLoading(true);

    try {
      if (algo === "rsa-oaep") {
        const data = await apiPost("/crypto/keys/rsa", { bits: Number(bits) });
        setPublicKey(data.public_key_pem);
        setPrivateKey(data.private_key_pem);
        setResult(JSON.stringify(data, null, 2));
      } else if (algo === "ecc-ecdh") {
        const data = await apiPost("/asymmetric/ecc/p256/keygen", {});
        setPublicKey(data.public_key_base64);
        setPrivateKey(data.private_key_base64);
        setResult(JSON.stringify(data, null, 2));
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    setResult("");
    setLoading(true);

    try {
      let path = "";
      let payload = {};

      if (algo === "rsa-oaep") {
        if (mode === "encrypt") {
          path = "/crypto/rsa/oaep/encrypt";
          payload = {
            public_key_pem: publicKey,
            plaintext_base64: textToBase64(message)
          };
        } else {
          path = "/crypto/rsa/oaep/decrypt";
          payload = {
            private_key_pem: privateKey,
            ciphertext_base64: ciphertext
          };
        }
      } else if (algo === "dh") {
        path = "/asymmetric/dh/exchange";
        payload = {
          p: Number(pValue),
          g: Number(gValue),
          alice_private: Number(alicePrivate),
          bob_private: Number(bobPrivate)
        };
      } else if (algo === "elgamal") {
        if (mode === "encrypt") {
          path = "/asymmetric/elgamal/encrypt";
          payload = {
            p: Number(pValue),
            g: Number(gValue),
            private_key: Number(elgamalPrivate),
            message: Number(elgamalMessage),
            ephemeral_key: Number(elgamalEphemeral)
          };
        } else {
          path = "/asymmetric/elgamal/decrypt";
          payload = {
            p: Number(pValue),
            g: Number(gValue),
            private_key: Number(elgamalPrivate),
            c1: Number(elgamalC1),
            c2: Number(elgamalC2)
          };
        }
      } else if (algo === "ecc-ecdh") {
        path = "/asymmetric/ecc/p256/derive";
        payload = {
          private_key_base64: privateKey,
          peer_public_key_base64: peerPublicKey
        };
      }

      const data = await apiPost(path, payload);
      if (algo === "rsa-oaep" && mode === "decrypt") {
        try {
          const plain = base64ToText(data.plaintext_base64);
          data.plaintext_text = plain;
        } catch (err) {
          // ignore decoding errors
        }
      }
      if (algo === "elgamal" && mode === "encrypt") {
        setElgamalC1(String(data.c1 || ""));
        setElgamalC2(String(data.c2 || ""));
      }
      setResult(JSON.stringify(data, null, 2));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="panel">
      <div className="card">
        <Field label="Algorithme">
          <select value={algo} onChange={(event) => setAlgo(event.target.value)}>
            <option value="rsa-oaep">RSA-OAEP (moderne)</option>
            <option value="dh">Diffie-Hellman (educatif)</option>
            <option value="elgamal">ElGamal (educatif)</option>
            <option value="ecc-ecdh">ECC P-256 (ECDH)</option>
          </select>
        </Field>
      </div>

      <div className="card">
        {algo === "rsa-oaep" ? (
          <>
            <div className="row">
              <Field label="Taille RSA">
                <select value={bits} onChange={(event) => setBits(event.target.value)}>
                  <option value={2048}>2048</option>
                  <option value={3072}>3072</option>
                  <option value={4096}>4096</option>
                </select>
              </Field>
              <button type="button" onClick={keygen} disabled={loading}>
                Generer les cles
              </button>
            </div>
            <div className="grid-2">
              <Field label="Cle publique (PEM)">
                <textarea
                  value={publicKey}
                  onChange={(event) => setPublicKey(event.target.value)}
                />
              </Field>
              <Field label="Cle privee (PEM)">
                <textarea
                  value={privateKey}
                  onChange={(event) => setPrivateKey(event.target.value)}
                />
              </Field>
            </div>
          </>
        ) : null}

        {algo === "ecc-ecdh" ? (
          <>
            <div className="row">
              <button type="button" onClick={keygen} disabled={loading}>
                Generer les cles P-256
              </button>
            </div>
            <div className="grid-2">
              <Field label="Cle publique (base64)">
                <textarea
                  value={publicKey}
                  onChange={(event) => setPublicKey(event.target.value)}
                />
              </Field>
              <Field label="Cle privee (base64)">
                <textarea
                  value={privateKey}
                  onChange={(event) => setPrivateKey(event.target.value)}
                />
              </Field>
            </div>
            <Field label="Cle publique du peer (base64)">
              <textarea
                value={peerPublicKey}
                onChange={(event) => setPeerPublicKey(event.target.value)}
              />
            </Field>
          </>
        ) : null}
      </div>

      <form onSubmit={submit} className="card">
        {algo === "rsa-oaep" ? (
          <>
            <Field label="Mode">
              <select value={mode} onChange={(event) => setMode(event.target.value)}>
                <option value="encrypt">Chiffrement RSA-OAEP</option>
                <option value="decrypt">Dechiffrement RSA-OAEP</option>
              </select>
            </Field>

            {mode === "encrypt" ? (
              <Field label="Message">
                <textarea value={message} onChange={(event) => setMessage(event.target.value)} />
              </Field>
            ) : (
              <Field label="ciphertext_base64">
                <textarea
                  value={ciphertext}
                  onChange={(event) => setCiphertext(event.target.value)}
                />
              </Field>
            )}
          </>
        ) : null}

        {algo === "dh" ? (
          <div className="grid-2">
            <Field label="p">
              <input value={pValue} onChange={(event) => setPValue(event.target.value)} />
            </Field>
            <Field label="g">
              <input value={gValue} onChange={(event) => setGValue(event.target.value)} />
            </Field>
            <Field label="alice_private">
              <input
                value={alicePrivate}
                onChange={(event) => setAlicePrivate(event.target.value)}
              />
            </Field>
            <Field label="bob_private">
              <input
                value={bobPrivate}
                onChange={(event) => setBobPrivate(event.target.value)}
              />
            </Field>
          </div>
        ) : null}

        {algo === "elgamal" ? (
          <>
            <Field label="Mode">
              <select value={mode} onChange={(event) => setMode(event.target.value)}>
                <option value="encrypt">Chiffrement ElGamal</option>
                <option value="decrypt">Dechiffrement ElGamal</option>
              </select>
            </Field>
            <div className="grid-2">
              <Field label="p">
                <input value={pValue} onChange={(event) => setPValue(event.target.value)} />
              </Field>
              <Field label="g">
                <input value={gValue} onChange={(event) => setGValue(event.target.value)} />
              </Field>
              <Field label="cle privee">
                <input
                  value={elgamalPrivate}
                  onChange={(event) => setElgamalPrivate(event.target.value)}
                />
              </Field>
              {mode === "encrypt" ? (
                <>
                  <Field label="message">
                    <input
                      value={elgamalMessage}
                      onChange={(event) => setElgamalMessage(event.target.value)}
                    />
                  </Field>
                  <Field label="k (ephemere)">
                    <input
                      value={elgamalEphemeral}
                      onChange={(event) => setElgamalEphemeral(event.target.value)}
                    />
                  </Field>
                </>
              ) : (
                <>
                  <Field label="c1">
                    <input
                      value={elgamalC1}
                      onChange={(event) => setElgamalC1(event.target.value)}
                    />
                  </Field>
                  <Field label="c2">
                    <input
                      value={elgamalC2}
                      onChange={(event) => setElgamalC2(event.target.value)}
                    />
                  </Field>
                </>
              )}
            </div>
          </>
        ) : null}

        {algo === "ecc-ecdh" ? (
          <>
            <Field label="Deriver le secret partage">
              <span className="helper">Utilise cle privee + cle publique du peer</span>
            </Field>
          </>
        ) : null}

        <button type="submit" disabled={loading}>
          {loading ? "Traitement..." : "Executer"}
        </button>
        {error ? <p className="error">{error}</p> : null}
      </form>

      <ResultCard title="Resultat" content={result} />
    </section>
  );
}

function HashPanel() {
  const [algo, setAlgo] = useState("sha256");
  const [text, setText] = useState("message");
  const [key, setKey] = useState("secret");
  const [result, setResult] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    setResult("");
    setLoading(true);

    try {
      const path = algo === "hmac" ? "/hash/hmac" : `/hash/${algo}`;
      const payload = algo === "hmac" ? { text, key } : { text };
      const data = await apiPost(path, payload);
      setResult(JSON.stringify(data, null, 2));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="panel">
      <form onSubmit={submit} className="card">
        <Field label="Algorithme">
          <select value={algo} onChange={(event) => setAlgo(event.target.value)}>
            {hashOptions.map((option) => (
              <option key={option.id} value={option.id}>
                {option.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Texte">
          <textarea value={text} onChange={(event) => setText(event.target.value)} />
        </Field>
        {algo === "hmac" ? (
          <Field label="Cle HMAC">
            <input value={key} onChange={(event) => setKey(event.target.value)} />
          </Field>
        ) : null}
        <button type="submit" disabled={loading}>
          {loading ? "Traitement..." : "Executer"}
        </button>
        {error ? <p className="error">{error}</p> : null}
      </form>

      <ResultCard title="Resultat" content={result} />
    </section>
  );
}

function SecureChatPanel() {
  const [room, setRoom] = useState("tp6");
  const [name, setName] = useState("Alice");
  const [status, setStatus] = useState("disconnected");
  const [wsClient, setWsClient] = useState(null);
  const [logs, setLogs] = useState([]);
  const [message, setMessage] = useState("Bonjour Bob");

  const [rsaPublic, setRsaPublic] = useState("");
  const [rsaPrivate, setRsaPrivate] = useState("");
  const [peerPublic, setPeerPublic] = useState("");

  const [aesKeyBase64, setAesKeyBase64] = useState("");
  const [aesKey, setAesKey] = useState(null);

  const nameRef = useRef(name);
  const rsaPrivateRef = useRef(rsaPrivate);
  const aesKeyRef = useRef(aesKey);

  useEffect(() => {
    nameRef.current = name;
  }, [name]);

  useEffect(() => {
    rsaPrivateRef.current = rsaPrivate;
  }, [rsaPrivate]);

  useEffect(() => {
    aesKeyRef.current = aesKey;
  }, [aesKey]);

  const addLog = (entry) => {
    setLogs((prev) => [entry, ...prev].slice(0, 50));
  };

  const connect = () => {
    if (wsClient) {
      return;
    }

    const ws = new WebSocket(toWsUrl(API_BASE, room, name));
    setStatus("connecting");

    ws.onopen = () => {
      setStatus("connected");
      addLog({ kind: "system", text: "Connecte au serveur" });
    };

    ws.onclose = () => {
      setStatus("disconnected");
      setWsClient(null);
      addLog({ kind: "system", text: "Connexion fermee" });
    };

    ws.onerror = () => {
      addLog({ kind: "error", text: "Erreur WebSocket" });
    };

    ws.onmessage = async (event) => {
      try {
        const serverMsg = JSON.parse(event.data);
        if (serverMsg.type === "join" || serverMsg.type === "leave") {
          addLog({ kind: "system", text: serverMsg.payload || serverMsg.type });
          return;
        }

        if (serverMsg.type !== "message") {
          return;
        }

        const payload = serverMsg.payload ? JSON.parse(serverMsg.payload) : null;
        if (!payload) {
          return;
        }

        if (payload.kind === "public_key") {
          setPeerPublic(payload.public_key_pem || "");
          addLog({ kind: "system", text: `Cle publique recu de ${serverMsg.sender}` });
          return;
        }

        if (payload.kind === "wrapped_key") {
          if (serverMsg.sender === nameRef.current) {
            return;
          }
          if (!rsaPrivateRef.current) {
            addLog({ kind: "error", text: "Cle privee manquante pour dechiffrer" });
            return;
          }
          const data = await apiPost("/crypto/rsa/oaep/decrypt", {
            private_key_pem: rsaPrivateRef.current,
            ciphertext_base64: payload.ciphertext_base64
          });
          await setAesFromBase64(data.plaintext_base64);
          addLog({ kind: "system", text: "Cle AES dechiffree" });
          return;
        }

        if (payload.kind === "cipher") {
          if (serverMsg.sender === nameRef.current) {
            return;
          }
          if (!aesKeyRef.current) {
            addLog({ kind: "error", text: "Cle AES manquante pour dechiffrer" });
            return;
          }
          const plaintext = await decryptMessage(payload, aesKeyRef.current);
          addLog({ kind: "in", text: `${serverMsg.sender}: ${plaintext}` });
        }
      } catch (err) {
        addLog({ kind: "error", text: "Message invalide" });
      }
    };

    setWsClient(ws);
  };

  const disconnect = () => {
    if (wsClient) {
      wsClient.close();
    }
  };

  const sendPayload = (payload) => {
    if (!wsClient || wsClient.readyState !== WebSocket.OPEN) {
      addLog({ kind: "error", text: "WS non connecte" });
      return;
    }
    wsClient.send(JSON.stringify({ type: "message", payload: JSON.stringify(payload) }));
  };

  const generateRsa = async () => {
    const data = await apiPost("/crypto/keys/rsa", { bits: 2048 });
    setRsaPublic(data.public_key_pem);
    setRsaPrivate(data.private_key_pem);
    addLog({ kind: "system", text: "Cles RSA generees" });
  };

  const sharePublicKey = () => {
    if (!rsaPublic) {
      addLog({ kind: "error", text: "Cle publique manquante" });
      return;
    }
    sendPayload({ kind: "public_key", public_key_pem: rsaPublic });
  };

  const generateAes = async () => {
    const key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
    const base64 = bytesToBase64(raw);
    setAesKeyBase64(base64);
    setAesKey(key);
    addLog({ kind: "system", text: "Cle AES generee" });
    return { base64, key };
  };

  const setAesFromBase64 = async (base64) => {
    const bytes = base64ToBytes(base64);
    const key = await crypto.subtle.importKey(
      "raw",
      bytes,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
    setAesKeyBase64(base64);
    setAesKey(key);
  };

  const sendAesKey = async () => {
    if (!peerPublic) {
      addLog({ kind: "error", text: "Cle publique du peer manquante" });
      return;
    }
    let base64 = aesKeyBase64;
    if (!base64) {
      const generated = await generateAes();
      base64 = generated.base64;
    }
    const data = await apiPost("/crypto/rsa/oaep/encrypt", {
      public_key_pem: peerPublic,
      plaintext_base64: base64
    });
    sendPayload({ kind: "wrapped_key", ciphertext_base64: data.ciphertext_base64 });
    addLog({ kind: "system", text: "Cle AES envoyee" });
  };

  const encryptMessage = async (plaintext, key) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      new TextEncoder().encode(plaintext)
    );
    return {
      kind: "cipher",
      nonce_base64: bytesToBase64(iv),
      ciphertext_base64: bytesToBase64(new Uint8Array(ciphertext))
    };
  };

  const decryptMessage = async (payload, key) => {
    const iv = base64ToBytes(payload.nonce_base64);
    const ciphertext = base64ToBytes(payload.ciphertext_base64);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );
    return new TextDecoder().decode(plaintext);
  };

  const sendSecureMessage = async () => {
    if (!aesKey) {
      addLog({ kind: "error", text: "Cle AES manquante" });
      return;
    }
    const payload = await encryptMessage(message, aesKey);
    sendPayload(payload);
    addLog({ kind: "out", text: `Moi: ${message}` });
  };

  return (
    <section className="panel">
      <div className="card">
        <h3>Connexion</h3>
        <div className="row">
          <Field label="Room">
            <input value={room} onChange={(event) => setRoom(event.target.value)} />
          </Field>
          <Field label="Nom">
            <input value={name} onChange={(event) => setName(event.target.value)} />
          </Field>
        </div>
        <div className="row">
          <button type="button" onClick={connect} disabled={status === "connected"}>
            Connecter
          </button>
          <button type="button" className="ghost" onClick={disconnect}>
            Deconnecter
          </button>
          <span className={`status ${status}`}>{status}</span>
        </div>
      </div>

      <div className="card">
        <h3>Cles RSA</h3>
        <div className="row">
          <button type="button" onClick={generateRsa}>
            Generer RSA
          </button>
          <button type="button" className="ghost" onClick={sharePublicKey}>
            Partager cle publique
          </button>
        </div>
        <Field label="Cle publique">
          <textarea value={rsaPublic} onChange={(event) => setRsaPublic(event.target.value)} />
        </Field>
        <Field label="Cle privee">
          <textarea value={rsaPrivate} onChange={(event) => setRsaPrivate(event.target.value)} />
        </Field>
        <Field label="Cle publique du peer">
          <textarea value={peerPublic} onChange={(event) => setPeerPublic(event.target.value)} />
        </Field>
      </div>

      <div className="card">
        <h3>Cle AES</h3>
        <div className="row">
          <button type="button" onClick={generateAes}>
            Generer AES
          </button>
          <button type="button" className="ghost" onClick={sendAesKey}>
            Envoyer la cle AES
          </button>
        </div>
        <Field label="AES (base64)">
          <textarea
            value={aesKeyBase64}
            onChange={(event) => setAesFromBase64(event.target.value)}
          />
        </Field>
      </div>

      <div className="card">
        <h3>Message securise</h3>
        <Field label="Message">
          <textarea value={message} onChange={(event) => setMessage(event.target.value)} />
        </Field>
        <button type="button" onClick={sendSecureMessage}>
          Envoyer
        </button>
      </div>

      <div className="card">
        <h3>Journal</h3>
        <div className="chat-log">
          {logs.length === 0 ? <p>Aucun message</p> : null}
          {logs.map((entry, index) => (
            <div key={`${entry.kind}-${index}`} className={`chat-item ${entry.kind}`}>
              <span>{entry.text}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function SignaturesPanel() {
  const [algo, setAlgo] = useState("rsa-pss");
  const [messageSign, setMessageSign] = useState("hello");
  const [messageVerify, setMessageVerify] = useState("hello");
  const [pValue, setPValue] = useState("61");
  const [qValue, setQValue] = useState("53");
  const [eValue, setEValue] = useState("17");
  const [gValue, setGValue] = useState("5");
  const [dsaQ, setDsaQ] = useState("11");
  const [privateKey, setPrivateKey] = useState("6");
  const [publicKey, setPublicKey] = useState("8");
  const [ephemeralKey, setEphemeralKey] = useState("7");
  const [ecdsaPrivate, setEcdsaPrivate] = useState("7");
  const [ecdsaPublicX, setEcdsaPublicX] = useState("0");
  const [ecdsaPublicY, setEcdsaPublicY] = useState("6");
  const [signatureValue, setSignatureValue] = useState("");
  const [signatureR, setSignatureR] = useState("");
  const [signatureS, setSignatureS] = useState("");
  const [verifyResult, setVerifyResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const usesPairSignature = ["dsa", "ecdsa", "elgamal"].includes(algo);

  const derivePublicKey = () => {
    if (algo === "dsa" || algo === "elgamal") {
      try {
        const pub = modPow(gValue || 0, privateKey || 0, pValue || 1).toString();
        setPublicKey(pub);
      } catch (err) {
        setError("Impossible de calculer la cle publique");
      }
    }
  };

  const sign = async () => {
    setError("");
    setVerifyResult(null);
    setLoading(true);

    try {
      let path = "";
      let payload = {};

      if (algo === "rsa-pss") {
        path = "/signature/rsa/sign";
        payload = { p: Number(pValue), q: Number(qValue), e: Number(eValue), message: messageSign };
      } else if (algo === "rsa-pkcs1v15") {
        path = "/signature/rsa/pkcs1v15/sign";
        payload = { p: Number(pValue), q: Number(qValue), e: Number(eValue), message: messageSign };
      } else if (algo === "dsa") {
        path = "/signature/dsa/sign";
        payload = {
          p: Number(pValue),
          q: Number(dsaQ),
          g: Number(gValue),
          private_key: Number(privateKey),
          message: messageSign,
          ephemeral_key: Number(ephemeralKey)
        };
      } else if (algo === "ecdsa") {
        path = "/signature/ecdsa/sign";
        payload = {
          private_key: Number(ecdsaPrivate),
          message: messageSign,
          ephemeral_key: Number(ephemeralKey)
        };
      } else if (algo === "elgamal") {
        path = "/signature/elgamal/sign";
        payload = {
          p: Number(pValue),
          g: Number(gValue),
          private_key: Number(privateKey),
          message: messageSign,
          ephemeral_key: Number(ephemeralKey)
        };
      }

      const data = await apiPost(path, payload);
      if (usesPairSignature) {
        setSignatureR(String(data.r));
        setSignatureS(String(data.s));
      } else {
        setSignatureValue(String(data.signature));
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const verify = async () => {
    setError("");
    setVerifyResult(null);
    setLoading(true);

    try {
      let path = "";
      let payload = {};

      if (algo === "rsa-pss") {
        path = "/signature/rsa/verify";
        payload = {
          p: Number(pValue),
          q: Number(qValue),
          e: Number(eValue),
          message: messageVerify,
          signature: Number(signatureValue)
        };
      } else if (algo === "rsa-pkcs1v15") {
        path = "/signature/rsa/pkcs1v15/verify";
        payload = {
          p: Number(pValue),
          q: Number(qValue),
          e: Number(eValue),
          message: messageVerify,
          signature: Number(signatureValue)
        };
      } else if (algo === "dsa") {
        path = "/signature/dsa/verify";
        payload = {
          p: Number(pValue),
          q: Number(dsaQ),
          g: Number(gValue),
          public_key: Number(publicKey),
          message: messageVerify,
          r: Number(signatureR),
          s: Number(signatureS)
        };
      } else if (algo === "ecdsa") {
        path = "/signature/ecdsa/verify";
        payload = {
          public_key_x: Number(ecdsaPublicX),
          public_key_y: Number(ecdsaPublicY),
          message: messageVerify,
          r: Number(signatureR),
          s: Number(signatureS)
        };
      } else if (algo === "elgamal") {
        path = "/signature/elgamal/verify";
        payload = {
          p: Number(pValue),
          g: Number(gValue),
          public_key: Number(publicKey),
          message: messageVerify,
          r: Number(signatureR),
          s: Number(signatureS)
        };
      }

      const data = await apiPost(path, payload);
      setVerifyResult(Boolean(data.valid));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="panel">
      <div className="card">
        <Field label="Algorithme">
          <select value={algo} onChange={(event) => setAlgo(event.target.value)}>
            {signatureOptions.map((option) => (
              <option key={option.id} value={option.id}>
                {option.label}
              </option>
            ))}
          </select>
        </Field>

        {(algo === "rsa-pss" || algo === "rsa-pkcs1v15") ? (
          <div className="grid-2">
            <Field label="p">
              <input value={pValue} onChange={(event) => setPValue(event.target.value)} />
            </Field>
            <Field label="q">
              <input value={qValue} onChange={(event) => setQValue(event.target.value)} />
            </Field>
            <Field label="e">
              <input value={eValue} onChange={(event) => setEValue(event.target.value)} />
            </Field>
          </div>
        ) : null}

        {algo === "dsa" ? (
          <div className="grid-2">
            <Field label="p">
              <input value={pValue} onChange={(event) => setPValue(event.target.value)} />
            </Field>
            <Field label="q">
              <input value={dsaQ} onChange={(event) => setDsaQ(event.target.value)} />
            </Field>
            <Field label="g">
              <input value={gValue} onChange={(event) => setGValue(event.target.value)} />
            </Field>
            <Field label="cle privee">
              <input value={privateKey} onChange={(event) => setPrivateKey(event.target.value)} />
            </Field>
            <Field label="cle publique">
              <input value={publicKey} onChange={(event) => setPublicKey(event.target.value)} />
            </Field>
            <Field label="k (ephemere)">
              <input value={ephemeralKey} onChange={(event) => setEphemeralKey(event.target.value)} />
            </Field>
            <button type="button" className="ghost" onClick={derivePublicKey}>
              Deriver la cle publique
            </button>
          </div>
        ) : null}

        {algo === "ecdsa" ? (
          <div className="grid-2">
            <Field label="cle privee">
              <input value={ecdsaPrivate} onChange={(event) => setEcdsaPrivate(event.target.value)} />
            </Field>
            <Field label="cle publique x">
              <input value={ecdsaPublicX} onChange={(event) => setEcdsaPublicX(event.target.value)} />
            </Field>
            <Field label="cle publique y">
              <input value={ecdsaPublicY} onChange={(event) => setEcdsaPublicY(event.target.value)} />
            </Field>
            <Field label="k (ephemere)">
              <input value={ephemeralKey} onChange={(event) => setEphemeralKey(event.target.value)} />
            </Field>
          </div>
        ) : null}

        {algo === "elgamal" ? (
          <div className="grid-2">
            <Field label="p">
              <input value={pValue} onChange={(event) => setPValue(event.target.value)} />
            </Field>
            <Field label="g">
              <input value={gValue} onChange={(event) => setGValue(event.target.value)} />
            </Field>
            <Field label="cle privee">
              <input value={privateKey} onChange={(event) => setPrivateKey(event.target.value)} />
            </Field>
            <Field label="cle publique">
              <input value={publicKey} onChange={(event) => setPublicKey(event.target.value)} />
            </Field>
            <Field label="k (ephemere)">
              <input value={ephemeralKey} onChange={(event) => setEphemeralKey(event.target.value)} />
            </Field>
            <button type="button" className="ghost" onClick={derivePublicKey}>
              Deriver la cle publique
            </button>
          </div>
        ) : null}
      </div>

      <div className="card">
        <h3>Signer</h3>
        <Field label="Message">
          <textarea value={messageSign} onChange={(event) => setMessageSign(event.target.value)} />
        </Field>
        <button type="button" onClick={sign} disabled={loading}>
          {loading ? "Signature..." : "Signer"}
        </button>
        {usesPairSignature ? (
          <div className="grid-2">
            <Field label="r">
              <input value={signatureR} onChange={(event) => setSignatureR(event.target.value)} />
            </Field>
            <Field label="s">
              <input value={signatureS} onChange={(event) => setSignatureS(event.target.value)} />
            </Field>
          </div>
        ) : (
          <Field label="signature">
            <input value={signatureValue} onChange={(event) => setSignatureValue(event.target.value)} />
          </Field>
        )}
      </div>

      <div className="card">
        <h3>Verifier</h3>
        <Field label="Message">
          <textarea
            value={messageVerify}
            onChange={(event) => setMessageVerify(event.target.value)}
          />
        </Field>
        <div className="row">
          <button type="button" onClick={verify} disabled={loading}>
            {loading ? "Verification..." : "Verifier"}
          </button>
          <button
            type="button"
            className="ghost"
            onClick={() => setMessageVerify(`${messageVerify}!`)}
          >
            Attaque: modifier message
          </button>
        </div>
        {verifyResult !== null ? (
          <div className={`badge ${verifyResult ? "ok" : "bad"}`}>
            {verifyResult ? "Signature valide" : "Signature invalide"}
          </div>
        ) : null}
      </div>

      {error ? <p className="error">{error}</p> : null}
    </section>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState("classic");
  const activeLabel = useMemo(
    () => tabs.find((tab) => tab.id === activeTab)?.label || "",
    [activeTab]
  );

  return (
    <div className="page">
      <header className="hero">
        <div>
          <p className="kicker">Welcome to </p>
          <h1>Sikrypt</h1>
          <p className="subtitle">
            Teste rapidement les algorithmes classic, symmetric, asymmetric, signatures et hash.
          </p>
        </div>
        <div className="hero-card">
          <h2>{activeLabel}</h2>
          <p>Backend: {API_BASE}</p>
          <span className="pill">API educative</span>
        </div>
      </header>

      <nav className="tabs">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={activeTab === tab.id ? "active" : ""}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {activeTab === "classic" ? <ClassicPanel /> : null}
      {activeTab === "symmetric" ? <SymmetricPanel /> : null}
      {activeTab === "asymmetric" ? <AsymmetricPanel /> : null}
      {activeTab === "signatures" ? <SignaturesPanel /> : null}
      {activeTab === "secure" ? <SecureChatPanel /> : null}
      {activeTab === "hash" ? <HashPanel /> : null}

      <footer className="footer">
        <p>Projet educatif - Sikrypt</p>
      </footer>
    </div>
  );
}
