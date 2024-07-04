import { crypto } from "k6/x/webcrypto";

export default async function () {
  const keyPkcs = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 1024,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );
  console.log(JSON.stringify(keyPkcs));

  const keyPss = await crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-384",
    },
    true,
    ["sign", "verify"]
  );
  console.log(JSON.stringify(keyPss));

  const keyOaep = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-512",
    },
    true,
    ["encrypt", "decrypt"]
  );
  console.log(JSON.stringify(keyOaep));
}