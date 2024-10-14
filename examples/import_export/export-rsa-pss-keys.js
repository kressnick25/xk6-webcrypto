import { crypto } from "k6/x/webcrypto";

export default async function () {
  const generatedKeyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-384",
    },
    true,
    ["sign", "verify"]
  );
  console.log(JSON.stringify(generatedKeyPair));

  const exportedPrivateKey = await crypto.subtle.exportKey(
    "pkcs8",
    generatedKeyPair.privateKey
  );
  console.log("exported private key: " + printArrayBuffer(exportedPrivateKey));


  const exportedPublicKey = await crypto.subtle.exportKey(
    "spki",
    generatedKeyPair.publicKey
  );
  console.log("exported public key: " + printArrayBuffer(exportedPublicKey));

  // TODO
/*
  const exportedJwk = crypto.subtle.exportKey(
    "jwk",
    generatedKeyPair
  );
  console.log("exported jwk: " + printArrayBuffer(exportedPublicKey));
*/
}

const printArrayBuffer = (buffer) => {
  let view = new Uint8Array(buffer);
  return Array.from(view);
};
