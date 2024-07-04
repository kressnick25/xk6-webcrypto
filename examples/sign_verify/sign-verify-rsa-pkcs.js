import { crypto } from "k6/x/webcrypto";

export default async function () {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 1024,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );

  const data = string2ArrayBuffer("Hello World");

  const alg = { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } };

  // makes a signature of the encoded data with the provided key
  const signature = await crypto.subtle.sign(alg, keyPair.privateKey, data);

  console.log("signature: ", printArrayBuffer(signature));

}

const string2ArrayBuffer = (str) => {
  let buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
  let bufView = new Uint16Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
};

const printArrayBuffer = (buffer) => {
  let view = new Uint8Array(buffer);
  return Array.from(view);
};
