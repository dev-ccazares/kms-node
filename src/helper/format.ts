// Funcion para formatear la llave pública en PEM
export function formatPublicKey(publicKeyDer: any): string {
  try {
    console.log("--------- formatPublicKey method started ---------");

    //Transformamos la llave pública en base 64
    const publicKeyBase64 = publicKeyDer.toString("base64");

    //Damos formato pem
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64
      .match(/.{1,64}/g)
      ?.join("\n")}\n-----END PUBLIC KEY-----\n`;

    return publicKeyPem;
  } catch (error) {
    console.error(
      "--------- Something went wrong foramting the public key ---------",
      error
    );
    throw error;
  }
}
