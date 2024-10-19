import { KMS } from "aws-sdk";
import * as crypto from "crypto";

import { awsConfig, paramsSecurity, keyId } from "../config/configs";
import { formatPublicKey } from "../helper/format";



export class EncryptManager {
  kms;

  constructor() {
    this.kms = new KMS({
      ...awsConfig,
    });
  }

  // Función para obtener la clave pública en formato PEM desde AWS KMS
  async getPublicKeyFromKms(): Promise<string> {
    try {
      console.log('--------- getPublicKeyFromKms method started ---------');

      //Obtenemos la llave pública de kms
      const data = await this.kms.getPublicKey(paramsSecurity).promise();

      //Si la llave es una llave publica le damos formato pem
      if (data.PublicKey) {
        const publicKeyPem = formatPublicKey(data.PublicKey);
        console.log('--------- getPublicKeyFromKms method finished ---------');
        return publicKeyPem;
      }

      //Si la llave no es publica lanzamos error
      throw new Error('They key is not a public key')
    } catch (error) {
      console.error('--------- Something went wrong retrieving the keys from kms ---------', error);
      throw error;
    }
  }

  // Encripta usando la clave pública obtenida desde KMS
  public encryptKms(plaintextData: string, publicKeyUser: string): string {
    try {
      // Convertir la clave pública PEM a un objeto clave pública que pueda ser usado por `publicEncrypt`
      const publicKey = crypto.createPublicKey({
        key: publicKeyUser,
        format: "pem", // Aseguramos que esté en formato PEM
        type: "spki", // Tipo de clave pública
      });

      // Usar `publicEncrypt` para cifrar los datos
      const encryptedText = crypto.publicEncrypt(
        {
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256", // Asegúrate de que coincida con el algoritmo que usas en KMS
        },
        Buffer.from(plaintextData, "utf-8")//Se transforma el string a buffer
      );
    
      return encryptedText.toString("base64");
    } catch (error) {
      console.error('--------- Something went wrong during encryption ---------', error);
      throw error;
    }
  }

  // Desencripta usando AWS KMS
  public async decryptKms(encryptedData: string): Promise<string | undefined> {
    try {
      const params = {
        CiphertextBlob: Buffer.from(encryptedData, "base64"),//Transformamos el mensaje encriptado en buffer
        KeyId: keyId,//Llamamos el Key id de la llave publica
        EncryptionAlgorithm: "RSAES_OAEP_SHA_256", // Se debe usar el mismo algoritmo de cifrado
      };

      // Usar `decrypt` para decifrar los datos
      const response = await this.kms.decrypt(params).promise();
      
      //Transformamos el mensaje desencriptado a string
      return response.Plaintext?.toString("utf-8");
    } catch (error) {
      console.log(`Error during decryption: ${error}`);
      throw error;
    }
  }
}

