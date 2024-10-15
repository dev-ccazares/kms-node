import { KMS } from "aws-sdk";
import * as crypto from "crypto";

export class AppController {
  kms;

  constructor() {
    this.kms = new KMS({
      endpoint: "http://localhost:4566", // Cambia por el endpoint de KMS real si no estás usando LocalStack
      region: "us-east-1",
      signatureVersion: "v4",
      ...this.awsConfig,
    });
  }

  awsConfig = {
    accessKeyId: "test",
    secretAccessKey: "test",
  };

  keyId = "17680c77-4b4f-4ac1-8581-ba973d09a781";

  paramsSecurity = {
    KeyId: this.keyId,
    GrantTokens: [this.keyId],
  };

  // Función para obtener la clave pública en formato PEM desde AWS KMS
  async getPublicKey(): Promise<string | undefined> {
    try {
      const data = await this.kms.getPublicKey(this.paramsSecurity).promise();
      if (data.PublicKey) {
        const publicKeyPem = this.formatPublicKey(data.PublicKey);
        return publicKeyPem;
      }
    } catch (error) {
      console.log(error);
      throw error;
    }
  }

  // Correctamente formatea la clave pública en PEM
  public formatPublicKey(publicKeyDer: any): string {
    const publicKeyBase64 = publicKeyDer.toString("base64");
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64
      .match(/.{1,64}/g)
      ?.join("\n")}\n-----END PUBLIC KEY-----\n`;
    return publicKeyPem;
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
        Buffer.from(plaintextData, "utf-8")
      );
      return encryptedText.toString("base64");
    } catch (error) {
      console.log(`Error during encryption: ${error}`);
      throw error;
    }
  }

  // Desencripta usando AWS KMS
  public async decryptKms(encryptedData: string): Promise<string | undefined> {
    try {
      const params = {
        CiphertextBlob: Buffer.from(encryptedData, "base64"),
        KeyId: this.keyId,
        EncryptionAlgorithm: "RSAES_OAEP_SHA_256", // Debes usar el mismo algoritmo de cifrado
      };
      const response = await this.kms.decrypt(params).promise();
      return response.Plaintext?.toString("utf-8");
    } catch (error) {
      console.log(`Error during decryption: ${error}`);
      throw error;
    }
  }

  async encrypt2(): Promise<void> {
    try {
      console.log("--- Inicio de la encriptación ---");
      const publicKeyPem = await this.getPublicKey();
      if (publicKeyPem) {
        console.log(`Clave pública obtenida:\n${publicKeyPem}`);
        // Encriptar el mensaje
        const encrypted = this.encryptKms("mensaje de prueba", publicKeyPem);
        console.log(`Mensaje encriptado: ${encrypted}`);
        // Desencriptar el mensaje
        const decrypted = await this.decryptKms(encrypted);
        console.log(`Mensaje desencriptado: ${decrypted}`);
      }
      console.log("--- Fin de la encriptación ---");
    } catch (error) {
      console.error(error);
    }
  }
}

// Ejecución del ejemplo
const ctl = new AppController();
ctl.encrypt2().then(() => console.log("Proceso finalizado"));
