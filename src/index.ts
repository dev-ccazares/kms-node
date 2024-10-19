import { EncryptManager } from "./service/encrypt-decrypt";

export class Runner {

  service = new EncryptManager();

  async run(): Promise<void> {
    try {
      console.log("--- Inicio de la encriptación ---");
      const publicKeyPem = await this.service.getPublicKeyFromKms();

      console.log(`Clave pública obtenida:\n${publicKeyPem}`);
      // Encriptar el mensaje
      const encrypted = this.service.encryptKms("mensaje de prueba", publicKeyPem);
      console.log(`Mensaje encriptado: ${encrypted}`);
      // Desencriptar el mensaje
      const decrypted = await this.service.decryptKms(encrypted);
      console.log(`Mensaje desencriptado: ${decrypted}`);

      console.log("--- Fin de la encriptación ---");
    } catch (error) {
      console.error(error);
    }
  }
}

// Ejecución del ejemplo
const ctl = new Runner();
ctl.run().then(() => console.log("Proceso finalizado"));
