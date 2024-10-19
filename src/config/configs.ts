export const awsConfig = {
    endpoint: "http://localhost:4566",//endpoint del localstack
    region: "us-east-1",//región de configuración del localstack
    signatureVersion: "v4",
    accessKeyId: "test",//accessKeyId configurada en localstack
    secretAccessKey: "test",//secretAccessKey configurada en localstack
  };

export const keyId = "17680c77-4b4f-4ac1-8581-ba973d09a781"; //keyId generada con kms

export const paramsSecurity = { //Params security para buscar en kms la llave pu
    KeyId: keyId,
    GrantTokens: [keyId],
  };