"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information
   */
  constructor(masterKey, hmacKey, aesKey, salt) {
    this.data = { 
      kvs: {},  // Key-Value Store for encrypted passwords
      salt: salt  // Store salt for key derivation
    };
    this.secrets = {
      masterKey: masterKey,
      hmacKey: hmacKey,
      aesKey: aesKey
    };
  }

  /** 
    * Creates an empty keychain with the given password.
    */
  static async init(password) {
    // Generate salt
    const salt = getRandomBytes(16);  // 128-bit salt as recommended

    // Import password as key material
    const rawKey = await subtle.importKey(
      "raw", 
      stringToBuffer(password), 
      "PBKDF2", 
      false, 
      ["deriveKey"]
    );

    // Derive master key using PBKDF2
    const masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      rawKey,
      { name: "HMAC", hash: "SHA-256" },
      true,
      ["sign", "verify"]
    );

    // Derive two sub-keys using HMAC
    const hmacKey = await subtle.sign(
      { name: "HMAC", hash: "SHA-256" },
      masterKey,
      stringToBuffer("mac")
    );

    const aesKey = await subtle.sign(
      { name: "HMAC", hash: "SHA-256" },
      masterKey,
      stringToBuffer("enc")
    );

    // Import AES key for encryption
    const importedAesKey = await subtle.importKey(
      "raw", 
      aesKey, 
      "AES-GCM", 
      true, 
      ["encrypt", "decrypt"]
    );

    // Create and return new Keychain instance
    return new Keychain(masterKey, hmacKey, importedAesKey, encodeBuffer(salt));
  }

  /**
    * Loads the keychain state from the provided representation
    */
  static async load(password, repr, trustedDataCheck) {
    // Parse the representation
    const parsedRepr = JSON.parse(repr);
    const salt = decodeBuffer(parsedRepr.salt);

    // Verify integrity if trusted data check is provided
    if (trustedDataCheck !== undefined) {
      const computedHash = await subtle.digest("SHA-256", stringToBuffer(repr));
      const computedHashStr = encodeBuffer(computedHash);
      
      if (computedHashStr !== trustedDataCheck) {
        throw "Integrity check failed: Potential tampering detected";
      }
    }

    // Import password as key material
    const rawKey = await subtle.importKey(
      "raw", 
      stringToBuffer(password), 
      "PBKDF2", 
      false, 
      ["deriveKey"]
    );

    // Derive master key using PBKDF2
    const masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      rawKey,
      { name: "HMAC", hash: "SHA-256" },
      true,
      ["sign", "verify"]
    );

    // Derive two sub-keys using HMAC
    const hmacKey = await subtle.sign(
      { name: "HMAC", hash: "SHA-256" },
      masterKey,
      stringToBuffer("mac")
    );

    const aesKey = await subtle.sign(
      { name: "HMAC", hash: "SHA-256" },
      masterKey,
      stringToBuffer("enc")
    );

    // Import AES key for encryption
    const importedAesKey = await subtle.importKey(
      "raw", 
      aesKey, 
      "AES-GCM", 
      true, 
      ["encrypt", "decrypt"]
    );

    // Create keychain instance
    const keychain = new Keychain(masterKey, hmacKey, importedAesKey, encodeBuffer(salt));
    
    // Restore KVS
    keychain.data.kvs = parsedRepr.kvs;

    return keychain;
  }

  /**
    * Returns a JSON serialization of the contents of the keychain
    */
  async dump() {
    // Prepare data for serialization
    const serializableData = {
      kvs: this.data.kvs,
      salt: this.data.salt
    };

    // Convert to JSON
    const jsonRepr = JSON.stringify(serializableData);

    // Compute SHA-256 hash
    const hash = await subtle.digest("SHA-256", stringToBuffer(jsonRepr));
    const hashStr = encodeBuffer(hash);

    return [jsonRepr, hashStr];
  }

  /**
    * Fetches the data corresponding to the given domain from the KVS
    */
  async get(name) {
    // Hash the domain name
    const hashedDomain = encodeBuffer(
      await subtle.sign({ name: "HMAC", hash: "SHA-256" }, this.secrets.masterKey, stringToBuffer(name))
    );

    // Check if domain exists in KVS
    if (!this.data.kvs[hashedDomain]) {
      return null;
    }

    // Decrypt the password
    const encryptedData = decodeBuffer(this.data.kvs[hashedDomain]);
    
    // Split encrypted data into IV and actual ciphertext
    const iv = encryptedData.slice(0, 12);  // 12-byte IV for AES-GCM
    const ciphertext = encryptedData.slice(12);

    const decryptedData = await subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      this.secrets.aesKey,
      ciphertext
    );

    return bufferToString(decryptedData);
  }

  /** 
  * Inserts the domain and associated data into the KVS
  */
  async set(name, value) {
    // Validate password length
    if (value.length > MAX_PASSWORD_LENGTH) {
      throw "Password exceeds maximum length";
    }

    // Hash the domain name
    const hashedDomain = encodeBuffer(
      await subtle.sign({ name: "HMAC", hash: "SHA-256" }, this.secrets.masterKey, stringToBuffer(name))
    );

    // Generate random IV
    const iv = getRandomBytes(12);  // 12-byte IV for AES-GCM

    // Encrypt the password
    const encryptedData = await subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      this.secrets.aesKey,
      stringToBuffer(value)
    );

    // Combine IV and ciphertext
    const combinedData = new Uint8Array([...iv, ...new Uint8Array(encryptedData)]);

    // Store in KVS
    this.data.kvs[hashedDomain] = encodeBuffer(combinedData);
  }

  /**
    * Removes the record with name from the password manager
    */
  async remove(name) {
    // Hash the domain name
    const hashedDomain = encodeBuffer(
      await subtle.sign({ name: "HMAC", hash: "SHA-256" }, this.secrets.masterKey, stringToBuffer(name))
    );

    // Check if domain exists
    if (!this.data.kvs[hashedDomain]) {
      return false;
    }

    // Remove from KVS
    delete this.data.kvs[hashedDomain];
    return true;
  }
}

module.exports = { Keychain }
