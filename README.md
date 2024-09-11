🔒 **RFC 8188 Encrypted Content-Encoding for HTTP in TypeScript**

 [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_ts-rfc8188&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_ts-rfc8188)
 [![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_ts-rfc8188&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_ts-rfc8188)
 [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_ts-rfc8188&metric=bugs)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_ts-rfc8188)
 [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_ts-rfc8188&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_ts-rfc8188)
 [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_ts-rfc8188&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_ts-rfc8188)
 ![NPM Downloads](https://img.shields.io/npm/dw/@apeleghq/rfc8188?style=flat-square)


---
### 🚀 Features

- Implements RFC 8188 for encrypted content-encoding in HTTP.
- Supports AES-128-GCM encryption algorithm.
- Additionally, supports AES-256-GCM encryption algorithm _(non-standard)_.
- Provides functions for both encryption and decryption of data.
- Flexible configuration options for encoding parameters.

### 💻 Installation

To install the package, you can use npm or yarn:

```sh
npm install @apeleghq/rfc8188
```

or

```sh
yarn add @apeleghq/rfc8188
```

### 📚 Usage

#### Decrypting Data

```javascript
import { encodings, decrypt } from '@apeleghq/rfc8188';

// Maximum permissible record size when decrypting. Because the decrypted data
// are buffered until a record is full, not limiting it can result in a very
// large memory allocation (4 GiB) depending on the incoming data.
// If this parameter is not provided, no limit is used. Otherwise, incoming data
// claiming to have records larger than this value will be rejected with.
const maxRecordSize = Infinity;

// Provide a function to lookup Initial Keying Material (IKM)
const lookupIKM = async (keyId) => {
  // Your logic to lookup IKM
  return new ArrayBuffer(16);
};

// Your readable stream with ciphertext
const dataStreamToDecrypt = new ReadableStream();

// Decrypt data
const decryptedDataSteam = decrypt(
    encodings.aes128gcm,
    dataStreamToDecrypt,
    lookupIKM,
    maxRecordSize, // optional
);

// Handle decrypted data stream
// ...
```

#### Encrypting Data

```javascript
import { encodings, encrypt } from '@apeleghq/rfc8188';

// Your readable stream with plaintext
const dataStreamToEncrypt = new ReadableStream();
// Some record size. It must be a value between 18 and 2**32 - 1 and is used
// for chunking.
const recordSize = 512;
// A key ID to be included in the payload header.
// It must be between 0 and 255 bytes long and is used to identify the IKM used.
const keyId = new ArrayBuffer(0);
// Initial Keying Material (IKM). Used to derive an encryption key. Note: this
// value is **not** output and it must be treated as a secret.
const IKM = new ArrayBuffer(0);
// Optional. A salt value, which will be combined with the IKM to derive an
// encyption key. If none is provided, a randomly-generated salt value will be
// used. Note that the salt must be exactly 16 bytes long.
const salt = new ArrayBuffer(16);

// Provide plaintext data and encryption parameters
const encryptedDataStream = await encrypt(
    encodings.aes128gcm,
    dataStreamToEncrypt,
    recordSize,
    keyId,
    IKM,
    salt, // optional
);

// Handle encrypted data stream
// ...
```

### 🤝 Contributing

We welcome any contributions and feedback! Please feel free to submit pull
requests, bug reports or feature requests to our GitHub repository.

### 📜 License

This project is released under the ISC license. Check out the `LICENSE` file for
more information.
