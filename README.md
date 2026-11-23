# aes256-offline
An HTML+JS application that encrypts input data with AES-256-CBC algorithm offline without the need of a server-side script


## Update to modern hash (with AI)
Supported Key Derivation & Hashing Modes for GibberishAES.enc() / GibberishAES.dec()

```
GibberishAES.enc(data, pass, [hashType], [iterations])
GibberishAES.dec(data, pass, [hashType], [iterations])
```

| hashType (3rd)  | iterations (4th)        | Equivalent OpenSSL CLI Flags             | OpenSSL Status             |
|-----------------|-------------------------|------------------------------------------|----------------------------|
| 'pbkdf2'        | Optional (default 10000)| -pbkdf2 (or -pbkdf2 -iter N)             | Recommended (No warnings)  |
| 'pbkdf2-sha256' | Optional (default 10000)| -pbkdf2 -md sha256 (or -iter N)          | Recommended (No warnings)  |
| 'pbkdf2-sha1'   | Optional (default 10000)| -pbkdf2 -md sha1 (or -iter N)            | Accepted (No warnings)     |
| 'sha256'        | Ignored                 | -md sha256                               | Deprecated (Shows WARNING) |
| 'sha1'          | Ignored                 | -md sha1                                 | Deprecated (Shows WARNING) |
| 'md5' or ''     | Ignored                 | -md md5                                  | Deprecated (Shows WARNING) |


### Bash / OpenSSL Decryption Examples:

##### Recommended (PBKDF2-SHA256, 10000 iterations):
```bash
echo "<CIPHERTEXT>" | openssl enc -d -aes-256-cbc -pbkdf2 -a -k "<PASSWORD>"
```

##### Custom iterations (e.g., 50000):
```bash
echo "<CIPHERTEXT>" | openssl enc -d -aes-256-cbc -pbkdf2 -md sha256 -iter 50000 -a -k "<PASSWORD>"
```

##### Legacy default (MD5, backward-compatible with v1.0.0):
```bash
echo "<CIPHERTEXT>" | openssl enc -d -aes-256-cbc -md md5 -a -k "<PASSWORD>"
```

> **Note:** Add the '-A' flag to OpenSSL if <CIPHERTEXT> is passed as a single line without line breaks. Default cipher is AES-256-CBC; adjust to -aes-128-cbc or -aes-192-cbc if GibberishAES.size() is changed.

---

## Hashing & HMAC Usage

All functions inside `GibberishAES.Hash` operate on **byte arrays** (`0–255`) rather than plain strings. Use the built-in helper methods `GibberishAES.s2a()` (UTF-8 string to byte array) and `GibberishAES.a2h()` (byte array to hex string) to work with text.

### 1. Calculating MD5, SHA-1, and SHA-256 Hashes

```javascript
const text = "Made with Gibberish";
const bytes = GibberishAES.s2a(text); // Convert UTF-8 string to byte array

// MD5
const md5Bytes = GibberishAES.Hash.MD5(bytes);
const md5Hex = GibberishAES.a2h(md5Bytes);
console.log("MD5:    ", md5Hex);

// SHA-1
const sha1Bytes = GibberishAES.Hash.SHA1(bytes);
const sha1Hex = GibberishAES.a2h(sha1Bytes);
console.log("SHA-1:  ", sha1Hex);

// SHA-256
const sha256Bytes = GibberishAES.Hash.SHA256(bytes);
const sha256Hex = GibberishAES.a2h(sha256Bytes);
console.log("SHA-256:", sha256Hex);
```

### 2. Calculating HMAC Signatures

`GibberishAES.Hash.HMAC(hashFn, keyBytes, messageBytes)` accepts three arguments:
1. **`hashFn`** – Reference to the hash function (`GibberishAES.Hash.SHA256`, `SHA1`, or `MD5`).
2. **`keyBytes`** – Secret key as a byte array.
3. **`messageBytes`** – Message payload as a byte array.

```javascript
const key = GibberishAES.s2a("secret_key");
const message = GibberishAES.s2a("Made with Gibberish");

// HMAC-SHA256
const hmacSha256Bytes = GibberishAES.Hash.HMAC(GibberishAES.Hash.SHA256, key, message);
console.log("HMAC-SHA256:", GibberishAES.a2h(hmacSha256Bytes));

// HMAC-SHA1
const hmacSha1Bytes = GibberishAES.Hash.HMAC(GibberishAES.Hash.SHA1, key, message);
console.log("HMAC-SHA1:  ", GibberishAES.a2h(hmacSha1Bytes));
```

### 3. Quick Verification in Terminal (Bash)

You can verify the JavaScript output against standard Linux CLI tools:

```bash
# SHA-256
printf "Made with Gibberish" | sha256sum

# HMAC-SHA256
printf "Made with Gibberish" | openssl dgst -sha256 -hmac "secret_key"
```

> **Note:** Use `printf` instead of `echo` to avoid appending a trailing newline (`\n`), which would alter the resulting checksum.

> **Security Note (`secret_key` vs. `password`):**
> Do **not** pass a human-chosen password directly as `secret_key` into `HMAC`. HMAC is designed to be fast and expects a high-entropy cryptographic key (such as a randomly generated API token). If you need to authenticate data using a user-supplied password, derive a strong key first using `GibberishAES.PBKDF2` before passing it to `HMAC`:
>
> ```javascript
> const password = GibberishAES.s2a("user_password");
> const salt = GibberishAES.s2a("unique_salt"); // Should be randomly generated in production
> const message = GibberishAES.s2a("Made with Gibberish");
>
> // 1. Derive a 32-byte cryptographic key from the password (10,000 iterations)
> const derivedKey = GibberishAES.PBKDF2(password, salt, 10000, 32, GibberishAES.Hash.SHA256);
>
> // 2. Sign the message using the derived key
> const signature = GibberishAES.Hash.HMAC(GibberishAES.Hash.SHA256, derivedKey, message);
> console.log("PBKDF2 + HMAC-SHA256:", GibberishAES.a2h(signature));
> ```

