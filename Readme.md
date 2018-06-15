## Uport android signer

This library is used to create and manage keys for uport account. 
It supports creating keyPairs from seed phrases,
protecting these keys with authenticated encryption (android lock-screen / fingerprint),
signing ETH transactions and signing uPort specific JWTs.

Where available, keys and seeds created by this lib will be protected by 
encryption backed by ARM Trusted Execution Environment (TEE).

Note: The curve used for ETH signing is not backed by the TEE,
therefore private keys exist in memory while in use but are encrypted with TEE keys while on storage.

### Import

in your main `build.gradle`:
```groovy

allprojects {
    repositories {
        ...
        maven { url 'https://jitpack.io' }
    }
}
```

in your app `build.gradle`:
```groovy
dependencies {
    ...
    implementation "com.github.uport-project:uport-android-signer:0.0.1"
}
```

### Usage

#### Key protection

When creating or importing keys/seeds, you must specify the protection `KeyProtection.Level` desired.
When using such a key/seed, the protection level is enforced based on the option used during creation.

Keys and seeds are always protected with hardware backed keys, where available.
This option is for choosing user authentication requirements. 

The options are:
* SIMPLE - usable without user authentication
* PROMPT - when fingerprint sensor is available and configured will prompt for fingerprint whenever used.
            otherwise it will default to normal android lockscreen using pin/pattern/password
* SINGLE_PROMPT - uses android lockscreen to confirm user authentication
            only if the user has not authenticated in the last 30 seconds.
* CLOUD - reserved/unused - defaults to SIMPLE

#### Create a seed:

This creates a seed that is used for future key derivation and signing:
The seed is representable by a bip39 mnemonic phrase.

```kotlin
UportHDSigner().createHDSeed(activity, KeyProtection.Level.SIMPLE, { err, rootAddress, publicKey ->
                //seed has been created and is accessible using rootAddress 
                // * the handle is `rootAddress`
                // * the corresponding publicKey in base64 is `publicKey`
                // * if there was an error, those are blank and the err object is non null
                
                // To use the seed, refer to it using this `rootAddress` 
            })
```

You can also import bip39 mnemonic phrases:

```kotlin
UportHDSigner().importHDSeed(activity, KeyProtection.Level.SIMPLE, phrase, { err, rootAddress, publicKey ->
                //seed has been imported and 
                // * the handle is `rootAddress`
                // * the corresponding publicKey in base64 is `publicKey`
                // * if there was an error, those are blank and the err object is non null 
            })
```

#### Signing

You can use this lib to calculate ETH transaction signatures.
Building and encoding transaction objects into `ByteArray`s is not in the scope of this lib.

You can sign transactions using keys derived from a previously imported seed.
To refer to that seed you must use the `rootAddress` from the seed creation/import callback
Based on the `KeyProtection.Level` used during seed import/creation, a prompt may be shown to the user
on the lock-screen / fingerprint dialog.

```kotlin

val rootAddress = "0x123..." //rootAddress received when creating/importing the seed

//bip32 key derivation
val derivationPath = "m/44'/60'/0'/0/0"

//the transaction payload, base64 encoded
val txPayloadB64 = Base64.encodeToString( transaction.rlpEncode(), Base64.DEFAULT )

//gets shown to the user on fingerprint dialog or on lockscreen, based on `KeyProtection.Level` used
val prompt = "Please sign this transaction"

UportHDSigner().signTransaction(activity, rootAddress, derivationPath, txPayloadB64, prompt, { err, sigData ->
    if (err != null) {
        //handle error
    } else {
        //use sigData r,s,v components
    }
})

```

Note: The requirement to encode the transaction payload as a base64 string is subject to change in future releases

##### uPort specific JWTs

This lib can also produce signatures for uPort specific JWTs:
The method signature is the same but the signing method differs.

Also, do note that in the current version of this API,
 `data` is a Base64 encoded string (not a serialized JSON) - this is subject to change in future releases 

```kotlin

UportHDSigner().signJwtBundle(activity, rootAddress, derivationPath, data, prompt, { err, sigData ->
    if (err != null) {
        //handle error
    } else {
        //use sigData r,s,v components
    }
})

```
