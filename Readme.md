## Uport android signer

This library is used to create and manage keys for uport account. 
It supports creating keyPairs from seed phrases,
protecting these keys with user-presence-auth,
signing ETH transactions and uPort specific JWT signing.

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

```kotlin
UportHDSigner().importHDSeed(activity, KeyProtection.Level.SIMPLE, phrase, { err, rootAddress, publicKey ->
                //seed has been imported and 
                // * the handle is `rootAddress`
                // * the corresponding publicKey in base64 is `publicKey`
                // * if there was an error, those are blank and the err object is non null 
            })
```