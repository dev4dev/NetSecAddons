# NetSecAddons

## AuthChallengeHandler

Allows to handle challenges with custom handlers. It is possible to add multiple handlers in case we need to handle different authentication methods or hosts in firrefetn ways

To use it you need to create an instance of `AuthChallengeHandlersPool` class, and then add handlers into it using `add(handler:)` method. The last step is to use it inside of `URLSessionDelegate.urlSession(_:,didReceive:,completionHandler:)` methods this way

```swift
public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    let handled = handlersPool.urlSession(session, didReceive: challenge, completionHandler: completionHandler)

    if !handled {
        completionHandler(.performDefaultHandling, nil)
    }
}

```

There is a predefined class `AuthURLSessionDelegate` that conforms to `URLSessionDelegate` protocol. You can use it in case you don't have any additional handlings inside of your app. 

## Handlers

Here is a list of currently implemented handlers:

### AuthMTLSHandler

It allows to pass client cert validation. To use it you need to provide a host name that should be handled, a `Data` of the `p12/pfx` certificate and cert's password/passphrase.

```swift
let data = try! Data(contentsOf: Bundle.main.url(forResource: "cert", withExtension: "pfx")!)
let handler = MTLSHandler(hosts: ["some-host.com"], certData: data, passphrase: "123qweasdzxc")
```

This can be used for `CloudFlare Shield` thing. As a developer you will be provided with two files, key and cert. To craft them into a `pfx` file you need to execute the following command in terminal

```bash
openssl pkcs12 -export -out cert.pfx -inkey <dev.key> -in <dev.crt>
```

`<dev.key>` and `<dev.cert>` are your filenames. After that you will be asked for a password/passphrase for your certificate, you will use it for `MTLSHandler` object initialization.

Live example:  
[![asciicast](https://asciinema.org/a/Ch0y2f4SbL2a8xLbfGRMZ4Mfq.svg)](https://asciinema.org/a/Ch0y2f4SbL2a8xLbfGRMZ4Mfq)


### TrustKitSSLPinningHandler

SSL Pinning using [TrustKit](https://github.com/datatheorem/TrustKit) library


### SimpleSSLPinningHandler

Simple SSL Pinning


## Notes

### How to get a public hash for SSL Pinning

```bash
openssl s_client -servername <address> -connect <address>:443 | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```
