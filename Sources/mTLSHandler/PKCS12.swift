//
//  PKCS12.swift
//  Texas-mTLS
//
//  Created by Alex Antonyuk on 16.02.2022.
//

import Foundation
import Security

extension String: LocalizedError {
    public var errorDescription: String? { self }
}

/// https://gist.github.com/algal/66703927b8379182640a42294e5f3c0b
public class PKCS12 {
    let label: String?
    let keyID: Data?
    let trust: SecTrust?
    let certChain: [SecTrust]?
    let identity: SecIdentity?

    public init(PKCS12Data: Data, password: String) throws
    {
        let importPasswordOption: NSDictionary = [kSecImportExportPassphrase as NSString: password]
        var items : CFArray?
        let secError: OSStatus = SecPKCS12Import(PKCS12Data as NSData, importPasswordOption, &items)

        guard secError == errSecSuccess else {
            if secError == errSecAuthFailed {
                throw "ERROR: SecPKCS12Import returned errSecAuthFailed. Incorrect password?"
            }
            throw "SecPKCS12Import returned an error trying to import PKCS12 data"
        }

        guard let theItemsCFArray = items else { throw "No data in the certificate" }
        let theItemsNSArray: NSArray = theItemsCFArray as NSArray
        guard let dictArray = theItemsNSArray as? [[String: AnyObject]] else { throw "Bad data format" }

        func f<T>(_ key: CFString) -> T? {
            for d in dictArray {
                if let v = d[key as String] as? T {
                    return v
                }
            }
            return nil
        }

        self.label = f(kSecImportItemLabel)
        self.keyID = f(kSecImportItemKeyID)
        self.trust = f(kSecImportItemTrust)
        self.certChain = f(kSecImportItemCertChain)
        self.identity =  f(kSecImportItemIdentity)
    }
}

extension URLCredential {
    public convenience init?(PKCS12 thePKCS12: PKCS12) {
        if let identity = thePKCS12.identity {
            self.init(
                identity: identity,
                certificates: thePKCS12.certChain,
                persistence: .forSession
            )
        }
        else { return nil }
    }
}
