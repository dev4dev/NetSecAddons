//
//  File.swift
//  
//
//  Created by Alex Antonyuk on 17.02.2022.
//

import Foundation
import CommonCrypto

import AuthChallengeHandler

public final class SimpleSSLPinningHandler: AuthChallengeHandler {
    public struct Config {
        let hosts: [String]
        let hashes: [String]

        public init(hosts: [String], hashes: [String]) {
            self.hosts = hosts
            self.hashes = hashes
        }
    }

    let hashKeysMap: [String: [String]]
    public init(configs: [Config]) {
        hashKeysMap = configs.reduce(into: [String: [String]](), { result, config in
            config.hosts.forEach { host in
                result[host] = config.hashes
            }
        })
    }

    // Precheck that the challenge should be handled
    /// - Parameter challenge: Challenge
    /// - Returns: Check result
    func check(challenge: URLAuthenticationChallenge) -> Bool {
        challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust
    }

    public func handle(_ session: URLSession, challenge: URLAuthenticationChallenge) -> HandlerResult? {
        guard check(challenge: challenge) else { return nil }

        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            return nil
        }

        let policies = NSMutableArray()
        let host = challenge.protectionSpace.host
        guard let pinnedPublicKeyHash = hashKeysMap[host] else { return nil }

        policies.add(SecPolicyCreateSSL(true, host as CFString))
        SecTrustSetPolicies(serverTrust, policies)

        let result = SecTrustEvaluateWithError(serverTrust, nil)

        guard result, let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            return (.cancelAuthenticationChallenge, nil)
        }

        guard let serverPublicKey = SecCertificateCopyKey(serverCertificate),
              let serverPublicKeyData: NSData = SecKeyCopyExternalRepresentation(serverPublicKey, nil ) else {
                  return nil
              }
        let keyHash = sha256(data: serverPublicKeyData as Data)
        if pinnedPublicKeyHash.contains(keyHash) {
            // Success! This is our server
            return (.useCredential, URLCredential(trust: serverTrust))
        } else {
            return (.cancelAuthenticationChallenge, nil)
        }
    }

    // MARK: -
    let rsa2048Asn1Header: [UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]

    func sha256(data: Data) -> String {
        var keyWithHeader = Data(rsa2048Asn1Header)
        keyWithHeader.append(data)
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        keyWithHeader.withUnsafeBytes { (data: UnsafeRawBufferPointer) in
            _ = CC_SHA256(data.baseAddress, CC_LONG(keyWithHeader.count), &hash)
        }

        return Data(hash).base64EncodedString()
    }
}
