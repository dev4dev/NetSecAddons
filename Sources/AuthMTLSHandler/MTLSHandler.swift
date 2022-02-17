//
//  File.swift
//  
//
//  Created by Alex Antonyuk on 16.02.2022.
//

import Foundation
import AuthChallengeHandler

public final class MTLSHandler: AuthChallengeHandler {

    let certData: Data
    let passphrase: String
    let host: String

    /// Default initializer
    /// - Parameters:
    ///   - host: Host to handle
    ///   - certData: Certificate data
    ///   - passphrase: Passphrase
    public init(host: String, certData: Data, passphrase: String) {
        self.certData = certData
        self.passphrase = passphrase
        self.host = host
    }

    /// Convenience initializer, may fail in case of cert file reading error
    /// - Parameters:
    ///   - host: Host to handle
    ///   - certData: Certificate url
    ///   - passphrase: Passphrase
    convenience public init?(host: String, certURL: URL, passphrase: String) {
        guard let data = try? Data(contentsOf: certURL) else { return nil }
        self.init(host: host, certData: data, passphrase: passphrase)
    }

    /// Precheck that the challenge should be handled
    /// - Parameter challenge: Challenge
    /// - Returns: Check resutl
    func check(challenge: URLAuthenticationChallenge) -> Bool {
        challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate &&
        challenge.protectionSpace.host == host
    }

    public func handle(_ session: URLSession, challenge: URLAuthenticationChallenge) -> HandlerResult? {
        guard check(challenge: challenge) else { return nil }
        return (.useCredential, .init(PKCS12: try! .init(PKCS12Data: certData, password: passphrase)))
    }
}
