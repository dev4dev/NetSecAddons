//
//  File.swift
//  
//
//  Created by Alex Antonyuk on 16.02.2022.
//

import Foundation
import AuthChallengeHandler

final class MTLSHandler: AuthChallengeHandler {

    let certData: Data
    let passphrase: String
    let host: String

    public init(host: String, certData: Data, passphrase: String) {
        self.certData = certData
        self.passphrase = passphrase
        self.host = host
    }

    func check(challenge: URLAuthenticationChallenge) -> Bool {
        challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate &&
        challenge.protectionSpace.host == host
    }

    func handle(_ session: URLSession, challenge: URLAuthenticationChallenge) -> HandlerResult? {
        guard check(challenge: challenge) else { return nil }
        return (.useCredential, .init(PKCS12: try! .init(PKCS12Data: certData, password: passphrase)))
    }
}
