//
//  File.swift
//  
//
//  Created by Alex Antonyuk on 17.02.2022.
//

import Foundation
import AuthChallengeHandler
import TrustKit

public final class TrustKitSSLPinningHandler: AuthChallengeHandler {
    public struct Config {
        let host: String
        let includeSubdomains: Bool
        let hashes: [String]
        let expiration: String?
        let forced: Bool

        /// Initializer
        /// - Parameters:
        ///   - host: Host "domain.com"
        ///   - includeSubdomains: Whether to include subdomains or not
        ///   - hashes: Array of hashes
        ///   - expiration: Expiration in format "yyyy-MM-dd" if needed
        ///   - forced: Block request if validation fails
        public init(host: String, includeSubdomains: Bool, hashes: [String], expiration: String? = nil, forced: Bool = true) {
            self.host = host
            self.includeSubdomains = includeSubdomains
            self.hashes = hashes
            self.expiration = expiration
            self.forced = forced
        }
    }

    private let tk: TrustKit
    private var hosts: [String] = []

    public init(configs: [Config]) {
        var domains: [String: Any] = [:]
        var hosts: [String] = []

        // https://datatheorem.github.io/TrustKit/documentation/Classes/TrustKit.html
        configs.forEach { config in
            var domain: [String: Any] = [
                kTSKEnforcePinning: config.forced,
                kTSKIncludeSubdomains: config.includeSubdomains,
                kTSKDisableDefaultReportUri: true,
                kTSKPublicKeyHashes: config.hashes
                ]

            if let exp = config.expiration {
                domain[kTSKExpirationDate] = exp
            }

            domains[config.host] = domain
            hosts.append(config.host)
        }

        let trustKitConfig: [String: Any] = [
            kTSKSwizzleNetworkDelegates: false,
            kTSKPinnedDomains: domains
        ]

        tk = TrustKit.init(configuration: trustKitConfig)
        self.hosts = hosts
    }

    /// Precheck that the challenge should be handled
    /// - Parameter challenge: Challenge
    /// - Returns: Check result
    func check(challenge: URLAuthenticationChallenge) -> Bool {
        challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust &&
        hosts.contains(challenge.protectionSpace.host)
    }

    public func handle(_ session: URLSession, challenge: URLAuthenticationChallenge) -> HandlerResult? {
        guard check(challenge: challenge) else { return nil }
        
        var result: HandlerResult? = nil
        let handled = tk.pinningValidator.handle(challenge) { disp, creds in
            result = (disp, creds)
        }
        return handled ? result : nil
    }
}
