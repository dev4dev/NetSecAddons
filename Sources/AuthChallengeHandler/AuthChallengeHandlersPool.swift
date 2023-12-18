//
//  AuthChallengeHandlersPool.swift
//  
//
//  Created by Alex Antonyuk on 16.02.2022.
//

import Foundation

public final class AuthChallengeHandlersPool {

    private var handlers: [AuthChallengeHandler] = []

    private let defaultDisposition: URLSession.AuthChallengeDisposition?
    /// Initializer of handlers pool
    /// - Parameter defaultDisposition: A default disposition that will be used in case none of handlers handles a challenge
    public init(defaultDisposition: URLSession.AuthChallengeDisposition? = nil) {
        self.defaultDisposition = defaultDisposition
    }

    /// Add a handler to the pool
    /// - Parameter handler: Handler
    public func add(handler: AuthChallengeHandler) {
        handlers.append(handler)
    }

    /// Call this method to try handle challenge
    /// - Parameters:
    ///   - session: URLSession
    ///   - challenge: Challenge
    ///   - completionHandler: CompetionHandler
    /// - Returns: Handling success status
    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) -> Bool {
        for handler in handlers {
            if let result = handler.handle(session, challenge: challenge) {
                completionHandler(result.0, result.1)
                return true
            }
        }

        if let defaultDisposition = defaultDisposition {
            completionHandler(defaultDisposition, nil)
            return true
        }

        return false
    }
}
