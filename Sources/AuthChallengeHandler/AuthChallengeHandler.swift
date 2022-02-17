//
//  File.swift
//  
//
//  Created by Alex Antonyuk on 16.02.2022.
//

import Foundation

public protocol AuthChallengeHandler {
    typealias HandlerResult = (URLSession.AuthChallengeDisposition, URLCredential?)
    /// Try to handle the challenge
    /// - Returns: Success flag
    func handle(_ session: URLSession, challenge: URLAuthenticationChallenge) -> HandlerResult?
}


public final class AuthChallengeHandlersPool {

    private var handlers: [AuthChallengeHandler] = []

    private let defaultDisposition: URLSession.AuthChallengeDisposition?
    /// Initializer of handlers pool
    /// - Parameter defaultDisposition: A default disposition that will be used in case none of handlers handles a challenge
    public init(defaultDisposition: URLSession.AuthChallengeDisposition? = nil) {
        self.defaultDisposition = defaultDisposition
    }

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
        var handled = false

        for handler in handlers {
            if let result = handler.handle(session, challenge: challenge) {
                handled = true
                completionHandler(result.0, result.1)
                break
            }
        }

        if !handled, let defaultDisposition = defaultDisposition {
            completionHandler(defaultDisposition, nil)
        }

        return handled
    }
}
