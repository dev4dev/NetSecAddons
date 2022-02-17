//
//  File.swift
//  
//
//  Created by Alex Antonyuk on 17.02.2022.
//

import Foundation

/// Simple implementation of URLSessionDelegate that needs to handle authentication challenges
public final class AuthURLSessionDelegate: NSObject, URLSessionDelegate {

    public let handlersPool: AuthChallengeHandlersPool = .init()

    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let handled = handlersPool.urlSession(session, didReceive: challenge, completionHandler: completionHandler)

        if !handled {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
