//
//  File.swift
//  
//
//  Created by Alex Antonyuk on 17.02.2022.
//

import Foundation

public final class SessionDelegate: NSObject, URLSessionDelegate {

    public let pool: AuthChallengeHandlersPool = .init()

    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let handled = pool.urlSession(session, didReceive: challenge, completionHandler: completionHandler)

        if !handled {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
