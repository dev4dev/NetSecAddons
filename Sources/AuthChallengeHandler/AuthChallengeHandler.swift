//
//  File.swift
//  
//
//  Created by Alex Antonyuk on 17.02.2022.
//

import Foundation

public protocol AuthChallengeHandler {
    typealias HandlerResult = (URLSession.AuthChallengeDisposition, URLCredential?)
    /// Try to handle the challenge
    /// - Returns: Handling result
    func handle(_ session: URLSession, challenge: URLAuthenticationChallenge) -> HandlerResult?
}
