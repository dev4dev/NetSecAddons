//
//  ContentView.swift
//  Examples
//
//  Created by Alex Antonyuk on 17.02.2022.
//

import SwiftUI
import Combine
import CommonCombine

import AuthChallengeHandler
import AuthMTLSHandler
import NetworkService
import TrustKitSSLPinningHandler
import SimpleSSLPinningHandler

struct ContentView: View {
    @StateObject var brain = Brain()

    var body: some View {
        VStack(spacing: 50.0) {
            HStack {
                Button {
                    brain.mtls()
                } label: {
                    Text("Perform mTLS Request")
                }

                Circle()
                    .fill(brain.state.mtls ? Color.green : Color.red)
                    .frame(width: 20, height: 20)
            }

            HStack {
                Button {
                    brain.tkPinning()
                } label: {
                    Text("Perform TrustKit SSL Pinning Request")
                }

                Circle()
                    .fill(brain.state.tkPinning ? Color.green : Color.red)
                    .frame(width: 20, height: 20)
            }

            HStack {
                Button {
                    brain.simplPinning()
                } label: {
                    Text("Perform Simple SSL Pinning Request")
                }

                Circle()
                    .fill(brain.state.simplePinning ? Color.green : Color.red)
                    .frame(width: 20, height: 20)
            }
        }
    }
}

final class Brain: ObservableObject {
    struct State {
        var mtls = false
        var tkPinning = false
        var simplePinning = false
    }

    private var subscriptions: Set<AnyCancellable> = .init()

    let delegate = AuthURLSessionDelegate()
    let networkService: NetworkService

    @Published private(set) var state: State = .init()

    init() {
        networkService = URLNetworkService(configuration: .init(), delegate: delegate)

        setupMTLS()
        setupSSLPinning()
        setupSimpleSSLPinning()
    }

    private func setupMTLS() {
        let certData = try! Data(contentsOf: Bundle.main.url(forResource: "cert", withExtension: "pfx")!)
        delegate.handlersPool.add(handler: MTLSHandler(hosts: ["nomnom-dev-api-shield.texasroadhouse.com"], certData: certData, passphrase: "123qweasdzxc"))
    }

    private func setupSSLPinning() {
        delegate.handlersPool.add(handler: TrustKitSSLPinningHandler(configs: [
            .init(
                host: "wearehathway.com",
                includeSubdomains: true,
                hashes: [
                    "z2bgu6Rryx0PF1Fjk9M9QeAz1WetvekOjTx0bgyv06U=",
                    "jQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0="
                ])
        ]))
    }

    private func setupSimpleSSLPinning() {
        delegate.handlersPool.add(handler: SimpleSSLPinningHandler(configs: [
            .init(
                hosts: [
                    "www.bounteous.com",
                    "bounteous.com"
                ],
                hashes: [
                    "P4XmHAiNi9ApJchIW+skNp42+HJzOmpjEjwEBbYqroE="
//                    "z2bgu6Rryx0PF1Fjk9M9QeAz1WetvekOjTx0bgyv06U=" // test error
                ])
        ]))
    }

    func mtls() {
        networkService.perform(request: .get(url: URL(string: "https://nomnom-dev-api-shield.texasroadhouse.com/brand")!))
            .receiveOnMain()
            .sink { compl in
                if case .failure = compl {
                    print("ERROR: MTLS")
                }
            } receiveValue: { [unowned self] response in
                print("mTLS:", String(bytes: response.data, encoding: .utf8) as Any)
                self.state.mtls = true
            }
            .store(in: &subscriptions)
    }

    func tkPinning() {
        networkService.perform(request: .get(url: URL(string: "https://wearehathway.com/")!))
            .receiveOnMain()
            .sink { compl in
                if case .failure = compl {
                    print("ERROR: TK Pinning")
                }
            } receiveValue: { [unowned self] response in
                print("TK Pinning:", String(bytes: response.data, encoding: .utf8) as Any)
                self.state.tkPinning = true
            }
            .store(in: &subscriptions)
    }

    func simplPinning() {
        networkService.perform(request: .get(url: URL(string: "https://bounteous.com/")!))
            .receiveOnMain()
            .sink { compl in
                if case .failure = compl {
                    print("ERROR: Simple Pinning")
                }
            } receiveValue: { [unowned self] response in
                print("Simple Pinning:", String(bytes: response.data, encoding: .utf8) as Any)
                self.state.simplePinning = true
            }
            .store(in: &subscriptions)
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
