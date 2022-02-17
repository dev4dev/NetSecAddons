//
//  ContentView.swift
//  Examples
//
//  Created by Alex Antonyuk on 17.02.2022.
//

import SwiftUI
import Combine

import AuthChallengeHandler
import AuthMTLSHandler
import NetworkService
import TrustKitSSLPinningHandler
import CommonCombine

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
                    brain.pinning()
                } label: {
                    Text("Perform SSL Pinning Request")
                }

                Circle()
                    .fill(brain.state.pinning ? Color.green : Color.red)
                    .frame(width: 20, height: 20)
            }
        }
    }
}

final class Brain: ObservableObject {
    struct State {
        var mtls = false
        var pinning = false
    }

    private var subscriptions: Set<AnyCancellable> = .init()

    let delegate = AuthURLSessionDelegate()
    let networkService: NetworkService

    @Published private(set) var state: State = .init()

    init() {
        networkService = URLNetworkService(configuration: .init(), delegate: delegate)

        setupMTLS()
        setupSSLPinning()
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

    func mtls() {
        networkService.perform(request: .get(url: URL(string: "https://nomnom-dev-api-shield.texasroadhouse.com/brand")!))
            .receiveOnMain()
            .sink { compl in

            } receiveValue: { [unowned self] response in
                print("mTLS:", String(bytes: response.data, encoding: .utf8) as Any)
                self.state.mtls = true
            }
            .store(in: &subscriptions)
    }

    func pinning() {
        networkService.perform(request: .get(url: URL(string: "https://wearehathway.com/")!))
            .receiveOnMain()
            .sink { compl in

            } receiveValue: { [unowned self] response in
                print("Pinning:", String(bytes: response.data, encoding: .utf8) as Any)
                self.state.pinning = true
            }
            .store(in: &subscriptions)
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
