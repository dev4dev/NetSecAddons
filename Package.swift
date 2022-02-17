// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "NetSecAddons",
    platforms: [.iOS(.v14)],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "AuthChallengeHandler",
            targets: ["AuthChallengeHandler"]),
        .library(
            name: "AuthMTLSHandler",
            targets: ["AuthMTLSHandler"]
        ),
        .library(
            name: "TrustKitSSLPinningHandler",
            targets: ["TrustKitSSLPinningHandler"]
        )
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(name: "TrustKit", url: "git@github.com:datatheorem/TrustKit.git", .upToNextMajor(from: "2.0.0"))
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "AuthChallengeHandler",
            dependencies: []),
        .target(
            name: "AuthMTLSHandler",
            dependencies: [
                "AuthChallengeHandler"
            ]
        ),
        .target(
            name: "TrustKitSSLPinningHandler",
            dependencies: [
                "AuthChallengeHandler",
                "TrustKit"
            ]
        )
//        .testTarget(
//            name: "NetworkingAddonsiOSTests",
//            dependencies: ["AuthChallengeHandler"]),
    ]
)
