// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SecureExec",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "SecureExec",
            path: "Sources",
            linkerSettings: [
                .linkedFramework("Cocoa"),
                .linkedFramework("SystemExtensions"),
                .linkedFramework("NetworkExtension"),
                .linkedFramework("Security"),
            ]
        )
    ]
)
