import Foundation
import SystemExtensions
import NetworkExtension

let extensionIdentifier = "co.secureexec.app.network-filter"
let callbackQueue = DispatchQueue(label: "co.secureexec.activator.callback")

// MARK: - System Extension request delegate

class ExtensionDelegate: NSObject, OSSystemExtensionRequestDelegate {
    let semaphore = DispatchSemaphore(value: 0)
    var result: Swift.Result<String, Error> = .failure(
        NSError(domain: "secureexec", code: 1, userInfo: [NSLocalizedDescriptionKey: "timeout"])
    )

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            self.result = .success("completed")
        case .willCompleteAfterReboot:
            self.result = .success("will complete after reboot")
        @unknown default:
            self.result = .success("finished with result: \(result)")
        }
        semaphore.signal()
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFailWithError error: Error) {
        self.result = .failure(error)
        semaphore.signal()
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("  → User approval required — check System Settings > Privacy & Security")
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        print("  → Replacing existing extension (v\(existing.bundleShortVersion) → v\(ext.bundleShortVersion))")
        return .replace
    }
}

// MARK: - RunLoop helper

func runLoopWait(_ sem: DispatchSemaphore, timeout: TimeInterval = 30) {
    let deadline = Date(timeIntervalSinceNow: timeout)
    while sem.wait(timeout: .now()) == .timedOut && Date() < deadline {
        RunLoop.current.run(mode: .default, before: Date(timeIntervalSinceNow: 0.1))
    }
}

// MARK: - NEFilterManager helpers

func enableContentFilter() -> Error? {
    let sem = DispatchSemaphore(value: 0)
    var resultError: Error?

    NEFilterManager.shared().loadFromPreferences { error in
        if let error = error {
            resultError = error
            sem.signal()
            return
        }
        let mgr = NEFilterManager.shared()
        if mgr.isEnabled {
            print("  Content filter already enabled")
            sem.signal()
            return
        }
        mgr.localizedDescription = "SecureExec Network Monitor"
        mgr.isEnabled = true

        let filterConfig = NEFilterProviderConfiguration()
        filterConfig.filterSockets = true
        filterConfig.filterPackets = false
        mgr.providerConfiguration = filterConfig

        mgr.saveToPreferences { error in
            resultError = error
            sem.signal()
        }
    }
    runLoopWait(sem)
    return resultError
}

func disableContentFilter() -> Error? {
    let sem = DispatchSemaphore(value: 0)
    var resultError: Error?

    NEFilterManager.shared().loadFromPreferences { error in
        if let error = error {
            resultError = error
            sem.signal()
            return
        }
        let mgr = NEFilterManager.shared()
        mgr.isEnabled = false
        mgr.saveToPreferences { error in
            resultError = error
            sem.signal()
        }
    }
    runLoopWait(sem)
    return resultError
}

// MARK: - Commands

func activate() {
    print("Activating system extension: \(extensionIdentifier)")

    let delegate = ExtensionDelegate()
    let request = OSSystemExtensionRequest.activationRequest(
        forExtensionWithIdentifier: extensionIdentifier,
        queue: callbackQueue
    )
    request.delegate = delegate
    OSSystemExtensionManager.shared.submitRequest(request)

    let timeout = delegate.semaphore.wait(timeout: .now() + 120)
    if timeout == .timedOut {
        print("ERROR: activation timed out after 120s")
        exit(1)
    }

    switch delegate.result {
    case .success(let msg):
        print("  Extension activation: \(msg)")
    case .failure(let error):
        print("ERROR: extension activation failed: \(error.localizedDescription)")
        exit(1)
    }

    print("Enabling content filter ...")
    if let error = enableContentFilter() {
        print("WARNING: failed to enable content filter: \(error.localizedDescription)")
        print("  You may need to enable it manually in System Settings > Network > Filters")
    } else {
        print("  Content filter enabled")
    }

    print("\nDone. Network extension is active.")
}

func deactivate() {
    print("Deactivating system extension: \(extensionIdentifier)")

    print("Disabling content filter ...")
    _ = disableContentFilter()

    let delegate = ExtensionDelegate()
    let request = OSSystemExtensionRequest.deactivationRequest(
        forExtensionWithIdentifier: extensionIdentifier,
        queue: callbackQueue
    )
    request.delegate = delegate
    OSSystemExtensionManager.shared.submitRequest(request)

    let timeout = delegate.semaphore.wait(timeout: .now() + 60)
    if timeout == .timedOut {
        print("ERROR: deactivation timed out after 60s")
        exit(1)
    }

    switch delegate.result {
    case .success(let msg):
        print("  Extension deactivation: \(msg)")
    case .failure(let error):
        print("ERROR: extension deactivation failed: \(error.localizedDescription)")
        exit(1)
    }

    print("\nDone. Network extension is deactivated.")
}

func status() {
    print("Network extension: \(extensionIdentifier)\n")

    let sem = DispatchSemaphore(value: 0)
    NEFilterManager.shared().loadFromPreferences { error in
        if let error = error {
            print("  Filter status: error loading — \(error.localizedDescription)")
        } else {
            let mgr = NEFilterManager.shared()
            let enabled = mgr.isEnabled ? "enabled" : "disabled"
            let desc = mgr.localizedDescription ?? "(none)"
            print("  Filter enabled:     \(enabled)")
            print("  Filter description: \(desc)")
            print("  Provider config:    \(mgr.providerConfiguration != nil ? "present" : "none")")
        }
        sem.signal()
    }
    sem.wait()

    let sockPath = "/tmp/secureexec-netflow.sock"
    let sockExists = FileManager.default.fileExists(atPath: sockPath)
    print("  Agent socket:       \(sockExists ? "listening (\(sockPath))" : "not found")")
}

func usage() {
    let name = CommandLine.arguments.first ?? "secureexec-activator"
    print("""
    Usage: \(name) <command>

    Commands:
      activate     Install & enable the network extension
      deactivate   Disable & remove the network extension
      status       Show current extension and filter status

    Note: activate/deactivate require running as root (sudo).
    """)
}

// MARK: - Main

let args = CommandLine.arguments
guard args.count >= 2 else {
    usage()
    exit(1)
}

switch args[1] {
case "activate":
    activate()
case "deactivate":
    deactivate()
case "status":
    status()
default:
    print("Unknown command: \(args[1])\n")
    usage()
    exit(1)
}
