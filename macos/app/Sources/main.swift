import Cocoa
import SystemExtensions
import NetworkExtension
import os

let log = OSLog(subsystem: "co.secureexec.app", category: "app")
let extensionIdentifier = "co.secureexec.app.network-filter"
let installDir = "/opt/secureexec"
let agentBin = "\(installDir)/bin/secureexec-agent-macos"
let agentPlist = "/Library/LaunchDaemons/co.secureexec.agent.plist"
let agentLog = "\(installDir)/var/agent.log"
let sockPath = "/tmp/secureexec-netflow.sock"

// MARK: - App Delegate

class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var refreshTimer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        UserDefaults.standard.register(defaults: ["autoStartEnabled": true])
        os_log(.info, log: log, "SecureExec app launched")
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "shield.checkered",
                                   accessibilityDescription: "SecureExec")
            button.image?.isTemplate = true
        }
        rebuildMenu()
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.rebuildMenu()
        }
        firstLaunchInstallIfNeeded()
    }

    func rebuildMenu() {
        let agentRunning = isAgentRunning()
        let agentLoaded = isAgentLoaded()
        os_log(.info, log: log, "rebuildMenu: agentRunning=%{public}@ agentLoaded=%{public}@",
               agentRunning ? "true" : "false", agentLoaded ? "true" : "false")

        fetchExtensionStatus { [weak self] extActive in
            guard let self = self else { return }
            self.buildMenu(agentRunning: agentRunning, agentLoaded: agentLoaded, extActive: extActive)
        }
    }

    private func buildMenu(agentRunning: Bool, agentLoaded: Bool, extActive: Bool) {
        let menu = NSMenu()

        let statusText = agentRunning ? "Agent: Running" : "Agent: Stopped"
        let statusItem = NSMenuItem(title: statusText, action: nil, keyEquivalent: "")
        statusItem.isEnabled = false
        menu.addItem(statusItem)

        let extText = extActive ? "Network Extension: Active" : "Network Extension: Inactive"
        let extItem = NSMenuItem(title: extText, action: nil, keyEquivalent: "")
        extItem.isEnabled = false
        menu.addItem(extItem)

        menu.addItem(NSMenuItem.separator())

        if agentRunning {
            menu.addItem(NSMenuItem(title: "Stop Agent", action: #selector(stopAgent), keyEquivalent: ""))
        } else {
            menu.addItem(NSMenuItem(title: "Start Agent", action: #selector(startAgent), keyEquivalent: ""))
        }

        menu.addItem(NSMenuItem.separator())

        if agentLoaded {
            menu.addItem(NSMenuItem(title: "Disable Auto-start", action: #selector(disableAutoStart), keyEquivalent: ""))
        } else {
            menu.addItem(NSMenuItem(title: "Enable Auto-start", action: #selector(enableAutoStart), keyEquivalent: ""))
        }

        menu.addItem(NSMenuItem.separator())

        if extActive {
            menu.addItem(NSMenuItem(title: "Deactivate Network Extension", action: #selector(deactivateExtension), keyEquivalent: ""))
        } else {
            menu.addItem(NSMenuItem(title: "Activate Network Extension", action: #selector(activateExtension), keyEquivalent: ""))
        }

        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "View Logs…", action: #selector(viewLogs), keyEquivalent: "l"))
        menu.addItem(NSMenuItem(title: "Quit SecureExec", action: #selector(quitApp), keyEquivalent: "q"))

        for item in menu.items {
            item.target = self
        }

        self.statusItem.menu = menu
    }

    // MARK: - Agent management

    @objc func startAgent() {
        os_log(.info, log: log, "startAgent")
        let autoStart = UserDefaults.standard.bool(forKey: "autoStartEnabled")
        runPrivilegedScript("launchctl enable system/co.secureexec.agent; launchctl bootstrap system '\(agentPlist)' 2>/dev/null || launchctl kickstart -k system/co.secureexec.agent")
        if !autoStart {
            runPrivilegedScript("launchctl disable system/co.secureexec.agent")
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { self.rebuildMenu() }
    }

    @objc func stopAgent() {
        os_log(.info, log: log, "stopAgent")
        let autoStart = UserDefaults.standard.bool(forKey: "autoStartEnabled")
        runPrivilegedScript("launchctl bootout system/co.secureexec.agent 2>/dev/null; true")
        if autoStart {
            runPrivilegedScript("launchctl enable system/co.secureexec.agent")
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { self.rebuildMenu() }
    }

    @objc func enableAutoStart() {
        os_log(.info, log: log, "enableAutoStart")
        runPrivilegedScript("launchctl enable system/co.secureexec.agent; launchctl bootstrap system '\(agentPlist)' 2>/dev/null; true")
        UserDefaults.standard.set(true, forKey: "autoStartEnabled")
        os_log(.info, log: log, "autoStartEnabled set to true")
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { self.rebuildMenu() }
    }

    @objc func disableAutoStart() {
        os_log(.info, log: log, "disableAutoStart")
        runPrivilegedScript("launchctl disable system/co.secureexec.agent")
        UserDefaults.standard.set(false, forKey: "autoStartEnabled")
        os_log(.info, log: log, "autoStartEnabled set to false")
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { self.rebuildMenu() }
    }

    // MARK: - Network extension management

    @objc func activateExtension() {
        let delegate = ExtensionDelegate { [weak self] result in
            DispatchQueue.main.async {
                switch result {
                case .success(let msg):
                    self?.showNotification("Network Extension", body: msg)
                    self?.enableContentFilter()
                case .failure(let err):
                    self?.showAlert("Activation Failed", message: err.localizedDescription)
                }
                self?.rebuildMenu()
            }
        }
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = delegate
        ExtensionDelegate.current = delegate
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    @objc func deactivateExtension() {
        disableContentFilter()

        let delegate = ExtensionDelegate { [weak self] result in
            DispatchQueue.main.async {
                switch result {
                case .success(let msg):
                    self?.showNotification("Network Extension", body: msg)
                case .failure(let err):
                    self?.showAlert("Deactivation Failed", message: err.localizedDescription)
                }
                self?.rebuildMenu()
            }
        }
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = delegate
        ExtensionDelegate.current = delegate
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    // MARK: - Content filter

    func enableContentFilter() {
        NEFilterManager.shared().loadFromPreferences { error in
            guard error == nil else { return }
            let mgr = NEFilterManager.shared()
            guard !mgr.isEnabled else { return }
            mgr.localizedDescription = "SecureExec Network Monitor"
            mgr.isEnabled = true
            let config = NEFilterProviderConfiguration()
            config.filterSockets = true
            config.filterPackets = false
            mgr.providerConfiguration = config
            mgr.saveToPreferences { _ in }
        }
    }

    func disableContentFilter() {
        NEFilterManager.shared().loadFromPreferences { error in
            guard error == nil else { return }
            let mgr = NEFilterManager.shared()
            mgr.isEnabled = false
            mgr.saveToPreferences { _ in }
        }
    }

    // MARK: - View logs

    @objc func viewLogs() {
        let url = URL(fileURLWithPath: agentLog)
        NSWorkspace.shared.open(url)
    }

    @objc func quitApp() {
        NSApplication.shared.terminate(nil)
    }

    // MARK: - First launch install

    func firstLaunchInstallIfNeeded() {
        let installed = FileManager.default.fileExists(atPath: agentBin)
        if !installed {
            installAgent()
        }
    }

    func installAgent() {
        guard let appPath = Bundle.main.bundlePath as String? else { return }
        let srcAgent = "\(appPath)/Contents/MacOS/secureexec-agent-macos"
        guard FileManager.default.fileExists(atPath: srcAgent) else { return }

        let script = """
        mkdir -p \(installDir)/bin && \
        mkdir -p \(installDir)/etc && \
        mkdir -p \(installDir)/var && \
        cp '\(srcAgent)' '\(agentBin)' && \
        chmod 755 '\(agentBin)' && \
        codesign --force --sign - --entitlements /dev/stdin '\(agentBin)' <<'ENTITLEMENTS'
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
        <key>com.apple.developer.endpoint-security.client</key><true/>
        <key>com.apple.developer.system-extension.install</key><true/>
        </dict></plist>
        ENTITLEMENTS
        """
        runPrivilegedScript(script)
        installLaunchdPlist()
    }

    func installLaunchdPlist() {
        let plistContent = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key><string>co.secureexec.agent</string>
            <key>ProgramArguments</key><array><string>\(agentBin)</string></array>
            <key>EnvironmentVariables</key><dict><key>SecureExec_LOG</key><string>info</string></dict>
            <key>WorkingDirectory</key><string>\(installDir)/var</string>
            <key>RunAtLoad</key><true/>
            <key>KeepAlive</key><true/>
            <key>StandardOutPath</key><string>\(installDir)/var/agent.log</string>
            <key>StandardErrorPath</key><string>\(installDir)/var/agent.err</string>
        </dict>
        </plist>
        """
        let tmpPath = NSTemporaryDirectory() + "co.secureexec.agent.plist"
        try? plistContent.write(toFile: tmpPath, atomically: true, encoding: .utf8)
        let script = """
        cp '\(tmpPath)' '\(agentPlist)' && \
        chmod 644 '\(agentPlist)' && \
        chown root:wheel '\(agentPlist)' && \
        launchctl enable system/co.secureexec.agent && \
        launchctl bootstrap system '\(agentPlist)'
        """
        runPrivilegedScript(script)
        UserDefaults.standard.set(true, forKey: "autoStartEnabled")
    }

    // MARK: - Status checks

    func isAgentRunning() -> Bool {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/ps")
        task.arguments = ["ax", "-o", "comm="]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice
        try? task.run()
        task.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        return output.contains("secureexec-agent-macos")
    }

    func isAgentLoaded() -> Bool {
        let plistExists = FileManager.default.fileExists(atPath: agentPlist)
        let pref = UserDefaults.standard.bool(forKey: "autoStartEnabled")
        let result = plistExists && pref
        os_log(.info, log: log, "isAgentLoaded: plistExists=%{public}@ pref=%{public}@ result=%{public}@",
               plistExists ? "true" : "false", pref ? "true" : "false", result ? "true" : "false")
        return result
    }

    func fetchExtensionStatus(completion: @escaping (Bool) -> Void) {
        NEFilterManager.shared().loadFromPreferences { _ in
            let enabled = NEFilterManager.shared().isEnabled
            DispatchQueue.main.async {
                completion(enabled)
            }
        }
    }

    // MARK: - Privileged execution

    func runPrivileged(_ tool: String, args: [String]) {
        var authRef: AuthorizationRef?
        let status = AuthorizationCreate(nil, nil, [], &authRef)
        guard status == errAuthorizationSuccess, let auth = authRef else { return }
        defer { AuthorizationFree(auth, []) }

        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        task.arguments = [tool] + args
        task.standardOutput = FileHandle.nullDevice
        task.standardError = FileHandle.nullDevice
        try? task.run()
        task.waitUntilExit()
    }

    @discardableResult
    func runPrivilegedScript(_ script: String) -> (exit: Int32, output: String) {
        os_log(.info, log: log, "runPrivilegedScript: %{public}@", script)
        let escaped = script
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-e", "do shell script \"\(escaped)\" with administrator privileges"]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        do {
            try task.run()
        } catch {
            os_log(.info, log: log, "failed to launch osascript: %{public}@", error.localizedDescription)
            return (-1, error.localizedDescription)
        }
        task.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        let code = task.terminationStatus
        if code != 0 {
            os_log(.info, log: log, "script exited %d: %{public}@", code, output)
        } else {
            os_log(.info, log: log, "script OK: %{public}@", output.isEmpty ? "(no output)" : output)
        }
        return (code, output)
    }

    // MARK: - UI helpers

    func showAlert(_ title: String, message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = .warning
        alert.runModal()
    }

    func showNotification(_ title: String, body: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = body
        alert.alertStyle = .informational
        alert.runModal()
    }
}

// MARK: - System Extension delegate

class ExtensionDelegate: NSObject, OSSystemExtensionRequestDelegate {
    static var current: ExtensionDelegate?
    let completion: (Result<String, Error>) -> Void

    init(completion: @escaping (Result<String, Error>) -> Void) {
        self.completion = completion
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            completion(.success("Extension activated successfully"))
        case .willCompleteAfterReboot:
            completion(.success("Will complete after reboot"))
        @unknown default:
            completion(.success("Completed"))
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        completion(.failure(error))
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = "Approval Required"
            alert.informativeText = "Please approve the SecureExec network extension in System Settings → Privacy & Security"
            alert.alertStyle = .informational
            alert.runModal()
        }
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }
}

// MARK: - Entry point

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
