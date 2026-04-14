import Foundation
import Network
import NetworkExtension
import os.log

class SecureExecFilterDataProvider: NEFilterDataProvider {

    private let logger = Logger(subsystem: "co.secureexec.app.network-filter", category: "filter")
    private let socketPath = "/tmp/secureexec-netflow.sock"
    private var outputHandle: FileHandle?
    private let writeLock = NSLock()
    private let sendQueue = DispatchQueue(label: "co.secureexec.app.network-filter.send")

    // MARK: - Filter lifecycle

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        logger.info("starting network filter")
        connectToAgent()

        let filterRule = NEFilterRule(
            networkRule: NENetworkRule(
                remoteNetwork: nil,
                remotePrefix: 0,
                localNetwork: nil,
                localPrefix: 0,
                protocol: .any,
                direction: .any
            ),
            action: .filterData
        )
        let settings = NEFilterSettings(rules: [filterRule], defaultAction: .allow)
        apply(settings) { error in
            if let error = error {
                self.logger.error("failed to apply filter settings: \(error.localizedDescription)")
            } else {
                self.logger.info("filter settings applied")
            }
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        logger.info("stopping network filter, reason=\(String(describing: reason))")
        writeLock.lock()
        outputHandle?.closeFile()
        outputHandle = nil
        writeLock.unlock()
        completionHandler()
    }

    // MARK: - Flow handling

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }

        let pid = pidFromAuditToken(flow.sourceAppAuditToken)

        guard let (srcAddr, srcPort) = extractEndpoint(socketFlow.localFlowEndpoint),
              let (dstAddr, dstPort) = extractEndpoint(socketFlow.remoteFlowEndpoint) else {
            return .allow()
        }

        let proto: String
        switch socketFlow.socketProtocol {
        case 6:  proto = "tcp"
        case 17: proto = "udp"
        default: proto = "\(socketFlow.socketProtocol)"
        }

        let dir: String
        switch socketFlow.direction {
        case .inbound:  dir = "inbound"
        case .outbound: dir = "outbound"
        default:        dir = "outbound"
        }

        sendQueue.async { [weak self] in
            guard let self = self else { return }
            let flowEvent = FlowEvent(
                pid: pid,
                process_name: self.processNameForPid(pid),
                process_start_time: self.processStartTimeForPid(pid),
                src_addr: srcAddr,
                src_port: srcPort,
                dst_addr: dstAddr,
                dst_port: dstPort,
                protocol: proto,
                direction: dir
            )
            self.sendEvent(flowEvent)
        }
        return .allow()
    }

    // MARK: - Endpoint extraction

    private func extractEndpoint(_ endpoint: Network.NWEndpoint?) -> (String, UInt16)? {
        guard let endpoint = endpoint else { return nil }
        switch endpoint {
        case .hostPort(let host, let port):
            let addr: String
            switch host {
            case .ipv4(let v4):
                addr = "\(v4)"
            case .ipv6(let v6):
                addr = "\(v6)"
            case .name(let name, _):
                addr = name
            @unknown default:
                addr = "\(host)"
            }
            return (addr, port.rawValue)
        default:
            return nil
        }
    }

    // MARK: - Process info lookup

    private func processNameForPid(_ pid: Int32) -> String {
        guard pid > 0 else { return "" }
        var buf = [CChar](repeating: 0, count: 1024)
        let ret = proc_pidpath(pid, &buf, UInt32(buf.count))
        guard ret > 0 else { return "" }
        let path = String(cString: buf)
        return (path as NSString).lastPathComponent
    }

    private func processStartTimeForPid(_ pid: Int32) -> Double {
        guard pid > 0 else { return 0 }
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        guard result == 0 else { return 0 }
        let tv = info.kp_proc.p_starttime
        return Double(tv.tv_sec) + Double(tv.tv_usec) / 1_000_000.0
    }

    // MARK: - Unix socket communication

    private func connectToAgent() {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            logger.error("failed to create socket: \(errno)")
            return
        }

        var flags = fcntl(fd, F_GETFL)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        socketPath.withCString { ptr in
            withUnsafeMutablePointer(to: &addr.sun_path) { sunPath in
                let dest = UnsafeMutableRawPointer(sunPath).assumingMemoryBound(to: CChar.self)
                _ = strcpy(dest, ptr)
            }
        }

        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(fd, sa, addrLen)
            }
        }

        if result != 0 && errno != EINPROGRESS {
            close(fd)
            return
        }

        if result != 0 {
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let ready = poll(&pfd, 1, 2000)
            if ready <= 0 || (pfd.revents & Int16(POLLERR | POLLHUP)) != 0 {
                close(fd)
                return
            }
        }

        flags = fcntl(fd, F_GETFL)
        _ = fcntl(fd, F_SETFL, flags & ~O_NONBLOCK)

        outputHandle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        logger.info("connected to agent socket")
    }

    private func sendEvent(_ event: FlowEvent) {
        guard let data = try? JSONEncoder().encode(event),
              var line = String(data: data, encoding: .utf8) else {
            return
        }
        line.append("\n")

        writeLock.lock()
        defer { writeLock.unlock() }

        if outputHandle == nil {
            connectToAgent()
        }

        guard let handle = outputHandle,
              let lineData = line.data(using: .utf8) else { return }

        do {
            try handle.write(contentsOf: lineData)
        } catch {
            logger.error("write failed, reconnecting: \(error.localizedDescription)")
            handle.closeFile()
            outputHandle = nil
        }
    }

    // MARK: - Helpers

    private func pidFromAuditToken(_ token: Data?) -> Int32 {
        guard let token = token, token.count >= 32 else { return 0 }
        return token.withUnsafeBytes { buf in
            buf.load(fromByteOffset: 20, as: Int32.self)
        }
    }
}

// MARK: - libproc import for process name lookup

@_silgen_name("proc_pidpath")
private func proc_pidpath(_ pid: Int32, _ buffer: UnsafeMutablePointer<CChar>, _ buffersize: UInt32) -> Int32

// MARK: - JSON model

struct FlowEvent: Codable {
    let pid: Int32
    let process_name: String
    let process_start_time: Double
    let src_addr: String
    let src_port: UInt16
    let dst_addr: String
    let dst_port: UInt16
    let `protocol`: String
    let direction: String
}

// MARK: - Entry point

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
