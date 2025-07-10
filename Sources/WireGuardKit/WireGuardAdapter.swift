// SPDX-License-Identifier: MIT
// Copyright © 2018-2021 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension

#if SWIFT_PACKAGE
import WireGuardKitGo
import WireGuardKitC
#endif

public enum WireGuardAdapterError: Error {
    /// Failure to locate tunnel file descriptor.
    case cannotLocateTunnelFileDescriptor

    /// Failure to perform an operation in such state.
    case invalidState

    /// Failure to resolve endpoints.
    case dnsResolution([DNSResolutionError])

    /// Failure to set network settings.
    case setNetworkSettings(Error)

    /// Failure to start WireGuard backend.
    case startWireGuardBackend(Int32)
}

public enum WireGuardGoState: Int32, CustomStringConvertible {
    case disabled = 0
    case connecting
    case connected
    case error
    case waitingForNetwork

    public var description: String {
        switch self {
            case .disabled:
                return "Disabled"
            case .connecting:
                return "Connecting"
            case .connected:
                return "Connected"
            case .error:
                return "Error"
            case .waitingForNetwork:
                return "Waiting For Network"
        }
    }
}

/// Enum representing internal state of the `WireGuardAdapter`
private enum State {
    /// The tunnel is stopped
    case stopped

    /// The tunnel is up and running
    case started(_ handle: Int32, _ settingsGenerator: PacketTunnelSettingsGenerator)

    /// The tunnel is temporarily shutdown due to device going offline
    case temporaryShutdown(_ handle: Int32, _ settingsGenerator: PacketTunnelSettingsGenerator)

    var handle: Int32? {
        switch self {
            case .stopped:
                return nil
            case let .temporaryShutdown(handle, _), let .started(handle, _):
                return handle
        }
    }

    var settingsGenerator: PacketTunnelSettingsGenerator? { 
        switch self {
            case .stopped:
                return nil
            case let .temporaryShutdown(_, settingsGenerator), let .started(_, settingsGenerator):
                return settingsGenerator
        }
    }
}

public class WireGuardAdapter: NSObject {
    public static let wireguardStateDidChangeNotification = NSNotification.Name("WireGuardStateDidChange")

    public typealias LogHandler = (WireGuardLogLevel, String) -> Void

    /// Packet tunnel provider.
    @objc private weak var packetTunnelProvider: NEPacketTunnelProvider?

    /// Used for observing changes in the network path.
    private var pathUpdateObservation: NSKeyValueObservation!

    /// Log handler closure.
    private let logHandler: LogHandler

    /// Private queue used to synchronize access to `WireGuardAdapter` members.
    private let workQueue = DispatchQueue(label: "WireGuardAdapterWorkQueue")

    /// Private queue used for observing state changes by the backend.
    private let stateChangeQueue = DispatchQueue(label: "WireGuardAdapterStateChangeQueue")

    /// Adapter state.
    private var state: State = .stopped

    /// WireGuardKitGo state.
    private var tunnelState: WireGuardGoState = .disabled {
        didSet {
            NotificationCenter.default.post(name: Self.wireguardStateDidChangeNotification, object: tunnelState)
        }
    }

    private var socketType: String = "udp" {
        didSet {
            self.logHandler(.verbose, "New socketType value: \(socketType)")
        }
    }

    /// Tunnel device file descriptor.
    private var tunnelFileDescriptor: Int32? {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var ret: Int32 = -1
            var len = socklen_t(MemoryLayout.size(ofValue: addr))
            withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    ret = getpeername(fd, $0, &len)
                }
            }
            if ret != 0 || addr.sc_family != AF_SYSTEM {
                continue
            }
            if ctlInfo.ctl_id == 0 {
                ret = ioctl(fd, CTLIOCGINFO, &ctlInfo)
                if ret != 0 {
                    continue
                }
            }
            if addr.sc_id == ctlInfo.ctl_id {
                return fd
            }
        }
        return nil
    }

    /// Returns a WireGuard version.
    class var backendVersion: String {
        guard let ver = wgVersion() else { return "unknown" }
        let str = String(cString: ver)
        free(UnsafeMutableRawPointer(mutating: ver))
        return str
    }

    /// Returns the tunnel device interface name, or nil on error.
    /// - Returns: String.
    public var interfaceName: String? {
        guard let tunnelFileDescriptor = self.tunnelFileDescriptor else { return nil }

        var buffer = [UInt8](repeating: 0, count: Int(IFNAMSIZ))

        return buffer.withUnsafeMutableBufferPointer { mutableBufferPointer in
            guard let baseAddress = mutableBufferPointer.baseAddress else { return nil }

            var ifnameSize = socklen_t(IFNAMSIZ)
            let result = getsockopt(
                tunnelFileDescriptor,
                2 /* SYSPROTO_CONTROL */,
                2 /* UTUN_OPT_IFNAME */,
                baseAddress,
                &ifnameSize)

            if result == 0 {
                return String(cString: baseAddress)
            } else {
                return nil
            }
        }
    }

    // MARK: - Initialization

    /// Designated initializer.
    /// - Parameter packetTunnelProvider: an instance of `NEPacketTunnelProvider`. Internally stored
    ///   as a weak reference.
    /// - Parameter logHandler: a log handler closure.
    public init(with packetTunnelProvider: NEPacketTunnelProvider, logHandler: @escaping LogHandler) {
        self.packetTunnelProvider = packetTunnelProvider
        self.logHandler = logHandler

        super.init()
        setupLogHandler()
    }

    deinit {
        // Force remove logger to make sure that no further calls to the instance of this class
        // can happen after deallocation.
        wgSetLogger(nil, nil)

        // Shutdown the tunnel
        if case .started(let handle, _) = self.state {
            wgTurnOff(handle)
        }
    }

    // MARK: - Public methods

    /// Returns a runtime configuration from WireGuard.
    /// - Parameter completionHandler: completion handler.
    public func getRuntimeConfiguration(completionHandler: @escaping (String?) -> Void) {
        workQueue.async {
            guard case .started(let handle, _) = self.state else {
                completionHandler(nil)
                return
            }

            if let settings = wgGetConfig(handle) {
                completionHandler(String(cString: settings))
                free(settings)
            } else {
                completionHandler(nil)
            }
        }
    }

    public func observeStateChanges() {
        stateChangeQueue.async { [weak self] in
            guard let `self` = self else { return }

            var previousState: WireGuardGoState? = nil
            while let handle = self.state.handle,
                // `wgGetState(_:)` is a blocking call, and will only unblock when the state changes.
                let goState = WireGuardGoState(rawValue: wgGetState(handle)) {

                guard previousState != goState else {
                    return
                }

                self.logHandler(.verbose, "WireGuardKitGo state change \(previousState?.description ?? "(nil)") --> \(goState.description)")

                previousState = goState
                workQueue.async {
                    self.tunnelState = goState
                }
            }
            self.logHandler(.verbose, "Exiting state change observation loop.")
        }
    }

    /// Start the tunnel tunnel.
    /// - Parameters:
    ///   - tunnelConfiguration: tunnel configuration.
    ///   - completionHandler: completion handler.
    public func start(tunnelConfiguration: TunnelConfiguration, socketType: String, completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            guard case .stopped = self.state else {
                completionHandler(.invalidState)
                return
            }

            self.socketType = socketType
            self.pathUpdateObservation = self.observe(\.packetTunnelProvider?.defaultPath, options: [.old, .new]) { [weak self] _, change in
                guard let new = change.newValue,
                      new == nil ||
                      change.oldValue == nil ||
                      change.oldValue! == nil ||
                      !new!.isEqual(to: change.oldValue!!) else {
                    return
                }
                self?.didReceivePathUpdate(path: new)
            }

            do {
                let settingsGenerator = try self.makeSettingsGenerator(with: tunnelConfiguration)
                try self.setNetworkSettings(settingsGenerator.generateNetworkSettings())

                let (wgConfig, resolutionResults) = settingsGenerator.uapiConfiguration()
                self.logEndpointResolutionResults(resolutionResults)

                self.state = .started(
                    try self.startWireGuardBackend(wgConfig: wgConfig),
                    settingsGenerator
                )

                self.observeStateChanges()
                completionHandler(nil)
            } catch let error as WireGuardAdapterError {
                self.pathUpdateObservation?.invalidate()
                completionHandler(error)
            } catch {
                fatalError()
            }
        }
    }

    /// Stop the tunnel.
    /// - Parameter completionHandler: completion handler.
    public func stop(completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            switch self.state {
            case .started(let handle, _):
                wgTurnOff(handle)

            case .temporaryShutdown:
                break

            case .stopped:
                completionHandler(.invalidState)
                return
            }

            self.pathUpdateObservation?.invalidate()
            self.pathUpdateObservation = nil

            self.state = .stopped

            completionHandler(nil)
        }
    }

    /// Update runtime configuration.
    /// - Parameters:
    ///   - tunnelConfiguration: tunnel configuration.
    ///   - completionHandler: completion handler.
    public func update(tunnelConfiguration: TunnelConfiguration, completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            if case .stopped = self.state {
                completionHandler(.invalidState)
                return
            }

            // Tell the system that the tunnel is going to reconnect using new WireGuard
            // configuration.
            // This will broadcast the `NEVPNStatusDidChange` notification to the GUI process.
            self.packetTunnelProvider?.reasserting = true
            defer {
                self.packetTunnelProvider?.reasserting = false
            }

            do {
                let settingsGenerator = try self.makeSettingsGenerator(with: tunnelConfiguration)
                try self.setNetworkSettings(settingsGenerator.generateNetworkSettings())

                switch self.state {
                case .started(let handle, _):
                    let (wgConfig, resolutionResults) = settingsGenerator.uapiConfiguration()
                    self.logEndpointResolutionResults(resolutionResults)

                    wgSetConfig(handle, wgConfig)
                    #if os(iOS)
                    wgDisableSomeRoamingForBrokenMobileSemantics(handle)
                    #endif

                    self.state = .started(handle, settingsGenerator)

                case .temporaryShutdown(let handle, _):
                    self.state = .temporaryShutdown(handle, settingsGenerator)

                case .stopped:
                    fatalError()
                }

                completionHandler(nil)
            } catch let error as WireGuardAdapterError {
                completionHandler(error)
            } catch {
                fatalError()
            }
        }
    }

    // MARK: - Private methods

    /// Setup WireGuard log handler.
    private func setupLogHandler() {
        let context = Unmanaged.passUnretained(self).toOpaque()
        wgSetLogger(context) { context, logLevel, message in
            guard let context = context, let message = message else { return }

            let unretainedSelf = Unmanaged<WireGuardAdapter>.fromOpaque(context)
                .takeUnretainedValue()

            let swiftString = String(cString: message).trimmingCharacters(in: .newlines)
            let tunnelLogLevel = WireGuardLogLevel(rawValue: logLevel) ?? .verbose

            unretainedSelf.logHandler(tunnelLogLevel, swiftString)
        }
    }

    /// Set network tunnel configuration.
    /// This method ensures that the call to `setTunnelNetworkSettings` does not time out, as in
    /// certain scenarios the completion handler given to it may not be invoked by the system.
    ///
    /// - Parameters:
    ///   - networkSettings: an instance of type `NEPacketTunnelNetworkSettings`.
    /// - Throws: an error of type `WireGuardAdapterError`.
    /// - Returns: `PacketTunnelSettingsGenerator`.
    private func setNetworkSettings(_ networkSettings: NEPacketTunnelNetworkSettings) throws {
        var systemError: Error?
        let group = DispatchGroup()

        group.enter()
        self.packetTunnelProvider?.setTunnelNetworkSettings(networkSettings) { error in
            systemError = error
            group.leave()
        }

        // Packet tunnel's `setTunnelNetworkSettings` times out in certain
        // scenarios & never calls the given callback.
        var loopOnce = 0
        let settingsTimeout = 5
        while loopOnce < 2 {
            if let systemError = systemError {
                throw WireGuardAdapterError.setNetworkSettings(systemError)
            }

            loopOnce += 1
            if group.wait(timeout: DispatchTime.now() + DispatchTimeInterval.seconds(settingsTimeout)) == .timedOut {
                self.logHandler(.error, "\(#function) timed out after \(settingsTimeout) seconds, proceeding anyway.")
            }
        }
    }

    /// Resolve peers of the given tunnel configuration.
    /// - Parameter tunnelConfiguration: tunnel configuration.
    /// - Throws: an error of type `WireGuardAdapterError`.
    /// - Returns: The list of resolved endpoints.
    private func resolvePeers(for tunnelConfiguration: TunnelConfiguration) throws -> [Endpoint?] {
        let endpoints = tunnelConfiguration.peers.map { $0.endpoint }
        let resolutionResults = DNSResolver.resolveSync(endpoints: endpoints)
        let resolutionErrors = resolutionResults.compactMap { result -> DNSResolutionError? in
            if case .failure(let error) = result {
                return error
            } else {
                return nil
            }
        }
        assert(endpoints.count == resolutionResults.count)
        guard resolutionErrors.isEmpty else {
            throw WireGuardAdapterError.dnsResolution(resolutionErrors)
        }

        let resolvedEndpoints = resolutionResults.map { result -> Endpoint? in
            // swiftlint:disable:next force_try
            return try! result?.get()
        }

        return resolvedEndpoints
    }

    /// Start WireGuard backend.
    /// - Parameter wgConfig: WireGuard configuration
    /// - Throws: an error of type `WireGuardAdapterError`
    /// - Returns: tunnel handle
    private func startWireGuardBackend(wgConfig: String) throws -> Int32 {
        guard let tunnelFileDescriptor = self.tunnelFileDescriptor else {
            throw WireGuardAdapterError.cannotLocateTunnelFileDescriptor
        }

        let handle = wgTurnOn(wgConfig, tunnelFileDescriptor, socketType)
        if handle < 0 {
            throw WireGuardAdapterError.startWireGuardBackend(handle)
        }
        #if os(iOS)
        wgDisableSomeRoamingForBrokenMobileSemantics(handle)
        #endif
        return handle
    }

    /// Resolves the hostnames in the given tunnel configuration and return settings generator.
    /// - Parameter tunnelConfiguration: an instance of type `TunnelConfiguration`.
    /// - Throws: an error of type `WireGuardAdapterError`.
    /// - Returns: an instance of type `PacketTunnelSettingsGenerator`.
    private func makeSettingsGenerator(with tunnelConfiguration: TunnelConfiguration) throws -> PacketTunnelSettingsGenerator {
        let providerConfiguration = (packetTunnelProvider?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        return PacketTunnelSettingsGenerator(
            tunnelConfiguration: tunnelConfiguration,
            resolvedEndpoints: try self.resolvePeers(for: tunnelConfiguration),
            providerConfiguration: providerConfiguration
        )
    }

    /// Log DNS resolution results.
    /// - Parameter resolutionErrors: an array of type `[DNSResolutionError]`.
    private func logEndpointResolutionResults(_ resolutionResults: [EndpointResolutionResult?]) {
        for case .some(let result) in resolutionResults {
            switch result {
            case .success((let sourceEndpoint, let resolvedEndpoint)):
                if sourceEndpoint.host == resolvedEndpoint.host {
                    self.logHandler(.verbose, "DNS64: mapped \(sourceEndpoint.host) to itself.")
                } else {
                    self.logHandler(.verbose, "DNS64: mapped \(sourceEndpoint.host) to \(resolvedEndpoint.host)")
                }
            case .failure(let resolutionError):
                self.logHandler(.error, "Failed to resolve endpoint \(resolutionError.address): \(resolutionError.errorDescription ?? "(nil)")")
            }
        }
    }

    /// Helper method used by network path monitor.
    /// - Parameter path: new network path
    private func didReceivePathUpdate(path: NetworkExtension.NWPath?) {
        self.logHandler(.verbose, path?.pathUpdateDescription ?? "Network went offline.")

        switch self.state {
        case .started(let handle, let settingsGenerator):
            guard let path, path.status.isSatisfiable else {
                self.logHandler(.verbose, "Connectivity offline, pausing backend.")
                self.state = .temporaryShutdown(handle, settingsGenerator)
                wgSetNetworkAvailable(handle, 0)
                return
            }

            let (wgConfig, resolutionResults) = settingsGenerator.endpointUapiConfiguration()
            self.logEndpointResolutionResults(resolutionResults)

            wgSetConfig(handle, wgConfig)

            #if os(iOS)
            wgDisableSomeRoamingForBrokenMobileSemantics(handle)
            #endif

            wgSetNetworkAvailable(handle, 1)
            wgBumpSockets(handle)

        case let .temporaryShutdown(handle, settingsGenerator):
            guard let path, path.status.isSatisfiable else {
                self.logHandler(.verbose, "Connectivity still offline.")
                return
            }

            self.logHandler(.verbose, "Connectivity online, resuming backend.")

            wgSetNetworkAvailable(handle, 1)

            self.state = .started(
                handle,
                settingsGenerator
            )

        case .stopped:
            // no-op
            break
        }
    }
}

/// A enum describing WireGuard log levels defined in `api-apple.go`.
public enum WireGuardLogLevel: Int32 {
    case verbose = 0
    case error = 1
}

private extension NetworkExtension.NWPath {
    var pathUpdateDescription: String {
        var result = "Network change detected with \(status). isExpensive: \(isExpensive)"
        if #available(iOS 13, macOS 10.15, *) {
            result += " isConstrained: \(isConstrained)"
        }
        return result
    }
}

extension NetworkExtension.NWPathStatus: CustomStringConvertible {
    public var description: String {
        switch self {
        case .satisfiable:
            return "satisfiable"
        case .satisfied:
            return "satisfied"
        case .unsatisfied:
            return "unsatisfied"
        case .invalid:
            return "invalid"
        @unknown default:
            return "unknown (\(rawValue))"
        }
    }
}

private extension NetworkExtension.NWPathStatus {
    /// Returns `true` if the path is potentially satisfiable.
    var isSatisfiable: Bool {
        switch self {
        case .satisfiable, .satisfied:
            return true
        case .unsatisfied, .invalid:
            return false
        @unknown default:
            return true
        }
    }
}
