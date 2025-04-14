// SPDX-License-Identifier: MIT
// Copyright © 2018-2021 WireGuard LLC. All Rights Reserved.

import Foundation
import Network

public enum DNSTransport {
    case classic
    case https
    case tls
}

extension DNSTransport {
    static func transport(from stringValue: some StringProtocol) -> DNSTransport? {
        switch stringValue {
        case "https":
            return .https
        case "tls":
            return .tls
        default:
            return nil
        }
    }
}

public struct DNSServer {
    public let address: IPAddress
    public let transport: DNSTransport

    public init(address: IPAddress, transport: DNSTransport) {
        self.address = address
        self.transport = transport
    }
}

extension DNSServer: Equatable {
    public static func == (lhs: DNSServer, rhs: DNSServer) -> Bool {
        return lhs.address.rawValue == rhs.address.rawValue && lhs.transport == rhs.transport
    }
}

extension DNSServer {
    public var stringRepresentation: String {
        switch transport {
        case .https:
            return "https://\(address)/dns-query"
        case .tls, .classic:
            return "\(address)"
        }
    }

    public init?(from addressString: String) {
        let host: String
        let transport: DNSTransport
        if #available(iOS 16.0, macOS 13.0, *) {
            let components = addressString.split(separator: "://")
            if components.count > 1 {
                host = String(components[1])
                transport = DNSTransport.transport(from: components[0]) ?? .classic
            } else {
                host = String(components[0])
                transport = .classic
            }
        } else {
            host = addressString
            transport = .classic
        }
        if let addr = IPv4Address(host) {
            self.address = addr
            self.transport = transport
        } else if let addr = IPv6Address(host) {
            self.address = addr
            self.transport = transport
        } else {
            return nil
        }
    }
}
