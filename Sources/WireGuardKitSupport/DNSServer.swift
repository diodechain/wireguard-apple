// SPDX-License-Identifier: MIT
// Copyright © 2018-2021 WireGuard LLC. All Rights Reserved.

import Foundation
import Network

public enum DNSTransport: Equatable {
    case classic
    case https(path: String?)
    case tls
}

extension DNSTransport {
    static func transport(from url: URL) -> DNSTransport {
        switch url.scheme {
        case "https":
            let path = url.path()
            return .https(path: path.isEmpty ? nil : path)
        case "tls":
            return .tls
        default:
            return .classic
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
        case .https(let path?):
            return "https://\(address)\(path)"
        case .https(nil):
            return "https://\(address)"
        case .tls, .classic:
            return "\(address)"
        }
    }

    public init?(from addressString: String) {
        guard let url = URL(string: addressString) else {
            return nil
        }

        let transport = DNSTransport.transport(from: url)

        let host: String
        if #available(iOS 16.7, macOS 13.7, *) {
            host = url.host() ?? addressString
        } else {
            host = url.host ?? addressString
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
