//
//  AsyncStream+Debounce.swift
//  WireGuardKit
//
//  Created by John Biggs on 11.08.2025.
//

import Foundation
import os.lock

public extension AsyncStream {
    /// Debounce an `AsyncStream`, returning a new one.
    func debounce(interval: Duration, tolerance: Duration? = nil) -> AsyncStream<Element> {
        assert(interval > .zero, "Debouncing with a zero interval makes no sense")

        return AsyncStream { continuation in
            let worker = Task {
                // The element we want to emit
                let pending = OSAllocatedUnfairLock<Element?>(initialState: nil)
                // One-shot timer triggering the debounce
                var timer: Task<Void, Error>?

                func armTimer() {
                    timer?.cancel()
                    timer = Task {
                        // Sleep for the specified interval, we might get canceled if new input comes
                        try await Task.sleep(for: interval, tolerance: tolerance)

                        // If the timer expires, yield the pending value
                        pending.withLock {
                            if !Task.isCancelled, let value = $0 {
                                $0 = nil
                                continuation.yield(value)
                            }
                        }
                    }
                }

                // Keep awaiting next elements and re-arming the timer
                for await next in self {
                    pending.withLock { $0 = next }
                    armTimer()
                }

                timer?.cancel()
                pending.withLock {
                    if let value = $0 {
                        continuation.yield(value)
                    }
                }

                continuation.finish()
            }

            continuation.onTermination = { _ in
                worker.cancel()
            }
        }
    }

    /// Return an `AsyncStream` that emits the running accumulation of `transform` starting from `initialResult`.
    ///
    /// This works identically to the `scan`  method in `AnyPublisher`.
    func scan<T: Sendable>(_ initialResult: T, _ transform: @Sendable @escaping (T, Element) -> T) -> AsyncStream<T> {
        return AsyncStream<T> { continuation in
            let worker = Task {
                var state = initialResult
                for await next in self {
                    guard !Task.isCancelled else { break }
                    state = transform(state, next)
                    continuation.yield(state)
                }
                continuation.finish()
            }

            continuation.onTermination = { _ in
                worker.cancel()
            }
        }
    }
}
