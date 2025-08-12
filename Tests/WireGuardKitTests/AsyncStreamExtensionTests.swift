//
// AsyncStreamExtensionTests.swift
//
// Created on 12.08.2025 by John Biggs.
//

import XCTest
@testable import WireGuardKitSupport

final class AsyncStreamDebounceTests: XCTestCase {
    /// Collects all elements from a stream into an array.
    private func collectAll<T>(
        from stream: AsyncStream<T>
    ) async -> [T] {
        var out: [T] = []
        for await value in stream {
            out.append(value)
        }
        return out
    }

    /// A tiny helper to sleep with milliseconds.
    private func ms(_ value: Int) -> Duration { .milliseconds(value) }

    func testDebounceEmitsLatestAfterQuietPeriod() async {
        // Given a stream that emits 1,2,3 quickly (within the debounce window)
        let source = AsyncStream<Int> { continuation in
            Task {
                continuation.yield(1)
                try? await Task.sleep(for: ms(30))
                continuation.yield(2)
                try? await Task.sleep(for: ms(30))
                continuation.yield(3)
                // No more input; now let the debounce timer expire
                try? await Task.sleep(for: ms(150))
                continuation.finish()
            }
        }

        // When debouncing at 100ms
        let debounced = source.debounce(interval: ms(100))

        // Then only the last value (3) should be emitted
        let values = await collectAll(from: debounced)
        XCTAssertEqual(values, [3], "Debounce should emit only the last value after inactivity.")
    }

    func testDebounceEmitsMultipleValuesWhenSeparatedByInterval() async {
        // Given values spaced out more than the debounce interval
        let source = AsyncStream<Int> { continuation in
            Task {
                continuation.yield(1)
                try? await Task.sleep(for: ms(150))
                continuation.yield(2)
                try? await Task.sleep(for: ms(150))
                continuation.yield(3)
                try? await Task.sleep(for: ms(150))
                continuation.finish()
            }
        }

        // When debouncing at 100ms
        let debounced = source.debounce(interval: ms(100))

        // Then each value should make it through
        let values = await collectAll(from: debounced)
        XCTAssertEqual(values, [1, 2, 3])
    }

    func testDebounceEmitsTrailingPendingOnFinish() async {
        // Given values that arrive quickly, then the upstream finishes *before* interval elapses
        let finishSoon = AsyncStream<Int> { continuation in
            Task {
                continuation.yield(10)
                try? await Task.sleep(for: ms(20))
                continuation.yield(11)
                // Finish immediately; the operator should emit the pending '11' on finish.
                continuation.finish()
            }
        }

        // When debouncing at 100ms
        let debounced = finishSoon.debounce(interval: ms(100))

        // Then the last pending value should still be emitted due to the finish path
        let values = await collectAll(from: debounced)
        XCTAssertEqual(values, [11], "Operator should flush pending value when upstream finishes.")
    }

    func testDebounceEmitsNothingIfNoInput() async {
        // Given a stream that finishes immediately with no values
        let empty = AsyncStream<Int> { continuation in
            continuation.finish()
        }

        // When debouncing
        let debounced = empty.debounce(interval: ms(100))

        // Then nothing is emitted
        let values = await collectAll(from: debounced)
        XCTAssertTrue(values.isEmpty)
    }

    func testDebounceStopsOnConsumerCancellation() async {
        // Given a busy source that keeps producing values
        let source = AsyncStream<Int> { continuation in
            Task {
                var i = 0
                while !Task.isCancelled && i < 10_000 {
                    continuation.yield(i)
                    i += 1
                    try? await Task.sleep(for: ms(10))
                }
                continuation.finish()
            }
        }

        // When debouncing at 100ms and canceling the consumer shortly after
        let debounced = source.debounce(interval: ms(100))

        // Collect in a task we can cancel
        let collector = Task<[Int], Never> {
            var out: [Int] = []
            for await v in debounced {
                out.append(v)
            }
            return out
        }

        // Cancel after 120ms, around when the *first* debounced output might occur.
        try? await Task.sleep(for: ms(120))
        collector.cancel()

        // Then we should either have zero or at most one value, and certainly no endless emission.
        let values = await collector.value
        XCTAssertLessThanOrEqual(values.count, 1, "Consumer cancellation should stop further emissions.")
    }
}

final class AsyncStreamScanTests: XCTestCase {
    private func stream<Element>(from elements: [Element]) -> AsyncStream<Element> {
        AsyncStream<Element> { continuation in
            for e in elements {
                continuation.yield(e)
            }
            continuation.finish()
        }
    }

    func testScanAccumulatesValues() async {
        let source = stream(from: [1, 2, 3, 4])

        let scanned = source.scan(0, { $0 + $1 })

        var received: [Int] = []
        for await v in scanned {
            received.append(v)
        }

        // Accumulations of [1,2,3,4] starting at 0 (seed not emitted)
        XCTAssertEqual(received, [1, 3, 6, 10])
    }

    func testScanDoesNotEmitInitialValue() async {
        let source = stream(from: [5])

        let scanned = source.scan(100) { $0 + $1 }

        var received: [Int] = []
        for await v in scanned {
            received.append(v)
        }

        // Only one element => only one output, not including the seed (100).
        XCTAssertEqual(received, [105])
    }

    func testScanOnEmptyStreamEmitsNothingAndFinishes() async {
        let source = stream(from: [Int]())
        let scanned = source.scan(42, { $0 + $1 })

        var iterator = scanned.makeAsyncIterator()
        let first = await iterator.next()

        XCTAssertNil(first, "Empty source should complete with no values (seed not emitted).")
    }

    func testScanPropagatesFinish() async {
        // The source finishes immediately after yielding 2 elements.
        let source = stream(from: [1, 1])
        let scanned = source.scan(0, { $0 + $1 })

        var count = 0
        for await _ in scanned {
            count += 1
        }

        XCTAssertEqual(count, 2, "Downstream should finish when upstream finishes.")
    }

    func testScanWithNonCommutativeTransform() async {
        struct State: Equatable { var log: [String] = [] }

        let source = stream(from: ["A", "B", "C"])
        let scanned = source.scan(State()) { state, element in
            var next = state
            next.log.append(element)
            return next
        }

        var states: [State] = []
        for await s in scanned {
            states.append(s)
        }

        XCTAssertEqual(states.map(\.log), [["A"], ["A","B"], ["A","B","C"]])
    }
}
