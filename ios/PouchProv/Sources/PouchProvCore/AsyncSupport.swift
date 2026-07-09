// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Dispatch
import Foundation

/// Monotonic clock for protocol deadlines (never wall-clock `Date`, which can
/// jump — the analogue of Kotlin's `System.nanoTime()`).
public enum MonotonicClock {
    public static func nowMs() -> Int64 {
        Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000)
    }
}

public struct TimeoutError: Error, CustomStringConvertible {
    public init() {}

    public var description: String { "operation timed out" }
}

/// Run `operation` with a deadline, throwing ``TimeoutError`` if it does not
/// complete in time. The operation is cancelled when the timeout wins, so it
/// must be responsive to task cancellation.
public func withTimeout<T: Sendable>(
    ms: Int64,
    _ operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(max(ms, 0)) * 1_000_000)
            throw TimeoutError()
        }
        let result = try await group.next()!
        group.cancelAll()
        return result
    }
}

/// A non-reentrant FIFO async mutex — the analogue of Kotlin's
/// `kotlinx.coroutines.sync.Mutex`.
///
/// Actor isolation alone is NOT a substitute: actors are reentrant at
/// suspension points, so two overlapping SAR transactions (or GATT operations)
/// would interleave. Hold this for the whole logical transaction instead.
public final class AsyncMutex: @unchecked Sendable {
    private let lock = NSLock()
    private var locked = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    public init() {}

    public func acquire() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            if !locked {
                locked = true
                lock.unlock()
                continuation.resume()
            } else {
                waiters.append(continuation)
                lock.unlock()
            }
        }
    }

    public func release() {
        lock.lock()
        if waiters.isEmpty {
            locked = false
            lock.unlock()
        } else {
            let next = waiters.removeFirst()
            lock.unlock()
            next.resume()
        }
    }

    public func withLock<T>(_ body: () async throws -> T) async rethrows -> T {
        await acquire()
        defer { release() }
        return try await body()
    }
}

/// An unbounded single-consumer packet queue with per-wait timeouts — the
/// analogue of Kotlin's `Channel(UNLIMITED)` + `withTimeoutOrNull`.
///
/// `feed` is safe to call from any thread (e.g. a BLE notification callback).
/// A timed-out `receive` does NOT terminate the queue; later packets are still
/// delivered, which is what the SAR receiver's periodic re-ack poll relies on.
final class PacketQueue: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer: [Data] = []
    private var waiter: (id: Int, continuation: CheckedContinuation<Data?, Never>)?
    private var nextId = 0

    func feed(_ packet: Data) {
        lock.lock()
        if let waiting = waiter {
            waiter = nil
            lock.unlock()
            waiting.continuation.resume(returning: packet)
        } else {
            buffer.append(packet)
            lock.unlock()
        }
    }

    /// Wait up to `timeoutMs` for the next packet; nil on timeout.
    func receive(timeoutMs: Int64) async -> Data? {
        await withCheckedContinuation { continuation in
            lock.lock()
            if !buffer.isEmpty {
                let packet = buffer.removeFirst()
                lock.unlock()
                continuation.resume(returning: packet)
                return
            }
            nextId += 1
            let id = nextId
            waiter = (id, continuation)
            lock.unlock()
            Task {
                try? await Task.sleep(nanoseconds: UInt64(max(timeoutMs, 0)) * 1_000_000)
                self.expire(id)
            }
        }
    }

    private func expire(_ id: Int) {
        lock.lock()
        guard let waiting = waiter, waiting.id == id else {
            lock.unlock()
            return
        }
        waiter = nil
        lock.unlock()
        waiting.continuation.resume(returning: nil)
    }
}
