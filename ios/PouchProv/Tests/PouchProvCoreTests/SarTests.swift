// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Foundation
import XCTest
@testable import PouchProvCore

/// SAR sender <-> receiver loopback. The sender's writes feed the receiver and
/// vice-versa; a multi-fragment payload exercises windowing, LAST/FIN and the
/// opening ack.
final class SarTests: XCTestCase {

    private final class Box<T>: @unchecked Sendable {
        var value: T?
    }

    private func roundTrip(_ payload: Data, maxlen: Int, window: Int) async throws -> Data {
        let senderBox = Box<SarSender>()
        let receiver = SarReceiver(
            write: { senderBox.value?.feed($0) },
            window: window,
            reackIntervalMs: 50
        )
        let sender = SarSender(write: { receiver.feed($0) }, maxlen: maxlen)
        senderBox.value = sender

        async let received = receiver.receive(timeoutMs: 10_000)
        try await sender.send(payload, timeoutMs: 10_000)
        return try await received
    }

    func testMultiFragment() async throws {
        let payload = Data((0..<1000).map { UInt8(truncatingIfNeeded: $0 * 7 + 3) })
        let result = try await roundTrip(payload, maxlen: 10, window: 4)
        XCTAssertEqual(payload, result)
    }

    func testSingleFragment() async throws {
        let payload = Data([1, 2, 3])
        let result = try await roundTrip(payload, maxlen: 244, window: 8)
        XCTAssertEqual(payload, result)
    }

    func testEmptyPayload() async throws {
        let result = try await roundTrip(Data(), maxlen: 244, window: 8)
        XCTAssertEqual(Data(), result)
    }

    func testWindowOne() async throws {
        let payload = Data((0..<300).map { UInt8(truncatingIfNeeded: $0) })
        let result = try await roundTrip(payload, maxlen: 12, window: 1)
        XCTAssertEqual(payload, result)
    }
}
