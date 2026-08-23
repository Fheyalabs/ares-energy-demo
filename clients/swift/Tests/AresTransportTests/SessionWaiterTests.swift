import XCTest
@testable import AresTransport

/// Regression tests for the orphaned-continuation bug fixed in receiveAny.
///
/// Before the fix, a timed-out receiveAny left its CheckedContinuation in
/// `waiters`.  The next deliver() would resume that abandoned continuation
/// (silently dropping the frame), and the subsequent receiveAny would block
/// forever.  These tests drive the waiter logic directly via the DEBUG-only
/// test surface, so no live socket is required.
#if DEBUG
final class SessionWaiterTests: XCTestCase {

    // Helper: build a minimal InboundFrame.
    private func frame(_ type: String, seq: Int = 0) -> InboundFrame {
        let raw = Data(#"{"type":"\#(type)","session_id":"test","seq":\#(seq)}"#.utf8)
        return try! WSFrame.decodeInbound(raw)
    }

    // MARK: - Core regression

    /// A timed-out receiveAny must NOT prevent a subsequent call from receiving
    /// the next delivered frame.  This is the direct regression for the
    /// orphaned-continuation bug: before the fix, the timeout left a stale
    /// continuation in `waiters`; the next delivery silently consumed it and
    /// the following receiveAny stalled.
    func testTimedOutReceiveAnyDoesNotOrphanNextFrame() async throws {
        let session = Session(_testPseudonym: "test-orphan")

        // 1. Issue a receiveAny that will time out (50 ms).
        let timedOut = await session._testTakeWithTimeout(0.05)
        XCTAssertFalse(timedOut, "Expected timeout but got a frame")

        // 2. Deliver a frame after the timeout.
        await session._testEnqueue(frame("hello", seq: 1))

        // 3. A fresh receiveAny should pick up the frame, NOT block forever.
        //    If the bug is present this call will block until the 1 s ceiling.
        let got = await session._testTakeWithTimeout(1.0)
        XCTAssertTrue(got, "Frame delivered after timeout was not received — orphaned continuation bug")
    }

    // MARK: - Multiple consecutive timeouts do not accumulate stale waiters

    /// Three consecutive timeouts must leave the waiter list empty; a frame
    /// delivered afterwards should land in inbox and be returned by the next
    /// receiveAny.
    func testMultipleConsecutiveTimeoutsLeaveNoOrphans() async throws {
        let session = Session(_testPseudonym: "test-multi-timeout")

        for _ in 0..<3 {
            let r = await session._testTakeWithTimeout(0.05)
            XCTAssertFalse(r, "Expected timeout")
        }

        // Deliver one frame; it should go into inbox (no waiters remaining).
        await session._testEnqueue(frame("after-timeouts", seq: 99))

        let got = await session._testTakeWithTimeout(1.0)
        XCTAssertTrue(got, "Frame was not received after multiple timeouts — stale waiters present")
    }

    // MARK: - Frame-before-receive lands in inbox

    /// A frame enqueued before any receiveAny call is buffered in inbox and
    /// returned immediately without suspending.
    func testFrameEnqueuedBeforeReceiveIsReturnedImmediately() async throws {
        let session = Session(_testPseudonym: "test-inbox")

        await session._testEnqueue(frame("pre-queued", seq: 7))

        // Very short timeout — should still succeed because inbox is non-empty.
        let got = await session._testTakeWithTimeout(0.001)
        XCTAssertTrue(got, "Pre-queued frame was not drained from inbox")
    }

    // MARK: - expect preserves unmatched frames

    /// A typed wait must not consume adjacent control frames. If the BFV
    /// fallback frame arrives just before normcheck.passed, expect should return
    /// the normcheck frame and leave fallback.bfv_required available next.
    func testExpectPreservesFallbackFrameBeforeNormcheckPassed() async throws {
        let session = Session(_testPseudonym: "test-expect-preserve")

        await session._testEnqueue(frame("fallback.bfv_required", seq: 10))
        await session._testEnqueue(frame("normcheck.passed", seq: 11))

        let norm = try await session.expect("normcheck.passed", timeout: 1)
        XCTAssertEqual(norm.type, "normcheck.passed")
        XCTAssertEqual(norm.seq, 11)

        let fallback = try await session.receiveAny(timeout: 1)
        XCTAssertEqual(fallback.type, "fallback.bfv_required")
        XCTAssertEqual(fallback.seq, 10)
    }

    /// If expect times out after seeing an unrelated frame, that unrelated frame
    /// must be put back so the caller can handle it with receiveAny.
    func testExpectTimeoutRestoresUnmatchedFrame() async throws {
        let session = Session(_testPseudonym: "test-expect-timeout")

        await session._testEnqueue(frame("fallback.bfv_required", seq: 20))

        do {
            _ = try await session.expect("normcheck.passed", timeout: 0.05)
            XCTFail("expect should have timed out")
        } catch TransportError.timeout(let message) {
            XCTAssertTrue(message.contains("normcheck.passed"))
        }

        let fallback = try await session.receiveAny(timeout: 1)
        XCTAssertEqual(fallback.type, "fallback.bfv_required")
        XCTAssertEqual(fallback.seq, 20)
    }

    func testReceiveAfterCloseFailsAsClosedInsteadOfWaitingForTimeout() async throws {
        let session = Session(_testPseudonym: "test-closed")
        await session.close()

        do {
            _ = try await session.receiveAny(timeout: 0.05)
            XCTFail("closed transport accepted a new receive waiter")
        } catch let error as TransportError {
            guard case .closed = error else {
                return XCTFail("unexpected transport error: \(error)")
            }
        }
    }
}
#endif
