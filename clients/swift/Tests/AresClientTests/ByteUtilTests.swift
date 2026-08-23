import XCTest
@testable import AresClient

final class ByteUtilTests: XCTestCase {
    func testU32BE() {
        XCTAssertEqual(ByteUtil.u32be(16), Data([0x00, 0x00, 0x00, 0x10]))
        XCTAssertEqual(ByteUtil.u32be(0), Data([0, 0, 0, 0]))
    }
    func testLengthPrefix() {
        let lp = ByteUtil.lp(Data("anon-g-verify".utf8))
        XCTAssertEqual(lp.prefix(4), Data([0, 0, 0, 0x0d]))
        XCTAssertEqual(lp.count, 4 + 13)
    }
    func testHexRoundTrip() {
        let d = Data([0x00, 0x01, 0xff, 0xa1])
        XCTAssertEqual(ByteUtil.hex(d), "0001ffa1")
        XCTAssertEqual(ByteUtil.fromHex("0001ffa1"), d)
    }
}
