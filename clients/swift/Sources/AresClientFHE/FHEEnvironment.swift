// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

public enum AresFHE {
    public static func openFHEVersion() -> String {
        var buf = [CChar](repeating: 0, count: 32)
        let written = GetOpenFHEVersion(&buf, 32)
        guard written > 0 else { return "" }
        return String(cString: buf)
    }
}
