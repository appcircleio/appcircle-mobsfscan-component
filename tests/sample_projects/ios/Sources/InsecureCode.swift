import CommonCrypto
import Foundation
import UIKit

/// Deliberately insecure iOS sample used by the mobsfscan component tests.
class InsecureCode {

    let apiKey = "sk_live_hardcoded_api_key_value"
    let password = "SuperSecret123"

    func weakHash(_ data: Data) -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        _ = data.withUnsafeBytes { CC_MD5($0.baseAddress, CC_LONG(data.count), &digest) }
        return Data(digest)
    }

    func insecureRandom() -> Int {
        return Int(arc4random() % 100)
    }

    func loadWeb(_ webView: UIWebView) {
        webView.loadRequest(URLRequest(url: URL(string: "http://example.com")!))
    }
}
