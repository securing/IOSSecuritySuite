//
//  Obfuscator.swift
//  IOSSecuritySuite
//
//  Created by Roman Panichkin on 04.09.2023.
//  Copyright © 2023 wregula. All rights reserved.
//

// https://gist.github.com/DejanEnspyra/80e259e3c9adf5e46632631b49cd1007
class Obfuscator {
    /// The salt used to obfuscate and reveal the string.
    private var salt: String

    init() {
        self.salt = "\(String(describing: IOSSecuritySuite.self))\(String(describing: JailbreakChecker.self))"
    }

    /**
     This method reveals the original string from the obfuscated
     byte array passed in. The salt must be the same as the one
     used to encrypt it in the first place.
     
     - parameter key: the byte array to reveal
     
     - returns: the original string
     */
    func reveal(key: [UInt8]) -> String {
        let cipher = [UInt8](salt.utf8)
        let length = cipher.count

        var decrypted = [UInt8]()

        for keyByte in key.enumerated() {
            decrypted.append(keyByte.element ^ cipher[keyByte.offset % length])
        }

        return String(bytes: decrypted, encoding: .utf8)!
    }
}
