//
//  JailbreakChecker.swift
//  IOSSecuritySuite
//
//  Created by wregula on 23/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//

import Foundation
import UIKit
import Darwin // fork
import MachO // dyld

class JailbreakChecker {
    
    static func amIJailbroken() -> Bool {
        return !self.performChecks().passed
    }
    
    static func amIJailbrokenWithFailMessage() -> (jailbroken: Bool, failMessage: String) {
        let performChecks = self.performChecks()
        return (!performChecks.passed, performChecks.failMessage)
    }
    
    private static func performChecks() -> (passed: Bool, failMessage: String) {
        
        let checklist = [
            self.checkURLSchemes(),
            self.checkExistenceOfSuspiciousFiles(),
            self.checkSuspiciousFilesCanBeOpened(),
            self.checkRestrictedDirectoriesWriteable(),
            self.checkFork(),
            self.checkSymbolicLinks(),
            self.checkDYLD()
        ]
        
        var passed = true
        var failMessage = ""
        
        for check in checklist {
            passed = passed && check.passed
            if !failMessage.isEmpty && !check.passed {
                failMessage += ", "
            }
            failMessage += check.failMessage
        }
        
        return (passed, failMessage)
    }
    
    private static func checkURLSchemes() -> (passed: Bool, failMessage: String) {
        
        let unc0verUrlScheme = URL(string: "undecimus://")
        if UIApplication.shared.canOpenURL(unc0verUrlScheme!) {
            return(false, "unc0ver jailbreak app URL scheme detected")
        }
        
        let cydiaUrlScheme = URL(string: "cydia://package/com.example.package")
        if UIApplication.shared.canOpenURL(cydiaUrlScheme!) {
            return(false, "Cydia URL scheme detected")
        }
        
        let sileoUrlScheme = URL(string: "sileo://")
        if UIApplication.shared.canOpenURL(sileoUrlScheme!) {
            return(false, "Sileo URL scheme detected")
        }
        
        return (true, "")
    }
    
    private static func checkExistenceOfSuspiciousFiles() -> (passed: Bool, failMessage: String) {
        
        let paths = [
            "/etc/apt/sources.list.d/electra.list", // electra
            "/etc/apt/sources.list.d/sileo.sources", // electra
            "/.bootstrapped_electra", // electra
            "/usr/lib/libjailbreak.dylib", // electra
            "/jb/lzma", // electra
            "/.cydia_no_stash", // unc0ver
            "/.installed_unc0ver", // unc0ver
            "/jb/offsets.plist", // unc0ver
            "/usr/share/jailbreak/injectme.plist", // unc0ver
            "/etc/apt/undecimus/undecimus.list", // unc0ver
            "/var/lib/dpkg/info/mobilesubstrate.md5sums", // unc0ver
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/jb/jailbreakd.plist", // unc0ver
            "/jb/amfid_payload.dylib", // unc0ver
            "/jb/libjailbreak.dylib", // unc0ver
            "/usr/libexec/cydia/firmware.sh",
            "/var/lib/cydia",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/usr/bin/ssh",
            "/private/var/lib/apt",
            "/private/var/Users/",
            "/var/log/apt",
            "/usr/libexec/ssh-keysign",
            "/Applications/Cydia.app"
        ]
        
        for path in paths {
            if FileManager.default.fileExists(atPath: path) {
                return (false, "Suspicious file exists: \(path)")
            }
        }
        
        return (true, "")
    }
    
    private static func checkSuspiciousFilesCanBeOpened() -> (passed: Bool, failMessage: String) {
        
        let paths = [
            "/.installed_unc0ver",
            "/.bootstrapped_electra",
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/usr/bin/ssh",
            "/var/log/apt"
        ]
        
        for path in paths {
            
            if FileManager.default.isReadableFile(atPath: path) {
                return (false, "Suspicious file can be opened: \(path)")
            }
        }
        
        return (true, "")
    }
    
    private static func checkRestrictedDirectoriesWriteable() -> (passed: Bool, failMessage: String) {
        
        let paths = [
            "/",
            "/root/",
            "/private/",
            "/jb/"
        ]
        
        // If library won't be able to write to any restricted directory the return(false, ...) is never reached
        // because of catch{} statement
        for path in paths {
            do {
                let pathWithSomeRandom = path+UUID().uuidString
                try "AmIJailbroken?".write(toFile: pathWithSomeRandom, atomically: true, encoding: String.Encoding.utf8)
                try FileManager.default.removeItem(atPath: pathWithSomeRandom) // clean if succesfully written
                return (false, "Wrote to restricted path: \(path)")
            } catch {}
        }
        
        return (true, "")
    }
    
    private static func checkFork() -> (passed: Bool, failMessage: String) {
        
        let pointerToFork = UnsafeMutableRawPointer(bitPattern: -2)
        let forkPtr = dlsym(pointerToFork, "fork")
        typealias ForkType = @convention(c) () -> pid_t
        let fork = unsafeBitCast(forkPtr, to: ForkType.self)
        let forkResult = fork()
        pointerToFork?.deallocate()
        
        if forkResult >= 0 {
            if forkResult > 0 {
                kill(forkResult, SIGTERM)
            }
            return (false, "Fork was able to create a new process (sandbox violation)")
        }
        
        return (true, "")
    }
    
    private static func checkSymbolicLinks() -> (passed: Bool, failMessage: String) {
        
        let paths = [
            "/var/lib/undecimus/apt", // unc0ver
            "/Applications",
            "/Library/Ringtones",
            "/Library/Wallpaper",
            "/usr/arm-apple-darwin9",
            "/usr/include",
            "/usr/libexec",
            "/usr/share"
        ]
        
        for path in paths {
            do {
                let result = try FileManager.default.destinationOfSymbolicLink(atPath: path)
                if !result.isEmpty {
                    return (false, "Non standard symbolic link detected: \(path) points to \(result)")
                }
            } catch {}
        }
        
        return (true, "")
    }
    
    private static func checkDYLD() -> (passed: Bool, failMessage: String) {
        
        let suspiciousLibraries = [
            "SubstrateLoader.dylib",
            "SSLKillSwitch2.dylib",
            "SSLKillSwitch.dylib",
            "MobileSubstrate.dylib",
            "TweakInject.dylib",
            "CydiaSubstrate",
            "cynject",
            "CustomWidgetIcons",
            "PreferenceLoader",
            "RocketBootstrap",
            "WeeLoader"
        ]
        
        for libraryIndex in 0..<_dyld_image_count() {
            
            // _dyld_get_image_name returns const char * that needs to be casted to Swift String
            guard let loadedLibrary = String(validatingUTF8: _dyld_get_image_name(libraryIndex)) else { continue }
            
            for suspiciousLibrary in suspiciousLibraries {
                if loadedLibrary.contains(suspiciousLibrary) {
                    return(false, "Suspicious library loaded: \(loadedLibrary)")
                }
            }
        }
        
        return (true, "")
    }
}
