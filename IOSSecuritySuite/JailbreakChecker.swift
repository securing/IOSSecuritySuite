//
//  JailbreakChecker.swift
//  IOSSecuritySuite
//
//  Created by wregula on 23/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//
// swiftlint:disable function_body_length type_body_length line_length

import Foundation
import UIKit
import Darwin // fork
import MachO // dyld
import ObjectiveC // NSObject and Selector

internal class JailbreakChecker {
  typealias CheckResult = (passed: Bool, failMessage: String)
  
  struct JailbreakStatus {
    let passed: Bool
    let failMessage: String // Added for backwards compatibility
    let failedChecks: [FailedCheckType]
  }
  
  // Cache emulator check result to avoid redundant calls
  private static var isEmulator: Bool {
    return EmulatorChecker.amIRunInEmulator()
  }
  
  static func amIJailbroken() -> Bool {
    // Fast path: exit early on first failure for simple boolean check
    return performChecks(earlyExit: true).passed == false
  }
  
  static func amIJailbrokenWithFailMessage() -> (jailbroken: Bool, failMessage: String) {
    let status = performChecks(earlyExit: false)
    return (!status.passed, status.failMessage)
  }
  
  static func amIJailbrokenWithFailedChecks() -> (jailbroken: Bool,
                                                  failedChecks: [FailedCheckType]) {
    let status = performChecks(earlyExit: false)
    return (!status.passed, status.failedChecks)
  }
  
  private static func performChecks(earlyExit: Bool = false) -> JailbreakStatus {
    var passed = true
    var failMessages: [String] = []
    var failedChecks: [FailedCheckType] = []
    
    for check in FailedCheck.allCases {
      let result = getResult(from: check)
      
      if !result.passed {
        passed = false
        failedChecks.append((check: check, failMessage: result.failMessage))
        failMessages.append(result.failMessage)
        
        // Early exit optimization for simple boolean check
        if earlyExit {
          return JailbreakStatus(passed: false, failMessage: result.failMessage, failedChecks: failedChecks)
        }
      }
    }
    
    return JailbreakStatus(passed: passed, failMessage: failMessages.joined(separator: ", "), failedChecks: failedChecks)
  }
  
  private static func getResult(from check: FailedCheck) -> CheckResult {
    switch check {
    case .urlSchemes:
      return checkURLSchemes()
    case .existenceOfSuspiciousFiles:
      return checkExistenceOfSuspiciousFiles()
    case .suspiciousFilesCanBeOpened:
      return checkSuspiciousFilesCanBeOpened()
    case .restrictedDirectoriesWriteable:
      return checkRestrictedDirectoriesWriteable()
    case .fork:
      if !isEmulator {
        return checkFork()
      } else {
        return (true, "")
      }
    case .symbolicLinks:
      return checkSymbolicLinks()
    case .dyld:
      return checkDYLD()
    case .suspiciousObjCClasses:
      return checkSuspiciousObjCClasses()
    default:
      return (true, "")
    }
  }
  
  private static func canOpenUrlFromList(urlSchemes: [String]) -> CheckResult {
    for urlScheme in urlSchemes {
      if let url = URL(string: urlScheme) {
        if UIApplication.shared.canOpenURL(url) {
          return(false, "\(urlScheme) URL scheme detected")
        }
      }
    }
    return (true, "")
  }
  
  // "cydia://" URL scheme has been removed. Turns out there is app in the official App Store
  // that has the cydia:// URL scheme registered, so it may cause false positive
  // "activator://" URL scheme has been removed for the same reason.
  private static func checkURLSchemes() -> CheckResult {
    let urlSchemes = [
      "undecimus://",    // unc0ver
      "sileo://",        // Sileo package manager
      "zbra://",         // Zebra package manager
      "filza://",        // Filza file manager
      "dopamine://",     // Dopamine jailbreak
      "palera1n://"      // palera1n jailbreak
    ]
    return canOpenUrlFromList(urlSchemes: urlSchemes)
  }
  
  private static func checkExistenceOfSuspiciousFiles() -> CheckResult {
    var paths = [
      // Modern rootless jailbreaks (Dopamine, palera1n, roothide)
      "/var/jb", // Rootless jailbreak prefix symlink
      "/var/jb/usr/bin", // Rootless binaries
      "/var/jb/Library/LaunchDaemons", // Rootless launch daemons
      "/var/jb/etc/rc.d", // Rootless startup scripts
      "/cores", // Temporary jailbreak filesystem mount point (palera1n)
      "/var/Liy/.procursus_strapped", // Dopamine bootstrap marker
      "/var/Liy", // Dopamine data directory
      
      // Dopamine-specific
      "/Applications/Dopamine.app",
      "/var/mobile/Library/Preferences/com.opa334.Dopamine.plist",
      
      // palera1n-specific
      "/Applications/palera1nLoader.app",
      "/usr/bin/palera1n-helper",
      "/var/mobile/Library/Preferences/com.samiiau.loader.plist",
      
      // RootHide detection
      "/var/mobile/Library/Preferences/com.roothide.pref.plist",
      
      // Ellekit (modern tweak injection)
      "/usr/lib/libellekit.dylib",
      "/var/jb/usr/lib/libellekit.dylib",
      
      // A-Bypass
      "/var/mobile/Library/Preferences/ABPattern", // A-Bypass
      "/usr/lib/ABDYLD.dylib", // A-Bypass
      "/usr/lib/ABSubLoader.dylib", // A-Bypass
      
      // Frida
      "/usr/sbin/frida-server",
      "/usr/lib/frida",
      
      // Electra
      "/etc/apt/sources.list.d/electra.list",
      "/etc/apt/sources.list.d/sileo.sources",
      "/.bootstrapped_electra",
      "/usr/lib/libjailbreak.dylib",
      "/jb/lzma",
      
      // unc0ver
      "/.cydia_no_stash",
      "/.installed_unc0ver",
      "/jb/offsets.plist",
      "/usr/share/jailbreak/injectme.plist",
      "/etc/apt/undecimus/undecimus.list",
      "/var/lib/dpkg/info/mobilesubstrate.md5sums",
      "/jb/jailbreakd.plist",
      "/jb/amfid_payload.dylib",
      "/jb/libjailbreak.dylib",
      
      // checkra1n
      "/var/binpack",
      "/var/binpack/Applications/loader.app",
      
      // Substrate/Substitute/libhooker
      "/Library/MobileSubstrate/MobileSubstrate.dylib",
      "/Library/MobileSubstrate/CydiaSubstrate.dylib",
      "/Library/MobileSubstrate/DynamicLibraries",
      "/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch2.plist",
      "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.plist",
      "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib",
      "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
      "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
      "/usr/lib/libhooker.dylib",
      "/usr/lib/libsubstitute.dylib",
      "/usr/lib/substrate",
      "/usr/lib/TweakInject",
      
      // Cydia and package managers
      "/usr/libexec/cydia/firmware.sh",
      "/var/lib/cydia",
      "/etc/apt",
      "/private/var/lib/apt",
      "/var/log/apt",
      "/Applications/Cydia.app",
      "/Applications/Sileo.app",
      "/Applications/Zebra.app",
      "/private/var/stash",
      "/private/var/lib/cydia",
      "/private/var/cache/apt/",
      "/private/var/log/syslog",
      "/private/var/tmp/cydia.log",
      
      // Preference bundles (jailbreak tools)
      "/Library/PreferenceBundles/LibertyPref.bundle",
      "/Library/PreferenceBundles/ShadowPreferences.bundle",
      "/Library/PreferenceBundles/ABypassPrefs.bundle",
      "/Library/PreferenceBundles/FlyJBPrefs.bundle",
      "/Library/PreferenceBundles/Cephei.bundle",
      "/Library/PreferenceBundles/SubstitutePrefs.bundle",
      "/Library/PreferenceBundles/libhbangprefs.bundle",
      
      // Legacy jailbreak apps
      "/Applications/Icy.app",
      "/Applications/MxTube.app",
      "/Applications/RockApp.app",
      "/Applications/blackra1n.app",
      "/Applications/SBSettings.app",
      "/Applications/FakeCarrier.app",
      "/Applications/WinterBoard.app",
      "/Applications/IntelliScreen.app",
      "/Applications/FlyJB.app",
      "/Library/BawAppie/ABypass",
      
      // Other artifacts
      "/private/var/mobile/Library/SBSettings/Themes",
      "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
      "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
      "/var/mobile/Library/Preferences/me.jjolano.shadow.plist"
    ]
    
    // These files can give false positive in the emulator
    if !EmulatorChecker.amIRunInEmulator() {
      paths += [
        "/bin/bash",
        "/usr/sbin/sshd",
        "/usr/libexec/ssh-keysign",
        "/bin/sh",
        "/etc/ssh/sshd_config",
        "/usr/libexec/sftp-server",
        "/usr/bin/ssh"
      ]
    }
    
    for path in paths {
      if FileManager.default.fileExists(atPath: path) {
        return (false, "Suspicious file exists: \(path)")
      } else if let result = FileChecker.checkExistenceOfSuspiciousFilesViaStat(path: path) {
        return result
      } else if let result = FileChecker.checkExistenceOfSuspiciousFilesViaFOpen(
        path: path,
        mode: .readable
      ) {
        return result
      } else if let result = FileChecker.checkExistenceOfSuspiciousFilesViaAccess(
        path: path,
        mode: .readable
      ) {
        return result
      }
    }
    
    return (true, "")
  }
  
  private static func checkSuspiciousFilesCanBeOpened() -> CheckResult {
    var paths = [
      "/.installed_unc0ver",
      "/.bootstrapped_electra",
      "/Applications/Cydia.app",
      "/Library/MobileSubstrate/MobileSubstrate.dylib",
      "/etc/apt",
      "/var/log/apt"
    ]
    
    // These files can give false positive in the emulator
    if !EmulatorChecker.amIRunInEmulator() {
      paths += [
        "/bin/bash",
        "/usr/sbin/sshd",
        "/usr/bin/ssh"
      ]
    }
    
    for path in paths {
      if FileManager.default.isReadableFile(atPath: path) {
        return (false, "Suspicious file can be opened: \(path)")
      } else if let result = FileChecker.checkExistenceOfSuspiciousFilesViaFOpen(
        path: path,
        mode: .writable
      ) {
        return result
      } else if let result = FileChecker.checkExistenceOfSuspiciousFilesViaAccess(
        path: path,
        mode: .writable
      ) {
        return result
      }
    }
    
    return (true, "")
  }
  
  private static func checkRestrictedDirectoriesWriteable() -> CheckResult {
    let paths = [
      "/",
      "/root/",
      "/private/",
      "/jb/"
    ]
    
    if FileChecker.checkRestrictedPathIsReadonlyViaStatvfs(path: "/") == false {
      return (false, "Restricted path '/' is not Read-Only")
    } else if FileChecker.checkRestrictedPathIsReadonlyViaStatfs(path: "/") == false {
      return (false, "Restricted path '/' is not Read-Only")
    } else if FileChecker.checkRestrictedPathIsReadonlyViaGetfsstat(name: "/") == false {
      return (false, "Restricted path '/' is not Read-Only")
    }
    
    // If library won't be able to write to any restricted directory the return(false, ...) is never reached
    // because of catch{} statement
    for path in paths {
      do {
        let pathWithSomeRandom = path + UUID().uuidString
        try "AmIJailbroken?".write(
          toFile: pathWithSomeRandom,
          atomically: true,
          encoding: String.Encoding.utf8
        )
        // clean if successfully written
        try FileManager.default.removeItem(atPath: pathWithSomeRandom)
        return (false, "Wrote to restricted path: \(path)")
      } catch {}
    }
    
    return (true, "")
  }
  
  private static func checkFork() -> CheckResult {
    let pointerToFork = UnsafeMutableRawPointer(bitPattern: -2)
    let forkPtr = dlsym(pointerToFork, "fork")
    typealias ForkType = @convention(c) () -> pid_t
    let fork = unsafeBitCast(forkPtr, to: ForkType.self)
    let forkResult = fork()
    
    if forkResult >= 0 {
      if forkResult > 0 {
        kill(forkResult, SIGTERM)
      }
      return (false, "Fork was able to create a new process (sandbox violation)")
    }
    
    return (true, "")
  }
  
  private static func checkSymbolicLinks() -> CheckResult {
    // Check for /var/jb symlink - key indicator of modern rootless jailbreaks
    // This symlink points to the jailbreak bootstrap (e.g., /private/preboot/.../procursus)
    if let jbTarget = try? FileManager.default.destinationOfSymbolicLink(atPath: "/var/jb") {
      return (false, "Rootless jailbreak symlink detected: /var/jb -> \(jbTarget)")
    }
    
    // Check for RootHide-style randomized jbroot symlinks
    // Pattern: /var/.jbroot-<hex>
    if let contents = try? FileManager.default.contentsOfDirectory(atPath: "/var") {
      for item in contents where item.hasPrefix(".jbroot-") {
        return (false, "RootHide jailbreak directory detected: /var/\(item)")
      }
    }
    
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
  
  // Pre-computed lowercase suspicious library names for faster comparison
  private static let suspiciousLibrariesLowercase: [String] = [
    // Modern jailbreak hooks
    "systemhook.dylib",      // Dopamine
    "roothideinit.dylib",    // RootHide
    "libellekit.dylib",      // Ellekit (modern tweak injection)
    "libhooker.dylib",       // libhooker
    "libblackjack.dylib",    // Dopamine
    
    // Substrate/Substitute
    "substrateloader.dylib",
    "mobilesubstrate.dylib",
    "tweakinject.dylib",
    "cydiasubstrate",
    "substrateinserter",
    "substratebootstrap",
    "libsubstitute.dylib",
    "substitute",
    
    // SSL/Security bypass
    "sslkillswitch2.dylib",
    "sslkillswitch.dylib",
    
    // Debugging/RE tools
    "fridagadget",
    "frida",
    "libcycript",
    "cycript",
    "cynject",
    
    // Anti-detection bypass tools
    "abypass",
    "flyjb",
    "shadow",
    "liberty",
    "choicy",
    "unsub",
    "vnodebypass",
    "hidejb",
    "/.file",  // HideJB changes paths to "/.file"
    
    // Other suspicious libraries
    "preferenceloader",
    "rocketbootstrap",
    "weeloader",
    "customwidgeticons",
    "cephei",
    "electra",
    "appsyncunified-frontboard.dylib",
    "libhooker"
  ]
  
  private static func checkDYLD() -> CheckResult {
    let imageCount = _dyld_image_count()
    
    for index in 0..<imageCount {
      guard let imageNamePtr = _dyld_get_image_name(index) else { continue }
      let imageName = String(cString: imageNamePtr)
      let imageNameLower = imageName.lowercased()
      
      // Single pass through suspicious libraries with pre-lowercased names
      for library in suspiciousLibrariesLowercase {
        if imageNameLower.contains(library) {
          return (false, "Suspicious library loaded: \(imageName)")
        }
      }
    }
    
    return (true, "")
  }
  
  private static func checkSuspiciousObjCClasses() -> CheckResult {
    // Shadow - popular anti-jailbreak-detection bypass
    if let shadowRulesetClass = objc_getClass("ShadowRuleset") as? NSObject.Type {
      let selector = Selector(("internalDictionary"))
      if class_getInstanceMethod(shadowRulesetClass, selector) != nil {
        return (false, "Shadow anti-anti-jailbreak detector detected")
      }
    }
    
    // Check for other known jailbreak bypass tools
    let suspiciousClasses = [
      "UnSub",           // UnSub bypass tweak
      "Choicy",          // Choicy tweak injection manager
      "Liberty",         // Liberty Lite bypass
      "FlyJB",           // FlyJB bypass
      "ABypass",         // A-Bypass
      "VnodeBypass",     // VnodeBypass
      "HideJB"           // HideJB
    ]
    
    for className in suspiciousClasses {
      if objc_getClass(className) != nil {
        return (false, "Jailbreak bypass tool detected: \(className)")
      }
    }
    
    return (true, "")
  }
}
// swiftlint:enable function_body_length type_body_length
