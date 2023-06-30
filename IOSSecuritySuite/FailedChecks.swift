//
//  FailedChecks.swift
//  IOSSecuritySuite
//
//  Created by im on 06/02/23.
//  Copyright © 2023 wregula. All rights reserved.
//
// swiftlint:disable trailing_whitespace

import Foundation

public typealias FailedCheckType = (check: FailedCheck, failMessage: String)

public enum FailedCheck: CaseIterable {
    
    /**
     Need to implement allCases to conform to CaseIterable when built by
     Xcode 13.4.1, in order to be compatible with Xcode 14.x
     */
    public static var allCases: [FailedCheck] {
        return [
            .urlSchemes,
            .existenceOfSuspiciousFiles,
            .suspiciousFilesCanBeOpened,
            .restrictedDirectoriesWriteable,
            .fork,
            .symbolicLinks,
            .dyld,
            .openedPorts,
            .pSelectFlag,
            .suspiciousObjCClasses
        ]
    }

    case urlSchemes
    case existenceOfSuspiciousFiles
    case suspiciousFilesCanBeOpened
    case restrictedDirectoriesWriteable
    case fork
    case symbolicLinks
    case dyld
    case openedPorts
    case pSelectFlag
    case suspiciousObjCClasses
}
