//
//  FailedChecks.swift
//  IOSSecuritySuite
//
//  Created by im on 06/02/23.
//  Copyright © 2023 wregula. All rights reserved.
//

import Foundation

/// Tuple with check (``FailedCheck``) and failMessage (String)
public typealias FailedCheckType = (check: FailedCheck, failMessage: String)

/// A list of possible checks made by this library
public enum FailedCheck: CaseIterable {
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
