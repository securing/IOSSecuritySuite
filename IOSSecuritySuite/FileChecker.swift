//
//  MountedVolumes.swift
//  IOSSecuritySuite
//
//  Created by Mario Sepulveda on 6/29/23.
//  Copyright © 2023 wregula. All rights reserved.
//
// swiftlint:disable trailing_whitespace

import Foundation

internal class FileChecker {
    typealias CheckResult = (passed: Bool, failMessage: String)
        
    /**
     Used to store some information provided by statfs()
     */
    struct MountedVolumeInfo {
        let fileSystemName: String
        let directoryName: String
        let isRoot: Bool
        let isReadOnly: Bool
    }
    
    /**
     Used to determine if a file access check should be in Write or Read-Only mode.
     */
    enum FileMode {
        case readable
        case writable
    }
    
    /**
     Given a path, this method provides information about the associated volume.
     - Parameters:
     - path: path is the pathname of any file within the mounted file system.
     - Returns: Returns nil, if statfs() gives a non-zero result.
     */
    private static func getMountedVolumeInfoViaStatfs(path: String,
                                                      encoding: String.Encoding = .utf8) -> MountedVolumeInfo? {
        guard let path: [CChar] = path.cString(using: encoding) else {
            assertionFailure("Failed to create a cString with path=\(path) encoding=\(encoding)")
            return nil
        }
        
        var statBuffer = statfs()
        /**
         Upon successful completion, the value 0 is returned; otherwise the
         value -1 is returned and the global variable errno is set to indicate
         the error.
         */
        let resultCode: Int32 = statfs(path, &statBuffer)
        
        if resultCode == 0 {
            let mntFromName: String = withUnsafePointer(to: statBuffer.f_mntfromname) { ptr -> String in
                return String(cString: UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self))
            }
            let mntOnName: String = withUnsafePointer(to: statBuffer.f_mntonname) { ptr -> String in
                return String(cString: UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self))
            }
            
            return MountedVolumeInfo(fileSystemName: mntFromName,
                                     directoryName: mntOnName,
                                     isRoot: (Int32(statBuffer.f_flags) & MNT_ROOTFS) != 0,
                                     isReadOnly: (Int32(statBuffer.f_flags) & MNT_RDONLY) != 0)
        } else {
            return nil
        }
    }
    
    /**
     This method provides information about all mounted volumes.
     - Returns: Returns nil, if getfsstat() does not return any filesystem statistics.
     */
    private static func getMountedVolumesViaGetfsstat() -> [MountedVolumeInfo]? {
        // If buf is NULL, getfsstat() returns just the number of mounted file systems.
        let count: Int32 = getfsstat(nil, 0, MNT_NOWAIT)
        
        guard count >= 0 else {
            assertionFailure("getfsstat() failed to return the number of mounted file systems.")
            return nil
        }
        
        var statBuffer: [statfs] = .init(repeating: .init(), count: Int(count))
        let size: Int = MemoryLayout<statfs>.size * statBuffer.count
        /**
         Upon successful completion, the number of statfs structures is
         returned. Otherwise, -1 is returned and the global variable errno is
         set to indicate the error.
         */
        let resultCode: Int32 = getfsstat(&statBuffer, Int32(size), MNT_NOWAIT)
        
        if resultCode > -1 {
            if count != resultCode {
                assertionFailure("Unexpected a resultCode=\(resultCode), was expecting=\(count).")
            }
            
            var result: [MountedVolumeInfo] = []
            
            for entry: statfs in statBuffer {
                let mntFromName: String = withUnsafePointer(to: entry.f_mntfromname) { ptr -> String in
                    return String(cString: UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self))
                }
                let mntOnName: String = withUnsafePointer(to: entry.f_mntonname) { ptr -> String in
                    return String(cString: UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self))
                }
                
                let info = MountedVolumeInfo(fileSystemName: mntFromName,
                                             directoryName: mntOnName,
                                             isRoot: (Int32(entry.f_flags) & MNT_ROOTFS) != 0,
                                             isReadOnly: (Int32(entry.f_flags) & MNT_RDONLY) != 0)
                result.append(info)
            }
            
            if count != result.count {
                assertionFailure("Unexpected filesystems count=\(result.count), was expecting=\(count).")
            }
            
            return result
        } else {
            assertionFailure("getfsstat() failed. resultCode=\(resultCode), expected count=\(count) filesystems.")
            return nil
        }
    }
    
    /**
     Loops through the mounted volumes provided by Getfsstat() and searches for a match.
     - Parameters:
     - name: The filesystem name or mounted directory name to search for.
     - Returns: Returns nil, if a matching mounted volume is not found.
     */
    private static func getMountedVolumesViaGetfsstat(withName name: String) -> MountedVolumeInfo? {
        if let list = getMountedVolumesViaGetfsstat() {
            if list.count == 0 {
                assertionFailure("Expected to a non-empty list of mounted volumes.")
            } else {
                return list.first(where: { $0.directoryName == name || $0.fileSystemName == name })
            }
        } else {
            assertionFailure("Expected a non-nil list of mounted volumes.")
        }
        return nil
    }
    
    /**
     Uses fopen() to check if an file exists and attempts to open it, in either Read-Only or Read-Write mode.
     - Parameters:
     - path: The file path to open.
     - mode: Determines if the file will be opened in Writable or Read-Only mode.
     - returns: Returns nil, if the file does not exist. Returns true if it can be opened with the given mode.
     */
    static func checkExistenceOfSuspiciousFilesViaFOpen(path: String,
                                                        mode: FileMode) -> CheckResult? {
        // the 'a' or 'w' modes, create the file if it does not exist.
        let mode: String = FileMode.writable == mode ? "r+" : "r"
        
        if let filePointer: UnsafeMutablePointer<FILE> = fopen(path, mode) {
            fclose(filePointer)
            return (false, "Suspicious file exists: \(path)")
        } else {
            return nil
        }
    }
    
    /**
     Uses stat() to check if a file exists.
     - returns: Returns nil, if stat() returns a non-zero result code.
     */
    static func checkExistenceOfSuspiciousFilesViaStat(path: String) -> CheckResult? {
        var statbuf: stat = stat()
        let resultCode = stat((path as NSString).fileSystemRepresentation, &statbuf)
        
        if resultCode == 0 {
            return (false, "Suspicious file exists: \(path)")
        } else {
            return nil
        }
    }
    
    /**
     Uses access() to check whether the calling process can access the file path, in either Read-Only or Write mode.
     - Parameters:
     - path: The file path to open.
     - mode: Determines if the file will be accessed in Write mode or Read-Only mode.
     - returns: Returns nil, if access() returns a non-zero result code.
     */
    static func checkExistenceOfSuspiciousFilesViaAccess(path: String,
                                                         mode: FileMode) -> CheckResult? {
        let resultCode = access((path as NSString).fileSystemRepresentation, FileMode.writable == mode ? W_OK : R_OK)
        
        if resultCode == 0 {
            return (false, "Suspicious file exists: \(path)")
        } else {
            return nil
        }
    }
    
    /**
     Checks if statvfs() considers the given path to be Read-Only.
     - Returns: Returns nil, if statvfs() gives a non-zero result.
     */
    static func checkRestrictedPathIsReadonlyViaStatvfs(path: String,
                                                        encoding: String.Encoding = .utf8) -> Bool? {
        guard let path: [CChar] = path.cString(using: encoding) else {
            assertionFailure("Failed to create a cString with path=\(path) encoding=\(encoding)")
            return nil
        }
        
        var statBuffer = statvfs()
        let resultCode: Int32 = statvfs(path, &statBuffer)
        
        if resultCode == 0 {
            return Int32(statBuffer.f_flag) & ST_RDONLY != 0
        } else {
            return nil
        }
    }
    
    /**
     Checks if statvs() considers the volume associated with given path to be Read-Only.
     - Returns: Returns nil, if statfs() does not find the mounted volume.
     */
    static func checkRestrictedPathIsReadonlyViaStatfs(path: String,
                                                       encoding: String.Encoding = .utf8) -> Bool? {
        return getMountedVolumeInfoViaStatfs(path: path, encoding: encoding)?.isReadOnly
    }
    
    /**
     Checks if Getfsstat() considers the volume to be Read-Only.
     - Parameters:
     - name: The filesystem name or mounted directory name to search for.
     - Returns: Returns nil, if a matching mounted volume is not found.
     */
    static func checkRestrictedPathIsReadonlyViaGetfsstat(name: String) -> Bool? {
        return self.getMountedVolumesViaGetfsstat(withName: name)?.isReadOnly
    }
}
