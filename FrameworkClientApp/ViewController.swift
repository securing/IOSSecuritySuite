//
//  ViewController.swift
//  FrameworkClientApp
//
//  Created by wregula on 23/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//
//swiftlint:disable all

import UIKit
import IOSSecuritySuite

class RuntimeClass {
   @objc dynamic func runtimeModifiedFunction()-> Int {
       return 1
   }
}

internal class ViewController: UIViewController {

    override func viewDidAppear(_ animated: Bool) {
        // Runtime Check
        let test = RuntimeClass.init()
        test.runtimeModifiedFunction()
        let dylds = ["UIKit"]
        let amIRuntimeHooked = IOSSecuritySuite.amIRuntimeHooked(dyldWhiteList: dylds, detectionClass: RuntimeClass.self, selector: #selector(RuntimeClass.runtimeModifiedFunction), isClassMethod: false)
        // MSHook Check
        func msHookReturnFalse(takes: Int) -> Bool {
            /// add breakpoint at here to test `IOSSecuritySuite.hasBreakpointAt`
            return false
        }
        typealias FunctionType = @convention(thin) (Int) -> (Bool)
        func getSwiftFunctionAddr(_ function: @escaping FunctionType) -> UnsafeMutableRawPointer {
            return unsafeBitCast(function, to: UnsafeMutableRawPointer.self)
        }
        let funcAddr = getSwiftFunctionAddr(msHookReturnFalse)

        let jailbreakStatus = IOSSecuritySuite.amIJailbrokenWithFailMessage()
        let title = jailbreakStatus.jailbroken ? "Jailbroken" : "Jailed"
        let message = """
        Jailbreak: \(jailbreakStatus.failMessage),
        Run in emulator?: \(IOSSecuritySuite.amIRunInEmulator())
        Debugged?: \(IOSSecuritySuite.amIDebugged())
        HasBreakpoint?: \(IOSSecuritySuite.hasBreakpointAt(funcAddr, functionSize: nil))
        Reversed?: \(IOSSecuritySuite.amIReverseEngineered())
        Am I MSHooked: \(IOSSecuritySuite.amIMSHooked(funcAddr))
        Am I runtime hooked: \(amIRuntimeHooked)
        Am I tempered with: \(IOSSecuritySuite.amITampered([.bundleID("biz.securing.FrameworkClientApp")]).result)
        Application executable file hash value: \(IOSSecuritySuite.getMachOFileHashValue() ?? "")
        IOSSecuritySuite executable file hash value: \(IOSSecuritySuite.getMachOFileHashValue(.custom("IOSSecuritySuite")) ?? "")
        """
        
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Dismiss", style: .default))

        print("FailMessage: \(message)")
        present(alert, animated: false)

        let checks = IOSSecuritySuite.amIJailbrokenWithFailedChecks()
        print("The failed checks are: \(checks)")
        
#if arch(arm64)
        print("Loaded libs: \(IOSSecuritySuite.findLoadedDylibs() ?? [])")
#endif
    }
}
