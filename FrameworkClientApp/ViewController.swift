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
    
    func testHookPrint() {
        typealias MyPrint = @convention(thin) (Any..., String, String) ->Void
        func myPrint(_ items: Any..., separator: String = " ", terminator: String = "\n") {
            NSLog("print has been hooked")
        }
        let myprint: MyPrint = myPrint
        let myPrintPointer = unsafeBitCast(myprint, to: UnsafeMutableRawPointer.self)
        var oldMethod: UnsafeMutableRawPointer?
        
        // hook
        replaceSymbol("$ss5print_9separator10terminatoryypd_S2StF", newMethod: myPrintPointer, oldMethod: &oldMethod)
        print("print hasn't been hooked")
        
        // antiHook
        IOSSecuritySuite.denySymbolHook("$ss5print_9separator10terminatoryypd_S2StF")
        print("print has been antiHooked")
    }

    override func viewDidAppear(_ animated: Bool) {
//        testHookPrint()
        
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
        Am I proxied: \(IOSSecuritySuite.amIProxied())
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
