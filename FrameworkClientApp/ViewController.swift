//
//  ViewController.swift
//  FrameworkClientApp
//
//  Created by wregula on 23/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//
//swiftlint:disable line_length

import UIKit
import IOSSecuritySuite

class RuntimeClass {
   @objc dynamic func runtimeModifiedFunction()-> Int {
       return 1
   }
}

internal class ViewController: UIViewController {

    override func viewDidAppear(_ animated: Bool) {
        //Runtime Check
        let test = RuntimeClass.init()
        test.runtimeModifiedFunction()
        let dylds = ["UIKit"]
        let amIRuntimeHooked = IOSSecuritySuite.amIRuntimeHooked(dyldWhiteList: dylds, detectionClass: RuntimeClass.self, selector: #selector(RuntimeClass.runtimeModifiedFunction), isClassMethod: false)
        //MSHook Check
        func msHookReturnFalse(takes: Int) -> Bool {
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
        Reversed?: \(IOSSecuritySuite.amIReverseEngineered())
        Am I MSHooked: \(IOSSecuritySuite.amIMSHooked(funcAddr))
        Am I runtime hooked: \(amIRuntimeHooked)
        """
        
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Dismiss", style: .default))

        print("FailMessage: \(message)")
        present(alert, animated: false)

        let checks = IOSSecuritySuite.amIJailbrokenWithFailedChecks()
        print("The failed checks are: \(checks)")
    }
}
