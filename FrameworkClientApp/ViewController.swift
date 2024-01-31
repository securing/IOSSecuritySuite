//
//  ViewController.swift
//  FrameworkClientApp
//
//  Created by wregula on 23/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//

import UIKit
import IOSSecuritySuite

class RuntimeClass {
  @objc dynamic func runtimeModifiedFunction() -> Int {
    return 1
  }
}

internal class ViewController: UIViewController {
  @IBOutlet weak var result: UITextView!
  
  override func viewDidAppear(_ animated: Bool) {
    var message = ""
    
#if arch(arm64)
    message += executeChecksForArm64()
#endif
    
    // Runtime Check
    let test = RuntimeClass.init()
    _ = test.runtimeModifiedFunction()
    let dylds = ["UIKit"]
    let amIRuntimeHooked = IOSSecuritySuite.amIRuntimeHooked(
      dyldAllowList: dylds,
      detectionClass: RuntimeClass.self,
      selector: #selector(RuntimeClass.runtimeModifiedFunction),
      isClassMethod: false
    )
    
    message += """
        Jailbreak? \(IOSSecuritySuite.amIJailbroken())
        Jailbreak with fail msg? \(IOSSecuritySuite.amIJailbrokenWithFailMessage())
        Jailbreak with failedChecks? \(IOSSecuritySuite.amIJailbrokenWithFailedChecks())
        Run in emulator? \(IOSSecuritySuite.amIRunInEmulator())
        Debugged? \(IOSSecuritySuite.amIDebugged())
        Unexpected Launcher? \(IOSSecuritySuite.isParentPidUnexpected())
        Am I tempered with? \(IOSSecuritySuite.amITampered(
        [.bundleID("biz.securing.FrameworkClientApp")])
        )
        Reversed? \(IOSSecuritySuite.amIReverseEngineered())
        Reversed with failedChecks? \(IOSSecuritySuite.amIReverseEngineeredWithFailedChecks())
        Am I runtime hooked? \(amIRuntimeHooked)
        Am I proxied? \(IOSSecuritySuite.amIProxied())
        """
    
    result.text = message
  }
}

#if arch(arm64)
extension ViewController {
  func executeChecksForArm64() -> String {
    // executeAntiHook()
    
    // MSHook Check
    func msHookReturnFalse(takes: Int) -> Bool {
      return false /// add breakpoint at here to test `IOSSecuritySuite.hasBreakpointAt`
    }
    
    typealias FunctionType = @convention(thin) (Int) -> (Bool)
    func getSwiftFunctionAddr(_ function: @escaping FunctionType) -> UnsafeMutableRawPointer {
      return unsafeBitCast(function, to: UnsafeMutableRawPointer.self)
    }
    
    let funcAddr = getSwiftFunctionAddr(msHookReturnFalse)
    
    return """
        Am I MSHooked? \(IOSSecuritySuite.amIMSHooked(funcAddr))
        Application executable file hash value? \(IOSSecuritySuite.getMachOFileHashValue() ?? "")
        IOSSecuritySuite executable file hash value? \(
        IOSSecuritySuite.getMachOFileHashValue(.custom("IOSSecuritySuite")) ?? ""
        )
        Loaded libs? \(IOSSecuritySuite.findLoadedDylibs() ?? [])
        HasBreakpoint? \(IOSSecuritySuite.hasBreakpointAt(funcAddr, functionSize: nil))
        Watchpoint? \(testWatchpoint())
        """
  }
  
  func testWatchpoint() -> Bool {
    
//    Uncomment these \/ and set a watch point to check the feature
//    var ptr = malloc(9)
//    var count = 3
    return IOSSecuritySuite.hasWatchpoint()
  }
  
  func executeAntiHook() {
    typealias MyPrint = @convention(thin) (Any..., String, String) -> Void
    func myPrint(_ items: Any..., separator: String = " ", terminator: String = "\n") {
      print("print has been hooked")
    }
    
    let myprint: MyPrint = myPrint
    let myPrintPointer = unsafeBitCast(myprint, to: UnsafeMutableRawPointer.self)
    var oldMethod: UnsafeMutableRawPointer?
    
    // simulating hook
    replaceSymbol(
      "$ss5print_9separator10terminatoryypd_S2StF",
      newMethod: myPrintPointer,
      oldMethod: &oldMethod
    )
    
    print("print hasn't been hooked")
    
    // antiHook
    IOSSecuritySuite.denySymbolHook("$ss5print_9separator10terminatoryypd_S2StF")
    print("print has been antiHooked")
  }
}
#endif
