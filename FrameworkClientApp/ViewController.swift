//
//  ViewController.swift
//  FrameworkClientApp
//
//  Created by wregula on 23/04/2019.
//  Copyright © 2019 wregula. All rights reserved.
//

import UIKit
import IOSSecuritySuite

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()

    }

    override func viewDidAppear(_ animated: Bool) {
    
        let jailbreakStatus = IOSSecuritySuite.amIJailbrokenWithFailMessage()
        let title = jailbreakStatus.jailbroken ? "Jailbroken" : "Jailed"
        let message = """
        Jailbreak: \(jailbreakStatus.failMessage),
        Run in emulator?: \(IOSSecuritySuite.amIRunInEmulator())
        Debugged?: \(IOSSecuritySuite.amIDebugged())
        Reversed?: \(IOSSecuritySuite.amIReverseEngineered())
        """
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Dismiss", style: .default))
        
        print("TEST: \(message)")
        self.present(alert, animated: false)
    }
}
