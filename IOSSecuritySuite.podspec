Pod::Spec.new do |s|
  s.name         = "IOSSecuritySuite"
  s.version      = "2.0.2"
  s.summary      = "iOS platform security & anti-tampering Swift library"
  s.homepage     = "https://github.com/securing/IOSSecuritySuite"
  s.license      = "custom EULA"
  s.author       = "Wojciech Reguła"
  s.social_media_url = "https://x.com/_r3ggi"
  s.platform     = :ios, "12.0"
  s.ios.frameworks = 'UIKit', 'Foundation'
  s.source       = { :git => "https://github.com/securing/IOSSecuritySuite.git", :tag => "#{s.version}" }
  s.source_files  = "IOSSecuritySuite/*.swift"
  s.resource_bundles = {'IOSSecuritySuitePrivacy' => ['IOSSecuritySuite/Resources/PrivacyInfo.xcprivacy']}
  s.swift_version = '5.0'
  s.requires_arc = true
  s.pod_target_xcconfig = { 'SWIFT_VERSION' => '5.0' }
end
