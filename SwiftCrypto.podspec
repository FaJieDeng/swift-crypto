Pod::Spec.new do |s|
  s.name = 'SwiftCrypto'
  s.version = '0.2.2'
  s.license = 'MIT'
  s.summary = 'A simple Cryptography Implementation in Swift for the ARK Blockchain'
  s.homepage = 'https://github.com/ArkEcosystem/swift-crypto'
  s.authors = { 'Ark Ecosystem' => 'info@ark.io' }
  s.source = { :git => 'https://github.com/ArkEcosystem/swift-crypto.git', :tag => s.version }

  s.ios.deployment_target = '10.0'

  s.dependency = {'BitcoinKit', :git => 'https://github.com/FaJieDeng/BitcoinKit.git', :tag => 'v1.1.1-dfj'}


  s.source_files = 'Crypto/Crypto/**/*.swift'
end
