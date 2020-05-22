//
// This file is part of Ark Swift Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
//

// swiftlint:disable force_try
// swiftlint:disable force_cast

import Foundation
import BitcoinKit

public class ArkTransaction {

    //新主网修改
    var nonce: UInt64?
    var typeGroup: UInt32?
    
    // Header
    var header: UInt8?
    var version: UInt8?
    var network: UInt8?
    var type: TransactionType?
    var timestamp: UInt32?

    // Types
    var id: String?
    var senderPublicKey: String?
    var recipientId: String?
    var vendorField: String?
    var vendorFieldHex: String?
    var amount: UInt64?
    var fee: UInt64?

    // Signatures
    var signature: String?
    var secondSignature: String?
    var signSignature: String?
    var signatures: [String]?

    var expiration: UInt32?

    var asset: [String: Any]?

    public func getId() -> String {
        return Crypto.sha256(Data(bytes: self.toBytes(skipSignature: false, skipSecondSignature: false))).hex
    }

    // TODO: proper try statement
    public func sign(_ keys: PrivateKey) -> ArkTransaction {
        self.senderPublicKey = keys.publicKey().raw.hex
        let transaction = Crypto.sha256(Data(bytes: self.toBytes()))
        self.signature = try! Crypto.sign(transaction, privateKey: keys).hex
        return self
    }

    // TODO: proper try statement
    public func secondSign(_ keys: PrivateKey) -> ArkTransaction {
        let transaction = Crypto.sha256(Data(bytes: self.toBytes(skipSignature: false)))
        self.signSignature = try! Crypto.sign(transaction, privateKey: keys).hex
        return self
    }

    public func verify() -> Bool {
        let hash = Crypto.sha256(Data(bytes: self.toBytes(skipSignature: true, skipSecondSignature: true)))

        do {
            return try Crypto.verifySignature(Data.init(hex: self.signature!)!,
                                          message: hash,
                                          publicKey: Data.init(hex: self.senderPublicKey!)!)
        } catch {
            return false
        }
    }

    // Needs to pass along the public key of the second signature
    public func secondVerify(publicKey: String) -> Bool {
        let hash = Crypto.sha256(Data(bytes: self.toBytes(skipSignature: false, skipSecondSignature: true)))

        do {
            return try Crypto.verifySignature(Data.init(hex: self.signSignature!)!,
                                              message: hash,
                                              publicKey: Data.init(hex: publicKey)!)
        } catch {
            return false
        }
    }

    public func toBytes(skipSignature: Bool = true, skipSecondSignature: Bool = true) -> [UInt8] {
        //新主网修改
       

        var bytes = [UInt8]()
        /*
        comm部分
        */
        //头部 (写死)
        let p:UInt8 = 0xFF
        bytes.append(p)
        print("ff:",Data(bytes: bytes).hex)
        //version
        bytes.append(self.version!)
        print("version:",Data(bytes: bytes).hex)
        //network
        bytes.append(self.network!)
        print("network:",Data(bytes: bytes).hex)
        //typeGroup
        var typeGroupBytes =  pack(self.typeGroup)
        typeGroupBytes.removeLast()
        bytes.append(contentsOf:typeGroupBytes)
        print("typeGroup:",Data(bytes: bytes).hex)
        //type
        let type = UInt16(self.type!.rawValue)
        bytes.append(contentsOf:pack(type))
        print("type:",Data(bytes: bytes).hex)
        //nonce 暂时写死，待会传进来
        var nonceBytes = pack(self.nonce)
        nonceBytes.removeLast()
        bytes.append(contentsOf:nonceBytes)
        print("nonce:",Data(bytes: bytes).hex)
        //senderPublicKey
        bytes.append(contentsOf: [UInt8](Data.init(hex: self.senderPublicKey!)!))
        print("senderPublicKey:",Data(bytes: bytes).hex)
        //fee
        var feeBytes = pack(self.fee)
        feeBytes.removeLast()
        bytes.append(contentsOf: feeBytes)
        print("fee:",Data(bytes: bytes).hex)
        
        /*
        vendorField部分
        *** 暂时先处理不存在vendorField的部分
        */
        let vendorField:UInt8 = 0
        bytes.append(vendorField)
        print("fee:",Data(bytes: bytes).hex)
        /*
        typeBuffer部分
        */
        //amount
        var amountBytes = pack(self.amount)
        amountBytes.removeLast()
        bytes.append(contentsOf: amountBytes)
        print("amount:",Data(bytes: bytes).hex)
        //expiration
        var expirationBytes = pack(self.expiration)
        expirationBytes.removeLast()
        bytes.append(contentsOf: expirationBytes)
        print("expiration:",Data(bytes: bytes).hex)
        //recipientId
        let recipientIdBytes = base58CheckDecode(recipientId!)!
        bytes.append(contentsOf: recipientIdBytes)
        print("recipientId:",Data(bytes: bytes).hex)
        
        let leftBytesCount = 33-amountBytes.count-expirationBytes.count -  recipientIdBytes.count;
        if (leftBytesCount>0) {
            bytes.append(contentsOf: [UInt8](repeating: 0, count: leftBytesCount))
        }
        
        print("result:",Data(bytes: bytes).hex)
        
        return bytes
    }

    public func toDict() -> [String: Any] {
        var transactionDict: [String: Any] = [:]
        if let amount = self.amount {
            transactionDict["amount"] = amount
        }
        if let fee = self.fee {
            transactionDict["fee"] = fee
        }
        if let asset = self.asset {
            transactionDict["asset"] = asset
        }
        if let id = self.id {
            transactionDict["id"] = id
        }
        if let network = self.network {
            transactionDict["network"] = network
        }
        if let recipientId = self.recipientId {
            transactionDict["recipientId"] = recipientId
        }
        if let secondSignature = self.secondSignature {
            transactionDict["secondSignature"] = secondSignature
        }
        if let senderPublicKey = self.senderPublicKey {
            transactionDict["senderPublicKey"] = senderPublicKey
        }
        if let signature = self.signature {
            transactionDict["signature"] = signature
        }
        if let signatures = self.signatures {
            transactionDict["signatures"] = signatures
        }
        if let signSignature = self.signSignature {
            transactionDict["signSignature"] = signSignature
        }
        //新主网修改
//        if let timestamp = self.timestamp {
//            transactionDict["timestamp"] = timestamp
//        }
        if let type = self.type {
            transactionDict["type"] = type.rawValue
        }
        if let vendorField = self.vendorField {
            transactionDict["vendorField"] = vendorField
        }
        if let vendorFieldHex = self.vendorFieldHex {
            transactionDict["vendorFieldHex"] = vendorFieldHex
        }
        if let version = self.version {
            transactionDict["version"] = version
        }
        if let expiration = self.expiration {
            transactionDict["expiration"] = expiration
        }
        if let nonce = self.nonce {
            transactionDict["nonce"] = nonce
        }
        if let typeGroup = self.typeGroup {
            transactionDict["typeGroup"] = typeGroup
        }
        
        

        return transactionDict
    }

    public func toJson() -> String? {
        let txDict = self.toDict()

        do {
            // Serialize as json Data
            let jsonData = try JSONSerialization.data(withJSONObject: txDict, options: [])

            // Turn it into a String
            return String(data: jsonData, encoding: .ascii)
        } catch {
            print(error.localizedDescription)
            return nil
        }
    }
}
