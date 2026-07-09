// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation
import SwiftASN1
import X509

/// TOFU server-certificate exchange and saead session setup. A port of the
/// CLI's `tofu.py` / Kotlin `Tofu`.
///
/// On saead firmware builds the pouch GATT service exposes three extra SAR
/// endpoints (raw payloads, not pouch-framed): `info` (device sender, CBOR
/// `{flags, server_cert_snr}`), `server_cert` (device receiver — we SAR-write
/// our self-signed server cert when the stored serial differs), and
/// `device_cert` (device sender — its self-signed identity cert, collected
/// trust-on-first-use). The exchanged public keys drive the ECDH session-key
/// derivation in ``Saead``.
public enum Tofu {

    /// The pouch GATT info payload: `{flags, server_cert_snr}`.
    public struct GattInfo: Equatable, Sendable {
        public let flags: Int
        public let serverCertSerial: Data

        public var hasServerCert: Bool { !serverCertSerial.isEmpty }

        public init(flags: Int, serverCertSerial: Data) {
            self.flags = flags
            self.serverCertSerial = serverCertSerial
        }

        public static func decode(_ data: Data) throws -> GattInfo {
            guard let obj = try Cbor.decode(data).mapValue else {
                throw Pouch.DecodeException("bad gatt info")
            }
            var flags = 0
            var serial = Data()
            for pair in obj {
                if pair.key.textValue == "flags" { flags = pair.value.intValue ?? 0 }
                if pair.key.textValue == "server_cert_snr" { serial = pair.value.bytesValue ?? Data() }
            }
            return GattInfo(flags: flags, serverCertSerial: serial)
        }
    }

    /// The client's pouch "server" identity: a P-256 key pair + self-signed cert.
    public struct ServerIdentity: Sendable {
        public let privateKey: P256.KeyAgreement.PrivateKey
        public let certDer: Data

        public init(privateKey: P256.KeyAgreement.PrivateKey, certDer: Data) {
            self.privateKey = privateKey
            self.certDer = certDer
        }

        /// First 6 bytes of SHA-256(cert DER), per pouch cert_ref.
        public var certRef: Data {
            Data(SHA256.hash(data: certDer).prefix(Saead.certRefLen))
        }
    }

    /// Generate a fresh self-signed server identity (reuses ``DeviceCert``).
    public static func generateServerIdentity(commonName: String = "pouchprov-ios") throws -> ServerIdentity {
        let creds = try DeviceCert.generateSelfSigned(commonName: commonName, validityDays: 3650)
        let signing = try DeviceCert.loadPrivateKey(creds.privateKeyPem)
        let agreement = try P256.KeyAgreement.PrivateKey(rawRepresentation: signing.rawRepresentation)
        return ServerIdentity(privateKey: agreement, certDer: try Pem.toDer(creds.certificatePem))
    }

    /// Strip leading zero bytes: mbedtls keeps the DER sign byte, most big-int
    /// serializations do not. Normalized forms compare equal.
    public static func normalizeSerial(_ serial: Data) -> Data {
        let stripped = serial.drop(while: { $0 == 0 })
        return stripped.isEmpty ? Data([0]) : Data(stripped)
    }

    /// The X.509 serial number bytes of a DER certificate.
    public static func certSerial(_ certDer: Data) throws -> Data {
        let cert = try Certificate(derEncoded: [UInt8](certDer))
        return Data(cert.serialNumber.bytes)
    }

    /// Extract the P-256 public key from a device certificate (DER).
    public static func devicePublicKey(_ certDer: Data) throws -> P256.KeyAgreement.PublicKey {
        let cert = try Certificate(derEncoded: [UInt8](certDer))
        guard let signing = P256.Signing.PublicKey(cert.publicKey) else {
            throw Saead.SaeadError("device certificate is not a P-256 key")
        }
        return try P256.KeyAgreement.PublicKey(x963Representation: signing.x963Representation)
    }

    /// One SAR receive cycle on a device-sender endpoint (info, device_cert).
    public static func sarRead(_ channel: any ProvChannel, timeoutMs: Int64 = 15_000) async throws -> Data {
        let receiver = SarReceiver(write: { try await channel.write($0) })
        try await channel.subscribe { receiver.feed($0) }
        do {
            let data = try await receiver.receive(timeoutMs: timeoutMs)
            await channel.unsubscribe()
            return data
        } catch {
            await channel.unsubscribe()
            throw error
        }
    }

    /// One SAR send cycle on a device-receiver endpoint (server_cert).
    public static func sarWrite(
        _ channel: any ProvChannel, data: Data, maxlen: Int, timeoutMs: Int64 = 15_000
    ) async throws {
        let sender = SarSender(write: { try await channel.write($0) }, maxlen: maxlen)
        try await channel.subscribe { sender.feed($0) }
        do {
            try await sender.send(data, timeoutMs: timeoutMs)
            await channel.unsubscribe()
        } catch {
            await channel.unsubscribe()
            throw error
        }
    }

    /// Read the pouch GATT info endpoint (a SAR cycle, not a GATT read).
    public static func readInfo(_ transport: any ProvTransport, timeoutMs: Int64 = 15_000) async throws -> GattInfo {
        guard let channel = transport.info else { throw Saead.SaeadError("no info endpoint") }
        return try GattInfo.decode(try await sarRead(channel, timeoutMs: timeoutMs))
    }

    /// Run the TOFU cert exchange; returns the device certificate (DER). Pushes
    /// our server certificate only when the device's stored serial differs from
    /// ours (or it has none).
    public static func exchangeCerts(
        _ transport: any ProvTransport,
        identity: ServerIdentity,
        maxlen: Int,
        timeoutMs: Int64 = 15_000
    ) async throws -> Data {
        let info = try await readInfo(transport, timeoutMs: timeoutMs)
        let ours = normalizeSerial(try certSerial(identity.certDer))
        let theirs = normalizeSerial(info.serverCertSerial)
        if !info.hasServerCert || theirs != ours {
            guard let channel = transport.serverCert else { throw Saead.SaeadError("no server-cert endpoint") }
            try await sarWrite(channel, data: identity.certDer, maxlen: maxlen, timeoutMs: timeoutMs)
        }
        guard let channel = transport.deviceCert else { throw Saead.SaeadError("no device-cert endpoint") }
        return try await sarRead(channel, timeoutMs: timeoutMs)
    }

    /// TOFU exchange + build the ``SaeadSession`` keyed to the device.
    public static func secureSession(
        _ transport: any ProvTransport,
        identity: ServerIdentity,
        maxlen: Int,
        timeoutMs: Int64 = 15_000
    ) async throws -> SaeadSession {
        let deviceDer = try await exchangeCerts(transport, identity: identity, maxlen: maxlen, timeoutMs: timeoutMs)
        return SaeadSession(
            serverPrivate: identity.privateKey,
            devicePublic: try devicePublicKey(deviceDer),
            serverCertRef: identity.certRef
        )
    }
}
