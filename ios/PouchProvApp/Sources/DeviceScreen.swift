// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import PouchProvBLE
import PouchProvCore
import SwiftUI
import UniformTypeIdentifiers

/// How the device credential is obtained.
private enum CertMode: String, CaseIterable {
    case golioth = "Golioth"
    case selfSigned = "Self-signed"
    case upload = "Upload"
}

struct DeviceScreen: View {
    @ObservedObject var viewModel: AppViewModel

    var body: some View {
        if let device = viewModel.selected {
            VStack(alignment: .leading, spacing: 0) {
                // Header
                HStack(alignment: .center) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(device.name ?? "(unnamed)")
                            .font(.title2.bold())
                        Text(device.identifier.uuidString)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Back") { viewModel.back() }
                }

                if viewModel.connecting {
                    ConnectingCard()
                } else if let error = viewModel.connectError {
                    ConnectErrorCard(message: error) {
                        viewModel.select(device)
                    }
                } else if let info = viewModel.version {
                    DeviceInfoCard(info: info)
                    if viewModel.provisioning {
                        ProvisionProgress(
                            state: viewModel.provisionState,
                            onDone: { viewModel.back() },
                            onAgain: { viewModel.resetProvision() }
                        )
                    } else {
                        ProvisionForm(
                            viewModel: viewModel,
                            info: info,
                            defaultCn: device.name ?? device.identifier.uuidString
                        )
                    }
                }
            }
        }
    }
}

private struct CardBackground: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(.secondarySystemBackground))
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .padding(.top, 16)
    }
}

private struct ConnectingCard: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                ProgressView()
                Text("Connecting & pairing…")
            }
            Text("If prompted, accept the pairing request on your iPhone.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .modifier(CardBackground())
    }
}

private struct ConnectErrorCard: View {
    let message: String
    let onRetry: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Couldn't connect")
                .font(.headline)
            Text(message)
                .font(.footnote)
            // iOS has no API to remove a bond — the Android app's
            // "Forget & re-pair" becomes a manual step here.
            Text("If pairing failed, forget the device in Settings → Bluetooth and try again.")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Button("Retry", action: onRetry)
                .buttonStyle(.borderedProminent)
                .padding(.top, 4)
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.red.opacity(0.12))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .padding(.top, 16)
    }
}

private struct DeviceInfoCard: View {
    let info: VersionInfo

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Device")
                .font(.headline)
            Text("protocol v\(info.proto) · lib \(info.lib) · block \(info.blockSize) B")
                .font(.footnote)
                .foregroundStyle(.secondary)
            HStack(spacing: 8) {
                let caps = info.caps.isEmpty ? ["none"] : info.caps
                ForEach(caps, id: \.self) { cap in
                    CapChip(text: cap)
                }
            }
            if info.popRequired {
                CapChip(text: "PoP required")
            }
        }
        .modifier(CardBackground())
    }
}

private struct CapChip: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.footnote)
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(Capsule().strokeBorder(.secondary))
    }
}

private struct ProvisionForm: View {
    @ObservedObject var viewModel: AppViewModel
    let info: VersionInfo
    let defaultCn: String

    @State private var pop = ""
    @State private var ssid = ""
    @State private var password = ""
    @State private var certMode: CertMode = .selfSigned
    @State private var cn = ""
    @State private var cert: Data?
    @State private var key: Data?
    @State private var ca: Data?

    @State private var pickingCert = false
    @State private var pickingKey = false
    @State private var pickingCa = false

    private var hasCred: Bool { info.hasCap("cred") }
    private var hasWifi: Bool { info.hasCap("wifi") }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if info.popRequired {
                TextField("Proof-of-possession", text: $pop)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
            }

            if hasCred {
                SectionTitle("Cloud credentials")
                Picker("Credential source", selection: $certMode) {
                    ForEach(CertMode.allCases, id: \.self) { mode in
                        Text(mode.rawValue).tag(mode)
                    }
                }
                .pickerStyle(.segmented)

                if certMode == .upload {
                    HStack(spacing: 8) {
                        Button(cert != nil ? "Cert ✓" : "Cert") { pickingCert = true }
                            .buttonStyle(.bordered)
                            .fileImporter(isPresented: $pickingCert, allowedContentTypes: [.item]) {
                                cert = Self.readFile($0)
                            }
                        Button(key != nil ? "Key ✓" : "Key") { pickingKey = true }
                            .buttonStyle(.bordered)
                            .fileImporter(isPresented: $pickingKey, allowedContentTypes: [.item]) {
                                key = Self.readFile($0)
                            }
                        Button(ca != nil ? "CA ✓" : "CA") { pickingCa = true }
                            .buttonStyle(.bordered)
                            .fileImporter(isPresented: $pickingCa, allowedContentTypes: [.item]) {
                                ca = Self.readFile($0)
                            }
                    }
                    .padding(.top, 4)
                } else {
                    TextField("Device ID (certificate CN)", text: $cn)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)

                    HStack(spacing: 8) {
                        Button {
                            if certMode == .golioth {
                                viewModel.mintGoliothCert(commonName: cn)
                            } else {
                                viewModel.generateCert(commonName: cn)
                            }
                        } label: {
                            Text(viewModel.generating
                                ? "Working…"
                                : certMode == .golioth ? "Mint from Golioth" : "Generate certificate")
                        }
                        .buttonStyle(.bordered)
                        .disabled(viewModel.generating)

                        if viewModel.generating {
                            ProgressView()
                        }
                        if let generatedCn = viewModel.generatedCn {
                            Text("Ready ✓ CN=\(generatedCn)")
                                .font(.footnote)
                        }
                    }

                    Text(certNote)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    if let error = viewModel.certError {
                        Text("Error: \(error)")
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                }
            }

            if hasWifi {
                SectionTitle("Wi-Fi")
                HStack(spacing: 8) {
                    Button(viewModel.wifiScanning ? "Scanning…" : "Scan networks") {
                        viewModel.scanWifi(pop: pop)
                    }
                    .buttonStyle(.bordered)
                    .disabled(viewModel.wifiScanning)
                    if viewModel.wifiScanning {
                        ProgressView()
                    }
                }
                if let error = viewModel.wifiError {
                    Text("Scan failed: \(error)")
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
                if let networks = viewModel.wifiNetworks {
                    SsidPicker(networks: networks) { ssid = $0 }
                }
                TextField("SSID", text: $ssid)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                SecureField("Wi-Fi password", text: $password)
                    .textFieldStyle(.roundedBorder)
            }

            if !hasCred && !hasWifi {
                Text("This device advertises no provisionable capabilities. You can still end the provisioning session.")
                    .padding(.top, 8)
            }

            Button {
                let generated = (hasCred && certMode != .upload) ? viewModel.generatedCredentials() : nil
                viewModel.provision(
                    pop: pop,
                    ssid: hasWifi ? ssid : nil,
                    password: hasWifi ? password : nil,
                    cert: generated?.cert ?? cert,
                    key: generated?.key ?? key,
                    ca: (hasCred && certMode == .upload) ? ca : nil
                )
            } label: {
                Text(!hasCred && !hasWifi ? "Finish" : "Provision")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .padding(.top, 16)
        }
        .padding(.top, 12)
        .onAppear {
            if cn.isEmpty { cn = defaultCn }
            if certMode == .selfSigned && !viewModel.goliothApiKey.isEmpty {
                certMode = .golioth
            }
        }
    }

    private var certNote: String {
        if certMode == .golioth {
            if viewModel.goliothApiKey.isEmpty {
                return "Set a Golioth API key in Settings to mint."
            }
            return "Registers a demo CA and signs a device cert · valid \(viewModel.certValidityDays) days."
        }
        return "Self-signed · valid \(viewModel.certValidityDays) days (change in Settings)."
    }

    private static func readFile(_ result: Result<URL, Error>) -> Data? {
        guard let url = try? result.get() else { return nil }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        return try? Data(contentsOf: url)
    }
}

private struct SsidPicker: View {
    let networks: [ScanEntry]
    let onSelect: (String) -> Void

    var body: some View {
        Menu {
            ForEach(Array(networks.enumerated()), id: \.offset) { _, entry in
                let name = String(decoding: entry.ssid, as: UTF8.self)
                Button(name.isEmpty ? "(hidden)" : "\(name)   \(entry.rssi) dBm") {
                    onSelect(name)
                }
            }
        } label: {
            HStack {
                Text("Discovered networks (\(networks.count))")
                Spacer()
                Image(systemName: "chevron.up.chevron.down")
            }
            .padding(10)
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(.secondary))
        }
        .padding(.top, 4)
    }
}

private struct ProvisionProgress: View {
    let state: ProvisionState
    let onDone: () -> Void
    let onAgain: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            switch state {
            case .done(let result):
                Text("Provisioned ✓")
                    .font(.headline)
                    .foregroundStyle(.green)
                if result.credentialsStored {
                    Text("Cloud credentials stored.")
                }
                if let wifi = result.wifi {
                    Text("Wi-Fi: \(String(describing: wifi.state))")
                }
                if !result.credentialsStored && result.wifi == nil {
                    Text("Session ended.")
                }
                Button("Done", action: onDone)
                    .buttonStyle(.borderedProminent)
                    .padding(.top, 8)
            case .failed(let message):
                Text("Provisioning failed")
                    .font(.headline)
                    .foregroundStyle(.red)
                Text(message)
                    .font(.footnote)
                Button("Try again", action: onAgain)
                    .buttonStyle(.borderedProminent)
                    .padding(.top, 8)
            default:
                HStack(spacing: 12) {
                    ProgressView()
                    Text(stepLabel)
                }
            }
        }
        .modifier(CardBackground())
    }

    private var stepLabel: String {
        switch state {
        case .idle: return "Preparing…"
        case .connecting: return "Connecting…"
        case .querying: return "Reading device version…"
        case .authorizing: return "Authorizing (proof-of-possession)…"
        case .pushingCredentials: return "Pushing credentials…"
        case .configuringWifi(let status):
            if let status { return "Wi-Fi: \(String(describing: status.state))" }
            return "Configuring Wi-Fi…"
        case .finishing: return "Finishing…"
        default: return "Working…"
        }
    }
}

private struct SectionTitle: View {
    let text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(text)
            .font(.subheadline.bold())
            .padding(.top, 16)
    }
}
