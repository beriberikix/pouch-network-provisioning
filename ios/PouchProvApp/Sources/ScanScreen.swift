// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import PouchProvBLE
import SwiftUI

struct ScanScreen: View {
    @ObservedObject var viewModel: AppViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Button {
                viewModel.startScan()
            } label: {
                Text(viewModel.scanning ? "Scanning…" : "Scan for devices")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(viewModel.scanning)

            Toggle("Include devices not in provisioning mode", isOn: $viewModel.scanAll)
                .font(.callout)
                .disabled(viewModel.scanning)

            if let error = viewModel.scanError {
                Text("Scan failed: \(error)")
                    .font(.footnote)
                    .foregroundStyle(.red)
            }

            if viewModel.scanning && viewModel.devices.isEmpty {
                HStack {
                    Spacer()
                    ProgressView()
                    Spacer()
                }
                .padding(.top, 24)
            }

            if !viewModel.scanning && viewModel.devices.isEmpty {
                Text("No provisioning devices found yet. Make sure the device is powered and advertising, then scan.")
                    .font(.body)
                    .padding(.top, 8)
            }

            LazyVStack(spacing: 8) {
                ForEach(viewModel.devices) { device in
                    DeviceRow(device: device) {
                        viewModel.select(device)
                    }
                }
            }
        }
    }
}

private struct DeviceRow: View {
    let device: PouchProvDevice
    let onTap: () -> Void

    var body: some View {
        Button(action: onTap) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(device.name ?? "(unnamed)")
                        .font(.headline)
                        .lineLimit(1)
                    Text(device.identifier.uuidString)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    if !device.provisioning {
                        Text("pouch (not provisioning)")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Text("\(device.rssi) dBm")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            .padding()
            .background(Color(.secondarySystemBackground))
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
        .buttonStyle(.plain)
        .disabled(!device.provisioning)
    }
}
