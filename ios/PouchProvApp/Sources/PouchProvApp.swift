// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

@main
struct PouchProvApp: App {
    var body: some Scene {
        WindowGroup {
            AppRoot()
        }
    }
}

/// Single-screen navigation mirroring the Android `AppRoot`: Settings, the scan
/// list, or the selected device.
struct AppRoot: View {
    @StateObject private var viewModel = AppViewModel()
    @State private var showSettings = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if showSettings {
                        SettingsScreen(viewModel: viewModel)
                    } else if viewModel.selected == nil {
                        ScanScreen(viewModel: viewModel)
                    } else {
                        DeviceScreen(viewModel: viewModel)
                    }
                }
                .padding()
            }
            .navigationTitle(showSettings ? "Settings" : "Pouch Provisioning")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if showSettings {
                    ToolbarItem(placement: .navigationBarLeading) {
                        Button("Back") { showSettings = false }
                    }
                } else {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button("Settings") { showSettings = true }
                    }
                }
            }
        }
    }
}
