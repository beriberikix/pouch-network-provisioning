// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

struct SettingsScreen: View {
    @ObservedObject var viewModel: AppViewModel

    @State private var showKey = false
    @State private var daysText = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // MARK: Golioth
            Text("Golioth")
                .font(.headline)

            HStack {
                Group {
                    if showKey {
                        TextField("Project API key", text: apiKeyBinding)
                    } else {
                        SecureField("Project API key", text: apiKeyBinding)
                    }
                }
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)

                Button(showKey ? "Hide" : "Show") { showKey.toggle() }
                    .font(.footnote)
            }
            Text("Used to register a temporary CA when minting device certificates.")
                .font(.footnote)
                .foregroundStyle(.secondary)

            // MARK: Certificate
            Text("Certificate")
                .font(.headline)
                .padding(.top, 24)

            TextField("Expiration (days from creation)", text: $daysText)
                .textFieldStyle(.roundedBorder)
                .keyboardType(.numberPad)
                .onChange(of: daysText) { input in
                    let filtered = String(input.filter(\.isNumber).prefix(4))
                    if filtered != input { daysText = filtered }
                    if let days = Int(filtered) { viewModel.setCertValidityDays(days) }
                }

            Text("A certificate generated today would expire \(expiryText).")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .onAppear {
            daysText = String(viewModel.certValidityDays)
        }
    }

    private var apiKeyBinding: Binding<String> {
        Binding(
            get: { viewModel.goliothApiKey },
            set: { viewModel.setGoliothApiKey($0) }
        )
    }

    private var expiryText: String {
        let expiry = Calendar.current.date(
            byAdding: .day,
            value: viewModel.certValidityDays,
            to: Date()
        ) ?? Date()
        return expiry.formatted(date: .numeric, time: .omitted)
    }
}
