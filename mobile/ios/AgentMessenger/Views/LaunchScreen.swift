import SwiftUI

/// Launch screen shown while the app is loading.
struct LaunchScreen: View {
    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "bubble.left.and.bubble.right.fill")
                .font(.system(size: 72))
                .foregroundStyle(.tint)

            Text("Agent Messenger")
                .font(.title)
                .fontWeight(.bold)

            ProgressView()
        }
    }
}

#Preview {
    LaunchScreen()
}