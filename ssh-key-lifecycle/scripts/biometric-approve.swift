// macOS-only: verify Touch ID in a separate process. No fallback to device password.
import Foundation
import LocalAuthentication
import Dispatch
import Darwin

let reason = CommandLine.arguments.count == 2 ? CommandLine.arguments[1] : ""
guard !reason.isEmpty && reason.utf8.count < 1024 else { exit(3) }
let context = LAContext()
context.localizedFallbackTitle = ""
var error: NSError?
guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else { exit(3) }
let wait = DispatchSemaphore(value: 0)
var approved = false
context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, _ in
    approved = success
    wait.signal()
}
if wait.wait(timeout: .now() + .seconds(540)) == .timedOut {
    context.invalidate()
    exit(3)
}
exit(approved ? 0 : 3)
