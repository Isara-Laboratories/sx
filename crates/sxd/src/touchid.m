// Objective-C shim bridging Rust to macOS LocalAuthentication.
//
// Exposes one synchronous function: present the system authentication sheet
// (TouchID, Apple Watch, or password fallback) and block until the user
// responds. Compiled by build.rs with -fobjc-arc and linked against the
// LocalAuthentication and Foundation frameworks.

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>

// Returns:
//    1  -> user authenticated
//    0  -> user cancelled or authentication failed
//   -1  -> policy cannot be evaluated (e.g. no device passcode set);
//          the caller should fall back to another gate.
int sx_touchid_authenticate(const char *reason) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];

        // Biometrics when available, otherwise the device passcode/password.
        // This still presents a real human checkpoint on Macs without TouchID.
        LAPolicy policy = LAPolicyDeviceOwnerAuthentication;

        NSError *canError = nil;
        if (![context canEvaluatePolicy:policy error:&canError]) {
            return -1;
        }

        NSString *localizedReason =
            (reason != NULL) ? [NSString stringWithUTF8String:reason] : @"authorize a secret";
        if (localizedReason == nil || localizedReason.length == 0) {
            localizedReason = @"authorize a secret";
        }

        // evaluatePolicy is asynchronous; block this thread on a semaphore
        // until the completion handler fires. The daemon serves connections
        // serially, so blocking here is fine.
        dispatch_semaphore_t sema = dispatch_semaphore_create(0);
        __block BOOL approved = NO;

        [context evaluatePolicy:policy
                localizedReason:localizedReason
                          reply:^(BOOL success, NSError *_Nullable evalError) {
                            (void)evalError;
                            approved = success;
                            dispatch_semaphore_signal(sema);
                          }];

        dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
        return approved ? 1 : 0;
    }
}
