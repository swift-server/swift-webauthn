//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2023 the WebAuthn Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// An internal type to assist kicking off work without primarily awaiting it, instead allowing that work to call into a continuation as needed.
/// Use ``withCancellableFirstSuccessfulContinuation()`` instead of invoking this directly.
actor CancellableContinuation<T: Sendable>: Sendable {
    private var bodyTask: Task<Void, Error>?
    private var continuation: CheckedContinuation<T, Error>?
    private var isCancelled = false
    
    private func cancelMainTask() {
        continuation?.resume(throwing: CancellationError())
        continuation = nil
        bodyTask?.cancel()
        isCancelled = true
    }
    
    private func isolatedResume(returning value: T) {
        continuation?.resume(returning: value)
        continuation = nil
        cancelMainTask()
    }
    
    nonisolated func cancel() {
        Task { await cancelMainTask() }
    }
    
    nonisolated func resume(returning value: T) {
        Task { await isolatedResume(returning: value) }
    }
    
    /// Wrap an asynchronous closure providing a continuation for when results are ready that can be called any number of times, but also allowing the closure to be cancelled at any time, including once the first successful value is provided.
    fileprivate func wrap(_ body: Body) async throws -> T {
        assert(bodyTask == nil, "A CancellableContinuationTask should only be used once.")
        /// Register a cancellation callback that will: a) immediately cancel the continuation if we have one, b) unset it so it doesn't get called a second time, and c) cancel the main task.
        return try await withTaskCancellationHandler {
            let response: T = try await withCheckedThrowingContinuation { localContinuation in
                /// Synchronously a) check if we've been cancelled, stopping early, b) save the contnuation, and c) assign the task, which runs immediately.
                /// This works since we are guaranteed to hear back from the cancellation handler either immediately, since Task.isCancelled is already set, or after task is set, since we are executing on the actor's executor.
                guard !Task.isCancelled else {
                    localContinuation.resume(throwing: CancellationError())
                    return
                }
                
                self.continuation = localContinuation
                self.bodyTask = Task { [unowned self] in
                    /// If the continuation doesn't exist at this point, it's because we've already been cancelled. This is guaranteed to run after the task has been set and potentially cancelled since it also runs on the task executor.
                    guard let continuation = self.continuation else { return }
                    do {
                        try await body(self)
                    } catch {
                        /// If the main body fails for any reason, pass along the error. This will be a no-op if the continuation was already resumed or cancelled.
                        continuation.resume(throwing: error)
                        self.continuation = nil
                    }
                }
            }
            /// Wait for the body to finish cancelling before continuing, so it doesn't run into any data races.
            try? await bodyTask?.value
            return response
        } onCancel: {
            cancel()
        }
    }
    
    /// A wrapper for the body, which will ever only be called once, in a non-escaping manner before the continuation resumes.
    fileprivate struct Body: @unchecked Sendable {
        var body: (_ continuation: CancellableContinuation<T>) async throws -> ()
        
        func callAsFunction(_ continuation: CancellableContinuation<T>) async throws {
            try await body(continuation)
        }
    }
}

/// Execute an operation providing it a continuation for when results are ready that can be called any number of times, but also allowing the operation to be cancelled at any time, including once the first successful value is provided.
func withCancellableFirstSuccessfulContinuation<T: Sendable>(_ body: (_ continuation: CancellableContinuation<T>) async throws -> ()) async throws -> T {
    try await withoutActuallyEscaping(body) { escapingBody in
        try await CancellableContinuation().wrap(.init { try await escapingBody($0) })
    }
}
