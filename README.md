# Introduction to macOS - Mach Ports
In previous blogposts, we discussed several security mechanisms of macOS:
- We discussed how `Entitlements` effectively create another security layer.
- We mentioned `SIP` and how it seperates the system from the root user.
- We discussed the `macOS App Sandbox` and how it can enforce policies on processes.
- We mentioned `Gatekeeper` and the Quarantine Extended Attributes.

There are other mechanisms we haven't touched (`TCC`, for instance) but today I'd like to discuss one of the fundamental mechanisms - Mach Ports.  
As you might have known, the macOS Kernel is some sort of a fusion between BSD and Mach, which leads to many interesting differences in APIs and even terminology sometimes (e.g. `tasks` vs. `processes`).  
You might know several "traditional" `Inter-process communication (IPC)` mechanisms, such as `pipes`, `sockets`, `shared memory` and so on... Well, `Mach` has `Mach Ports`. Those are the building blocks of more higher-level IPC mechanisms (e.g. `MIG`, `XPC`).
