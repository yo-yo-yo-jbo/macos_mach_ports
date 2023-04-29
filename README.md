# Introduction to macOS - Mach Ports
In previous blogposts, we discussed several security mechanisms of macOS:
- We discussed how `Entitlements` effectively create another security layer.
- We mentioned `SIP` and how it seperates the system from the root user.
- We discussed the `macOS App Sandbox` and how it can enforce policies on processes.
- We mentioned `Gatekeeper` and the Quarantine Extended Attributes.

There are other mechanisms we haven't touched (`TCC`, for instance) but today I'd like to discuss one of the fundamental mechanisms - Mach Ports.  
As you might have known, the macOS Kernel is some sort of a fusion between BSD and Mach, which leads to many interesting differences in APIs and even terminology sometimes (e.g. `tasks` vs. `processes`).  
You might know several "traditional" `Inter-process communication (IPC)` mechanisms, such as `pipes`, `sockets`, `shared memory` and so on... Well, `Mach` has `Mach Ports`. Those are the building blocks of more higher-level IPC mechanisms (e.g. `MIG`, `XPC`).

## Port Rights
Mach Ports are (kind of) equivalent to one-directional pipes. Tasks and the kernel can enqueue and dequeue messages via a *port right*.  
Each Mach Port can have one `Receiver` and multiple `Senders`, hence there are several types of `Port Rights`:
- `Receive Right`: allows receiving messages, held by the "owner" of the Mach Port. As I mentioned, there is only one receive right for every port in the entire system.
- `Send Right`: allows sending messages to the port.
- `Send-Once Right`: allows a one-time sending right and then disappears.
- `Port Set Right`: allows referring to a set of ports rather than a single port, similarly to how APIs like `select` work in POSIX.
- `Dead Name`: a placeholder for Port Rights that cannot receive anymore (`Dead Ports`).

Port Rights are referred in userland by `Port Right Names`, which are just integers similarly to how `file descriptors` or `HANDLEs` are used in Linux or Windows:
```c
typedef mach_port_t int;
```

## Using the API
You can easily use the `mach_msg` API to use Mach Ports.
