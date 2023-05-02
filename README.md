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

The major difference is that Mach Ports are *not* conserved between `fork` calls (besides a few special ports we will examine later in this blogpost).
That raises an important question - how do we share Mach Ports and Port Rights?  
Well, Mach Ports can be registered with a special registry. The special registry is traditionally referred to as the `Bootstrap Port`, and in macOS it's implemented in the `launchd` process (yes, the same process that launches Apps and responsible of Launch Agents and Launch Daemons).  
Just like a DNS server, it maps ports to reverse-DNS notation, so your port can be looked up.  
To communicate with the `Bootstrap Port`, you can either use the `task_get_special_port` API (with the `TASK_BOOTSTRAP_PORT` constant) or refer to a global variable `bootstrap_port`.

With that in mind, here is an example of how to receive and send data:
