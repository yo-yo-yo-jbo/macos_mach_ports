# Introduction to macOS - Mach Ports
In previous blogposts, we discussed several security mechanisms of macOS:
- We discussed how `Entitlements` effectively create another security layer.
- We mentioned `SIP` and how it seperates the system from the root user.
- We discussed the `macOS App Sandbox` and how it can enforce policies on processes.
- We mentioned `Gatekeeper` and the Quarantine Extended Attributes.

There are other mechanisms we haven't touched (`TCC`, for instance) but today I'd like to discuss one of the fundamental mechanisms - Mach Ports.  
As you might have known, the macOS Kernel is some sort of a fusion between BSD and Mach, which leads to many interesting differences in APIs and even terminology sometimes (e.g. `tasks` vs. `processes`).  
You might know several "traditional" `Inter-process communication (IPC)` mechanisms, such as `pipes`, `sockets`, `shared memory` and so on... Well, `Mach` has `Mach Ports`. Those are the building blocks of more higher-level IPC mechanisms (e.g. `MIG`, `XPC`).

## Port Rights and the Bootstrap Port
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
```c
#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

#define CLOSE_PORT(port)                do                                                        \
                                        {                                                         \
                                            if (MACH_PORT_NULL != (port))                         \
                                            {                                                     \
                                                mach_port_deallocate(mach_task_self(), port);     \
                                                (port) = MACH_PORT_NULL;                          \
                                            }                                                     \
                                        } while (false)

#define REGISTERED_NAME ("com.jbo.poc")

typedef struct
{
    mach_msg_header_t header;
    int some_number;
    char some_string[10];
} custom_message_t;

typedef struct
{
    custom_message_t body;
    mach_msg_trailer_t trailer;
} custom_message_recv_t;

static
bool
send_routine(
    int number,
    char* text
)
{
    bool result = false;
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = KERN_SUCCESS;
    custom_message_t msg = { 0 };

    // Lookup the port from the bootstrap server
    kr = bootstrap_look_up(bootstrap_port, REGISTERED_NAME, &port);
    if (KERN_SUCCESS != kr)
    {
        printf("[!] bootstrap_look_up() failed: 0x%.8x\n", kr);
        goto cleanup;
    }

    // Construct the message header
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_remote_port = port;
    msg.header.msgh_local_port = MACH_PORT_NULL;

    // Construct the contents
    msg.some_number = number;
    strncpy(msg.some_string, text, sizeof(msg.some_string));

    // Send the message
    kr = mach_msg(&(msg.header), MACH_SEND_MSG, sizeof(msg), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (KERN_SUCCESS != kr)
    {
        printf("[!] mach_msg() failed: 0x%.8x\n", kr);
        goto cleanup;
    }

    // Success
    result = true;

cleanup:

    // Free resources
    CLOSE_PORT(port);

    // Return result
    return result;
}

static
bool
receive_routine(void)
{
    bool result = false;
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = KERN_SUCCESS;
    custom_message_recv_t msg = { 0 };

    // Create a new port
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (KERN_SUCCESS != kr)
    {
        printf("[!] mach_port_allocate() failed: 0x%.8x\n", kr);
        goto cleanup;
    }

    // Add send rights
    kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (KERN_SUCCESS != kr)
    {
        printf("[!] mach_port_insert_right() failed: 0x%.8x\n", kr);
        goto cleanup;
    }

    // Register the port with the bootstrap server
    kr = bootstrap_register(bootstrap_port, REGISTERED_NAME, port);
    if (KERN_SUCCESS != kr)
    {
        printf("[!] bootstrap_register() failed: 0x%.8x\n", kr);
        goto cleanup;
    }

    // Wait for a message
    printf("[+] Waiting for a message.\n");
    kr = mach_msg(&(msg.body.header), MACH_RCV_MSG, 0, sizeof(msg), port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (KERN_SUCCESS != kr)
    {
        printf("[!] mach_msg() failed: 0x%.8x\n", kr);
        goto cleanup;
    }

    // Print the message fields
    printf("[+] Got message, some_number=%d, some_string=%s\n", msg.body.some_number, msg.body.some_string);
    
    // Success
    result = true;

cleanup:

    // Free resources
    CLOSE_PORT(port);

    // Return result
    return result;
}

int
main(
    int argc,
    char** argv
)
{
    bool result = false;

    // Handle receiver
    if (argc < 3)
    {
        printf("[+] Starting receiver.\n");
        result = receive_routine(); 
    }
    else
    {
        printf("[+] Starting sender.\n");
        result = send_routine(atoi(argv[1]), argv[2]);
    }

    // Indicate result
    return result ? 0 : -1;
}
```

This will either run a receiver or a sender, based on the number of arguments. Here's a demonstration:
```shell
jbo@McJbo ~ % gcc -Wno-deprecated -omach_demo ./mach_demo.c
jbo@McJbo ~ % ./mach_demo &
[1] 40558
jbo@McJbo ~ % [+] Starting receiver.
[+] Waiting for a message.

jbo@McJbo ~ % ./mach_demo 42 Muhaha
[+] Starting sender.
[+] Got message, some_number=42, some_string=Muhaha
[1]  + done       ./mach_demo
jbo@McJbo mach_fun %
```

