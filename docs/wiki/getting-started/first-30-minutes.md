# Your first 30 minutes

First boot has finished and the console shows the router's ports, the web
console's address and a generated password. This page takes you from
there to a router you can trust with your network.

## 1. Open the web console

From a computer on the LAN (it gets an address from the router by DHCP),
open the address shown on the console, for example:

```
https://10.73.1.1/
```

The router makes its own self-signed TLS certificate on first start, so
the browser warns that it does not know the certificate. That is expected
for a device on your own network: accept it for this address. The
certificate is valid for the router's hostname and its LAN addresses.

The web console listens only on the router's addresses in its management
zones (by default every zone that is not the internet), on TCP 443.

## 2. Sign in and set up your account

Sign in with the username `admin` and the password from the console. You
are taken straight to a setup step, and nothing else is reachable until you
finish it:

- **Choose your own username.** `admin`, `administrator`, `root`, `user`,
  `fr_os` and `fros` are refused: they are the first names attackers try.
  A username is lower-case letters, digits, `_`, `.` and `-`, up to 32
  characters, starting with a letter or `_`.
- **Choose your own password.** At least 12 characters, not one of the
  most common passwords, not repetitive, and not containing the username.
  The generated password is refused.

When you finish, the generated account and password stop working at once,
and the password disappears from the machine's console.

## 3. Add a second factor

Open **Account**, then **Second factor**, and add one or both:

- **An authenticator app (TOTP):** scan the QR code with any TOTP app and
  type the current code to confirm.
- **A security key or passkey (WebAuthn):** a hardware key or your
  device's built-in passkey.

Once every administrator has a second factor, turn on **Require a second
factor for admins** under **Users**. From then on an administrator
without one is sent to enrol before doing anything else.

## 4. Segment your network (optional, recommended)

After setup the console opens the **Segments** screen. With one click it
adds two VLANs on the LAN port, each with its own subnet, DHCP pool and
zone, and rules that let it reach the internet and nothing else:

| Segment | VLAN | Network |
| --- | --- | --- |
| IoT devices (`iot`) | 30 | `192.168.30.1/24` |
| Guests (`guest`) | 40 | `192.168.40.1/24` |

Your switch or access point must tag these VLANs for the devices you put
on them. If you don't have VLAN-capable equipment, skip this step: IoT
isolation (on by default) still keeps detected IoT devices away from the
rest of the LAN.

## 5. Make your first change, safely

Try the change workflow on something harmless before you depend on it:

1. Confirmation is on by default: an apply waits 300 seconds for you to
   confirm it. The time is the `management.confirm_apply_seconds` key in
   the configuration (0 turns it off, otherwise 60 to 3600 seconds).
2. Make a small change, for example a DHCP reservation for your computer
   under **DHCP**, and press **Apply now** on the dashboard.
3. A banner on every page shows that the apply waits. Press **Confirm**
   while you can still reach the console.
4. Do it once more and do **not** confirm: when the time runs out, the
   router goes back to the previous configuration on its own. The banner
   then offers **Load it to fix it**, which makes the rejected
   configuration the saved one again, without applying it, so you can
   correct it on the screens and apply once more.

Read [Applying changes safely](../concepts/apply-and-rollback.md) to see
exactly what happens at each step.

## 6. Check the basics

| Check | How |
| --- | --- |
| A LAN client gets an address | It is in the DHCP pool, and listed under **DHCP**. |
| DNS works | The client can resolve names. |
| The internet works | The client can open a web page. |
| Nothing is open from the WAN | **Attack surface** shows what listens and from which zones it is reachable. Nothing should be reachable from `wan`. |
| The settings survive a reboot | Reboot the router from its console and sign in again. If the settings are gone, see [persistence](installation.md#persistence). |

## 7. Read your security score

The **Security score** screen runs a checklist against the running router
and links each item to the screen that fixes it:

- no account with a default name;
- a second factor for every administrator;
- a valid configuration;
- management closed to the internet;
- up to date, and security updates installing themselves;
- no any-to-any, internet-wide or shadowed rules;
- firewall drops logged;
- devices segmented, or IoT isolation on;
- nothing unneeded listening.

Each item names the security requirement it comes from, so you can read
why it matters.

## 8. Give others read-only access

If someone else should see the dashboard but not change anything, create
an account with the **viewer** role under **Users**. A viewer can see every
screen and change only their own password and second factors.

## Next

- Learn how FR_OS decides what passes: [Zones and segments](../concepts/zones.md).
- Understand the configuration file: [The configuration file](../concepts/configuration-file.md).
