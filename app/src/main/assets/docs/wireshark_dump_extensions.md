# How to Display KotSafe Dump Extensions in Wireshark

This tutorial provides complete step-by-step instructions on enabling **KotSafe Dump Extensions** on Android and displaying application names, Android UIDs, package identifiers, and decrypted TLS streams directly inside **Wireshark**.

---

## 📑 Table of Contents
1. [What are KotSafe Dump Extensions?](#1-what-are-kotsafe-dump-extensions)
2. [How KotSafe Embeds Metadata into Packet Captures](#2-how-kotsafe-embeds-metadata-into-packet-captures)
3. [Step 1: Enabling Dump Extensions in KotSafe](#3-step-1-enabling-dump-extensions-in-kotsafe)
4. [Step 2: Exporting Captures (File or Live Streaming)](#4-step-2-exporting-captures-file-or-live-streaming)
5. [Step 3: Native Wireshark Inspection (Zero Plugins Needed)](#5-step-3-native-wireshark-inspection-zero-plugins-needed)
6. [Step 4: Installing the KotSafe Wireshark Lua Dissector](#6-step-4-installing-the-kotsafe-wireshark-lua-dissector)
7. [Step 5: Configuring Custom Wireshark Columns & Filters](#7-step-5-configuring-custom-wireshark-columns--filters)
8. [Automatic TLS Decryption via DSB Blocks](#8-automatic-tls-decryption-via-dsb-blocks)
9. [Complete KotSafe Lua Dissector Source Code](#9-complete-kotsafe-lua-dissector-source-code)
10. [Troubleshooting & FAQs](#10-troubleshooting--faqs)

---

## 1. What are KotSafe Dump Extensions?

Standard network capture engines (tcpdump, standard PCAP) only capture Network Layer (L3) and Transport Layer (L4) packet headers and payloads. Because mobile operating systems multiplex hundreds of apps over a single network interface, a standard PCAP file **cannot tell you which Android app sent or received a packet**:

```
Standard PCAP:    [ IP Header ] [ TCP Header ] [ Payload ] ──> Unknown App / Process
KotSafe PCAPNG:   [ IP Header ] [ TCP Header ] [ Payload ] + [ UID 10185 ] [ com.whatsapp ] [ "WhatsApp" ]
```

**KotSafe Dump Extensions** resolve this by tagging every packet with Android process metadata:
* **Linux UID** (User ID, e.g., `10185`)
* **Package Name** (e.g., `com.whatsapp`, `com.google.android.youtube`)
* **App Label** (e.g., `WhatsApp`, `YouTube`, `Chrome`)
* **Interface & Direction** (Inbound vs Outbound)
* **TLS Decryption Secrets** (Zero-configuration SSL/TLS keylog blocks for live HTTPS decryption)

---

## 2. How KotSafe Embeds Metadata into Packet Captures

KotSafe supports two file formats for traffic dumping:

### Format A: PCAPNG (Recommended)
PCAPNG (Next Generation Packet Capture) is an extensible block-based format:
1. **Section Header Block (SHB)**: Embeds device hardware model, Android OS version, and KotSafe engine version.
2. **Custom Blocks (Type `0x00000BAD`)**: Uses KotSafe's Private Enterprise Number (PEN `62652`) to define a `UID Mapping Block`. It maps each UID to its Android Package Name and human-readable App Name once per session.
3. **Enhanced Packet Blocks (EPB)**: Each packet carries option `0x0001` (`opt_comment`) formatted as `u-<UID>` (e.g. `u-10185`), requiring minimal overhead.
4. **Decryption Secrets Block (DSB, Type `0x0000000A`)**: Embeds TLS key secrets (`TLSKeyLog`) so Wireshark can automatically decrypt HTTPS traffic without manual key files!

### Format B: Legacy PCAP Trailer
When saving as legacy PCAP:
* KotSafe prepends a synthetic Ethernet header and appends a 32-byte Ethernet trailer containing Magic `0x01072021`, the 32-bit UID, and a 20-byte App Name string.

---

## 3. Step 1: Enabling Dump Extensions in KotSafe

1. Open **KotSafe** on your Android device.
2. Navigate to **Settings** (tap the gear icon or Settings tab).
3. Scroll down to **Traffic Inspection & PCAP Dumps**.
4. Enable **PCAPng format**: Ensure the toggle is switched **ON** (checked).
5. Enable **KotSafe extensions**: Toggle the switch **ON** (checked).
   * *Summary displayed*: "Extend packet dump format with additional metadata, such as the app that sent/received a packet".
6. *(Optional for HTTPS Decryption)*: Under **Security & TLS**, enable **TLS Decryption (SSL Keylog)**.

```
┌────────────────────────────────────────────────────────┐
│  Traffic Inspection & PCAP Dumps                       │
├────────────────────────────────────────────────────────┤
│  [x] PCAPng format                                     │
│      Use next-generation capture format                │
│                                                        │
│  [x] KotSafe extensions                                │
│      Include App name, UID, and process metadata       │
└────────────────────────────────────────────────────────┘
```

---

## 4. Step 2: Exporting Captures (File or Live Streaming)

### Option 1: File Export
1. Return to the **Status** tab and tap **Start**.
2. Run the applications you wish to analyze on your device.
3. Tap **Stop** in KotSafe.
4. A prompt will appear allowing you to save or share the capture file (e.g., `KotSafe_20260924_1630.pcapng`).
5. Transfer the `.pcapng` file to your PC via USB, ADB, Google Drive, or email.

### Option 2: Live Streaming to Wireshark via UDP / PCAP-over-IP
1. In KotSafe **Settings** ➔ **Streaming, Proxies & Mesh**, enable **PCAP Live Streamer**.
2. Select **UDP** or **TCP server** mode and specify your PC's IP and port (e.g., `192.168.1.50:12345`).
3. On your PC, run Wireshark or `nc -u -l -p 12345 | wireshark -k -i -`.

---

## 5. Step 3: Native Wireshark Inspection (Zero Plugins Needed)

Even without installing any plugins, Wireshark natively reads KotSafe's PCAPng comments:

1. Launch **Wireshark** (v3.0 or later).
2. Open the exported `KotSafe_*.pcapng` file (`File ➔ Open`).
3. Click on any packet in the **Packet List**.
4. In the middle **Packet Details** pane, expand **Frame**.
5. Look at **Packet Comments**: You will see `u-10185` (where `10185` is the Android App UID)!
6. You can filter packets by UID using standard Wireshark display filters:
   ```
   frame.comment contains "u-10185"
   ```

---

## 6. Step 4: Installing the KotSafe Wireshark Lua Dissector

To automatically resolve `u-10185` into human-readable names like `"WhatsApp"` or `"com.whatsapp"` and display them in their own dedicated columns, install the **KotSafe Lua Dissector**:

### Plugin Installation Locations:

| Operating System | Target Folder Path |
| :--- | :--- |
| **Linux** | `~/.local/lib/wireshark/plugins/` or `~/.config/wireshark/plugins/` |
| **Windows** | `%APPDATA%\Wireshark\plugins\` (e.g., `C:\Users\<User>\AppData\Roaming\Wireshark\plugins\`) |
| **macOS** | `~/.config/wireshark/plugins/` or `/Applications/Wireshark.app/Contents/PlugIns/wireshark/` |

### Installation Steps:
1. Locate your Wireshark personal plugins directory:
   * In Wireshark, click **Help** ➔ **About Wireshark** ➔ **Folders** tab.
   * Double-click the link next to **Personal Lua Plugins**.
2. Copy the file [`tools/kotsafe.lua`](../tools/kotsafe.lua) from this repository into that plugins directory.
3. Reload Lua plugins in Wireshark by pressing:
   * **Linux/Windows**: `Ctrl + Shift + L`
   * **macOS**: `Cmd + Shift + L`
   *(Or simply restart Wireshark)*.

---

## 7. Step 5: Configuring Custom Wireshark Columns & Filters

Once the Lua dissector is loaded, Wireshark gains full awareness of KotSafe metadata!

### Adding Custom Columns for App Name & Package:
1. In Wireshark, right-click any column header (e.g., *No.* or *Time*) and click **Column Preferences**.
2. Click the **+** (Add) button at the bottom of the list.
3. Set the column properties:
   * **Title**: `App Name`
   * **Type**: `Custom`
   * **Fields**: `kotsafe.appname`
4. Click **+** again to add the package name:
   * **Title**: `Package`
   * **Type**: `Custom`
   * **Fields**: `kotsafe.packagename`
5. Click **OK**.
6. **Result**: Your Wireshark packet list now clearly displays which Android app generated every packet!

### Powerful Display Filters:
Filter your entire capture by application name, package, or UID:
```wireshark
# View all traffic generated by WhatsApp
kotsafe.appname == "WhatsApp"

# View traffic from Google Chrome or YouTube
kotsafe.packagename matches "chrome|youtube"

# View all traffic except system services
kotsafe.uid >= 10000

# View DNS queries made by a specific app
dns and kotsafe.appname == "Telegram"
```

---

## 8. Automatic TLS Decryption via DSB Blocks

When **TLS Decryption** is enabled in KotSafe alongside PCAPng dump format:
1. KotSafe writes **Decryption Secrets Blocks (DSB)** containing SSL session keys directly into the `.pcapng` file.
2. When you open the capture file in Wireshark (version 3.0+), Wireshark detects the embedded TLS keys and **automatically decrypts HTTPS payloads**!
3. You will see green **HTTP/2**, **HTTP**, and unencrypted JSON/REST APIs in the packet list without having to configure `SSLKEYLOGFILE` in Wireshark preferences.

---

## 9. Complete KotSafe Lua Dissector Source Code

You can also copy the Lua plugin code directly below and save it as `kotsafe.lua`:

```lua
--
--  KotSafe Wireshark Lua Dissector Plugin
--  Dissects KotSafe PCAP / PCAPng dump extensions (App Name, Package Name, UID)
--

kotsafe_proto = Proto("KotSafe", "KotSafe Mobile Security Data")

local KOTSAFE_PCAP_MAGIC = 0x01072021
local KOTSAFE_TRAILER_SIZE = 32
local KOTSAFE_PEN = 62652

local block_types = {
  [1] = "UID Mapping",
}

local f = {}
f.magic          = ProtoField.uint32("kotsafe.magic", "Magic", base.HEX)
f.block_ver      = ProtoField.int32("kotsafe.block_version", "Block version", base.DEC)
f.block_type     = ProtoField.int32("kotsafe.block_type", "Block type", base.DEC, block_types)
f.uid            = ProtoField.int32("kotsafe.uid", "UID", base.DEC)
f.appname        = ProtoField.string("kotsafe.appname", "App Name", base.UNICODE)
f.appname_len    = ProtoField.uint8("kotsafe.appname_len", "App Name Length", base.DEC)
f.packagename    = ProtoField.string("kotsafe.packagename", "Package Name", base.UNICODE)
f.packagename_len= ProtoField.uint8("kotsafe.packagename_len", "Package Name Length", base.DEC)

kotsafe_proto.fields = f

local pen_field = Field.new("frame.cb_pen")
local comment_field = Field.new("frame.comment")
local uid_map = {}

local function dissect_pcap_trailer(buffer, pinfo, tree)
  local length = buffer:len()
  if length < KOTSAFE_TRAILER_SIZE then return false end

  local trailer = buffer(length - KOTSAFE_TRAILER_SIZE, KOTSAFE_TRAILER_SIZE - 4)
  local magic = trailer(0, 4):uint()
  if magic ~= KOTSAFE_PCAP_MAGIC then return false end

  local appname = string.gsub(trailer(8, 20):raw(), "%z.*", "")
  local uid_val = trailer(4, 4):int()

  local subtree = tree:add(kotsafe_proto, buffer(), string.format("KotSafe Metadata: App [%s], UID [%d]", appname, uid_val))
  subtree:add(f.magic, trailer(0, 4))
  subtree:add(f.uid, trailer(4, 4))
  subtree:add(f.appname, appname)
  pinfo.cols.info:append(string.format(" [KotSafe: %s]", appname))
  return true
end

local function dissect_pcapng(buffer, pinfo, tree)
  local pen_fields = { pen_field() }

  if pen_fields[1] then
    local pen = pen_fields[1].value
    if (pen == KOTSAFE_PEN) and (buffer:len() >= 4) then
      local get_uint = (buffer(0, 2):uint() == 1) and function(buf) return buf:uint() end or function(buf) return buf:le_uint() end
      local block_type = buffer(2, 1):uint()
      local subtree = tree:add(kotsafe_proto, buffer(), string.format("KotSafe Block: \"%s\" (%u)", block_types[block_type] or "Unknown", block_type))
      local block = buffer(4, buffer:len() - 4)

      if block_type == 1 then
        local uid = get_uint(block(0, 4))
        local packagename_len = block(4, 1):uint()
        local appname_len = block(5, 1):uint()
        local package_name = block(6, packagename_len):string()
        local app_name = block(6 + packagename_len, appname_len):string()

        subtree:set_text(string.format("KotSafe UID Mapping: %u -> %s (%s)", uid, package_name, app_name))
        subtree:add(f.uid, block(0, 4), uid)
        subtree:add(f.packagename, block(6, packagename_len))
        subtree:add(f.appname, block(6 + packagename_len, appname_len))
        uid_map[uid] = {package_name, app_name}
      end
    end
  else
    local comment_fields = { comment_field() }
    if comment_fields[1] then
      local comment = comment_fields[1].value
      if (string.sub(comment, 1, 2) == "u-") then
        local uid = tonumber(string.sub(comment, 3))
        if uid ~= nil then
          local mapping = uid_map[uid]
          local package_name = mapping and mapping[1] or "Unknown"
          local app_name = mapping and mapping[2] or ("UID " .. uid)
          local subtree = tree:add(kotsafe_proto, buffer(), string.format("KotSafe Metadata: App [%s], UID [%d]", app_name, uid))
          subtree:add(f.uid, uid)
          subtree:add(f.packagename, package_name)
          subtree:add(f.appname, app_name)
        end
      end
    end
  end
end

function kotsafe_proto.dissector(buffer, pinfo, tree)
  if not dissect_pcap_trailer(buffer, pinfo, tree) then
    dissect_pcapng(buffer, pinfo, tree)
  end
end

register_postdissector(kotsafe_proto)
```

---

## 10. Troubleshooting & FAQs

### Q: Why do some packets show `UID: -1` or `UID: 0`?
**A:** `UID 0` belongs to root / Android kernel processes. `UID -1` indicates packets generated by kernel subsystems, tethering bridges, or ICMP replies that are not bound to an individual userspace application package.

### Q: Wireshark shows "Lua: Error during loading"?
**A:** Ensure Wireshark was compiled with Lua support. On Debian/Ubuntu/Kali, ensure `wireshark` package is up to date (`sudo apt install wireshark`). Check **Help ➔ About Wireshark** and verify `with Lua 5.x` is listed in the build features.

### Q: How do I verify the plugin is active?
**A:** Go to **Help ➔ About Wireshark ➔ Plugins** tab. Filter by "Lua" and verify `KotSafe` is listed in the table.
