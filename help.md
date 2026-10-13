# Brian's Tools Help

Brian's Tools is a desktop **Network Toolbox** for network engineers and admins. It puts the calculators, lookups and test tools you reach for every day in one window, on Windows, macOS and Linux.

## Getting started

- **Open a tool:** pick it from **☰ Tools** (top left) or click its name on the **Home** tab. Every tool you open gets its own tab, which stays open until you close it.
- **Favorites:** tools marked ★ are favorites. They open as tabs every time the app starts. Use the ★ button next to the Tools menu, the stars on the Home tab, or right-click a tab.
- **Close a tab:** hover over it and click the **×**, press ⌘W (macOS) or Ctrl+W, or middle-click it.
- **Right-click anything:** text boxes, result fields and table cells all have Copy / Paste and **Send to**, which takes what you clicked into another tool and runs it there.
- **Help any time:** **☰ Tools → Brian's Tools Help** (or F1, or the Help link on Home) opens this guide. **☰ Tools → About Brian's Tools** shows the version.

## Working in the app

### The Home tab

The start page. It lists every tool by group (IP, Time, MAC, Network, Text & logs) with a short description. Click a tool's name to open it in a tab, or click its ☆/★ to add or remove it from the favorites that open at launch. A new install opens on Home. Existing setups get a Home tab at the front once, and the app reopens on the last favorite you used.

### Tabs, favorites and the Tools menu

- **☰ Tools** (top left) is a drop-down menu of every tool, grouped by IP, Time, MAC, Network, and Text & logs. Favorites are marked ★.
- **Tabs stay open:** opening a tool (from the Tools menu, Home, Send to, or a link in another tool) gives it a tab that stays open until you close it.
- **Closing:** hover a tab to reveal its **×** and click it. You can also middle-click the tab (Windows/Linux), press Ctrl+W (⌘W on macOS), or right-click the tab and choose **Close** or **Close other tabs**. **Tools → Close all tabs that aren't favorites** tidies up. Closing the last tab leaves Home open.
- **Favorites** are the tabs that open every time the app starts. Toggle the current tool with the ★ button next to the Tools menu, the Tools menu, the star on Home, or by right-clicking a tab.
  - **Closing a favorite's tab** only closes it for now. It's back at the next launch.
  - **Un-favoriting a tool** leaves its tab open for now; it just won't open at launch.
  - **Making a tool a favorite** opens its tab right away (if it isn't open already).
  - **Tools → Favorites** lets you tick tools on or off, make every tool a favorite, or clear the list.
- **Order:** favorite tabs come first, then the other open tabs in the order you opened them. Drag a tab to reorder it within its group, or right-click it and choose **Move left** or **Move right**.
- **Shortcuts:** Ctrl+1–9 (⌘1–9 on macOS) jumps to the first nine tabs. Ctrl+W (⌘W) closes the current tab.
- **Saved between runs:** your favorites and their order. The app reopens on the favorite you used last. Other open tabs aren't saved.

### Right-click menu and Send to

Right-click any text box, input field, result value, or table cell in any tool.

- **Editing:** Cut, Copy, Paste, and Select all (Cut and Paste only where you can type).
- **No selection needed:** with nothing highlighted, the menu uses the IP, MAC, host name, or word under the pointer (`10.1.1.1 255.255.255.0` is picked up as a pair).
- **Send “…” to ▸** lists every tool. Choosing one puts the text into that tool, switches to it, and runs it:
  - **IP Calc** takes the first subnet or address (`ip address 10.1.2.3 255.255.255.0` → that subnet).
  - **IP Summarize, MAC Format, MAC Lookup, Whois, Route Table, and Log Times** take the whole text. Whois starts its lookups.
  - **Bits & Bytes** reads the number and unit (`10 Gbps`, `1.5GB`).
  - **Time Zones and Time Calc** take the first date and time, in any format Log Times understands (syslog, ISO, epoch, …).
  - **DNS Digr and Traceroute** take the first IP or host name and run.
  - **Ping** adds and starts every IP or host name. Lines that start with a target keep the rest of the line as the note (`192.0.2.1 Core router`).
  - **Ping Sweep** loads the list but waits for you to press **Start**.
  - **Compare** asks for the left or right side.
- **Tables:** right-clicking a cell sends that cell. With several rows selected, it sends that column for all of them (for example, every IP in a sweep result). Tables with their own menu keep it and gain **Send to** at the bottom. Tables without one get Copy cell, Copy row, and Send to.

### Copying tables

Every **Copy table**, **Copy selected**, **Copy history**, **Copy row**, and **Copy routes** gives plain text with a header row, a dashed line under it, and columns padded with spaces so everything lines up under its heading in any monospaced font (terminal, ticket, email in a fixed-width font). Number columns are right-aligned. DNS Digr's **Copy answers** and **Copy output** line up the record fields the same way, and the Route Table summary uses aligned tables too. **Save history…** as `.tsv` still writes tabs for spreadsheets; any other extension gets the aligned layout. Lists (Copy alive, Copy list, and so on) stay one value per line.

### Scrolling

When the window is smaller than a page, scrollbars appear on the right and along the bottom. They hide again when everything fits, and tables keep their full column widths instead of being squashed.

- **Mouse wheel / trackpad:** scrolls the page. Shift + wheel, or a sideways trackpad swipe, scrolls it horizontally.
- **Over a table or text box:** just pointing at it is enough. The wheel scrolls that box (Shift for sideways), the same way on macOS, Windows, and Linux. If everything in the box is already visible, the page scrolls instead.
- **Tables:** columns keep their width. A table that's wider than its space gets its own scrollbar along the bottom, which appears only when needed, so you scroll the table sideways rather than the whole page. In Whois, columns widen to fit long values (organizations, notes, abuse emails) so nothing is cut off.
- **Over any scrollbar:** the wheel scrolls whatever that scrollbar controls.
- **Clean redraws:** text boxes repaint their visible lines every time their view moves, whether by wheel, their own scrollbar, or the keyboard. This stops macOS smearing repeated lines into a box whose bottom runs past the window edge. The scrolled page and tables are also repainted a moment after you stop scrolling.
- **Any Tk version:** works with the wheel and trackpad on Tk 8.6 and on Tk 8.7 / 9 (for example Homebrew Python on macOS, where trackpads send a different kind of scroll event).
- **Troubleshooting:** if scrolling misbehaves, start the app from a terminal with `BRIANSTOOLS_DEBUG_WHEEL=1 python3 brianstools.py`. Each wheel or trackpad event is printed with the widget under the pointer.

### Resizing text boxes and tables

Every text box and table in the tools has a small grip bar centered under it. Drag the grip up or down to make that box shorter or taller.

- **Snaps to whole lines and rows,** so nothing is cut in half. The smallest size is two lines or rows.
- **Keeps its size:** a box you've sized stays that height instead of stretching to fill the window, and a box taller than the window makes the page scroll.
- **Remembered:** heights are saved between launches, counted in lines and rows so they follow your text size.
- **Back to automatic:** double-click the grip.
- **Compare side by side:** one grip under the pair sizes both sides together.
- **Dialogs:** pop-up windows such as Add list… and the settings editor have no grips. Resize the window instead.

### Appearance (light and dark)

**Tools → Appearance** offers **Follow system** (the default), **Light**, or **Dark**. The change applies right away and is remembered.

- **Follow system** checks the macOS / Windows setting every few seconds and switches with it. On Linux it reads the GNOME colour scheme at start-up.
- **Light:** cool slate-gray pages with white tables and fields.
- **Dark:** the logo's navy with slate fields and cyan accents.
- **Selecting text with the mouse** in any text box shows a light cyan background with black text, so it stays readable on top of the app's own highlights.
- Both themes use the brand kit colours and look the same on every OS. The macOS title bar follows the choice too.

### Fonts and text size

The app uses each platform's own interface font: SF Pro on macOS, Segoe UI on Windows, and the desktop font on Linux. Addresses, tables, and output use a clean monospace font (SF Mono or Menlo; Cascadia Mono or Consolas; DejaVu Sans Mono). **Tools → Text size** offers Small, Medium (the default, one step below the system size), Large (the system size), and Larger. The change applies right away and is remembered.

### Settings and saved data

Everything the app remembers between launches is in `settings.json`. The downloaded `oui.txt`, the RPKI VRP cache `rpki-vrps.json`, the domain RDAP list `rdap-dns.json`, and the Bandwidth Cost comparison `costs.json` sit in the same folder (your PeeringDB API key, if you add one, is in `settings.json`):

- **macOS:** `~/Library/Application Support/BriansTools/` (in Finder: ⌘⇧G and paste that path)
- **Windows:** `%APPDATA%\BriansTools\`
- **Linux:** `~/.config/brianstools/`

**Editing settings:** **☰ Tools → Settings** (or ⌘, on macOS, Ctrl+, elsewhere; also **Brian's Tools → Settings…** in the macOS app menu):
- **Edit settings…** opens `settings.json` in an editor inside the app, showing the current values, including anything on screen that hasn't been saved yet. **Save & restart** checks the JSON (a mistake is highlighted with its line and column) and reopens the window with your changes. **Format** tidies the layout, **Revert** discards your edits, and ⌘S / Ctrl+S saves.
- **Open settings.json in text editor** saves the current settings and opens the file in your system's text editor (TextEdit on macOS, Notepad on Windows). When you save it there, the app notices and offers to restart with your changes. If you decline, the app's own settings are written over your edits when it closes.
- **Show settings folder** opens the folder in Finder or Explorer.
- **Reset all settings…** clears everything back to defaults after asking. Your oui.txt is kept.

`settings.json` holds your favorites and their order, the last favorite you used, appearance, text size, window size, each tool's inputs and options, ping targets with their notes, and the oui.txt location. It's written when the app closes, so edit it by hand only while the app is closed. Deleting it resets everything to defaults.

## IP tools

### IP Calc

One input box that detects IPv4 vs IPv6.

- IPv4 input: `10.1.2.3/24`, `10.1.2.3 255.255.255.0`, `10.1.2.3/255.255.255.0`, wildcard `10.1.2.3 0.0.0.255`, or a bare IP (/32).
- IPv4 output: network, netmask, wildcard, broadcast, host range, usable hosts (/31 and /32 per RFC 3021), class, address type (RFC 1918, CGNAT 100.64/10, documentation, multicast, …), in-addr.arpa zone, binary, and hex.
- IPv6 output: compressed and expanded forms, first/last address, address count, number of /64s, type (GUA, ULA, link-local, NAT64, documentation, …), and the ip6.arpa zone.
- Every value is selectable and has a **Copy** button.
- **Copy as ▾** menu: CIDR, `ip address A M`, ACL `net wildcard`, OSPF `network … area 0`, and range.
- **Copy Subnet Summary:** copies a plain-text block ready to paste into an email or ticket. The first usable address is the gateway, and the usable range is what's left for the customer. For example:
  ```
  Network:      203.0.113.8/29
  Gateway:      203.0.113.9
  Usable range: 203.0.113.10 - 203.0.113.14  (5 addresses)
  Subnet mask:  255.255.255.248
  Broadcast:    203.0.113.15
  ```
  For /31 (and IPv6 /127) the first address is the gateway and the other is the customer's. A /32 has no gateway. IPv6 shows the prefix length instead of a mask and has no broadcast.
- **Multicast addresses:** typing a multicast IP (e.g. `224.0.0.10` or `ff02::5`) adds the protocol name (EIGRP, OSPFv3, …), its scope (e.g. link-local, not forwarded), and the Ethernet MAC it maps to.
- **Split:** pick a longer prefix to list the subnets (the first 4,096 for IPv4, 2,048 for IPv6). **Copy list** copies them.
  - **Double-click** a subnet, select it and press **Return**, or right-click → **Open** to load it into IP Calc.
  - **‹ Back** (Ctrl+[ or ⌘[) returns to the previous block.

### IP Summarize

Paste prefixes, `ip mask` pairs, or ranges (`a - b`) to get the minimal aggregate, a covering supernet, and how much extra space that supernet includes. Double-click a result to open it in IP Calc.

### Bits & Bytes

Enter an amount and a unit (default **bits**) to see it in bits, bytes, and kilo/mega/giga/tera/peta bits and bytes. **Notation Type** switches between "kilo" = 1024 and "kilo" = 1000 (SI). Results are exact, rounded to 17 significant digits.

### Bandwidth Cost

What a circuit really costs per Mbps and Gbps, with a saved table for comparing quotes.

- **Inputs:** a note (vendor, circuit, location), the monthly cost (MRC), any one-time cost (install / NRC) with **Spread over the term** on or off, the term in months or years, and the bandwidth in Mbps, Gbps or Tbps. **Divide by users** adds per-user figures; **Avg. utilization %** is only used for the per-GB figures. Amounts like `$1,500` and `1.5k` work.
- **Results (live as you type):** cost per Mbps per month, per Gbps per month, effective monthly, the first month's bill, per year, and the whole term. With **Spread over the term** on, the one-time cost is divided across the term and included in the monthly and per-Mbps figures. With it off, those figures use the monthly cost only, and the one-time cost shows up in the first month's bill. The whole-term total always includes it. The comparison table's **One-time is** column shows Spread or Up front for each quote. With users ticked, it also shows per user per month, per user over the whole term, and bandwidth per user. It also shows data moved per month at that utilization, and cost per GB and per TB moved. Each figure has a Copy button, and **Copy this quote** copies them all.
- **Comparison table:** **Add to comparison** adds the quote as a row: note, bandwidth, monthly, one-time, term, effective monthly, total, per Mbps, per Gbps, users, per user per month, per user per term, per GB, and when it was added. The lowest cost per Mbps is green. Click a row to load it into the form, change it, and press **Update selected**. **Remove** (or Delete) and **Clear all** tidy up. Column headings sort.
- **Per-user costs without a bandwidth** (e.g. a straight capital quote): tick **Divide by users**, leave **Bandwidth** blank, and enter the one-time cost, the monthly cost (or leave it blank / 0), the term, and the number of customers. For example, $50,000 of capital over 5 years for 1,000 customers comes to $0.8333 per customer per month and $50.00 per customer over the term. The per-Mbps and per-GB figures show "no bandwidth entered". In the comparison table, those quotes leave the bandwidth columns blank. When no quote has a bandwidth, green marks the lowest cost per user instead.
- **Saved automatically** to `costs.json` in the settings folder after every change, so the table is there next time.
- **Copy table** copies the whole comparison as aligned text that pastes cleanly into Notepad or any fixed-width editor.

## Time tools

### Time Zones

Enter a date and time (or click **Now**) and pick the zone it's in. It's converted to every zone in your list, sorted by UTC offset, with the abbreviation (EDT, JST, …), the offset, and a **+1/−1** when the date changes. The Unix epoch of the entered time is shown next to the source time.

- **Picking zones:** search all of the world's zones on the left (e.g. "tokyo", "europe") and double-click, or select and **Add →**. **Add all shown** adds every match, or every zone if the search is empty.
- **Reusing a row:** double-click a result to convert from that zone instead. **Delete** removes a row, and **Copy all** copies the table as aligned text.
- **Daylight saving:** times that are skipped (spring forward) or that happen twice (fall back) are flagged.

### Time Calc

Add or subtract years, months, weeks, days, hours, minutes, and seconds from a start date/time.

- **Start:** type the date, use **▦ Pick** for a calendar, or click **Today**. **Now**, **Start of Day**, and **Noon** set the time. Uncheck **Include time of day** for dates only.
- **Months and years** follow the calendar. If the day doesn't exist in the target month, the last day is used (Jan 31 + 1 month = Feb 28), with a note.
- **Include only certain weekdays** counts weeks and days only on the days you tick, e.g. 10 business days with **Mon–Fri**.
- **Repeat** applies the same step N times and lists every date, e.g. every 2 weeks for the next 10 occurrences.
- **Results:** the result in long form plus the difference from the start, total days and hours, day of year, ISO week, and **Unix epoch**, each with **Copy**. The epoch is shown in seconds and milliseconds for your computer's time zone, plus "if UTC" seconds for treating the time as UTC.
- **No time zones:** this is plain clock math, with no DST adjustment. Use the Time Zones tab for zone conversions.

## MAC tools

### MAC Format

Paste a list of MAC addresses, or any text that contains them, such as `show mac address-table` output. A regex picks out the MACs and ignores everything else, including IPv4/IPv6 addresses and other hex.

- **Input formats:** `aabb.ccdd.eeff`, `aa-bb-cc-dd-ee-ff`, `aa:bb:cc:dd:ee:ff`, `aabbccddeeff`, and short groups like `a:b:c:d:e:f`.
- **Convert to:** 3-dot (`aabb.ccdd.eeff`), dash (`aa-bb-…`), or colon (`aa:bb:…`). **Letters** switches between lower and UPPER case.
- **Output:** MACs only (one per line, optionally with duplicates removed), or the original lines with each MAC rewritten in place.
- **Stats:** line count, MACs found, unique MACs, duplicates, and lines with no MAC. Duplicates and skipped lines are listed below the stats.
- **Highlighting:** in the source box, found MACs are green, duplicates orange, and lines without a MAC grey.

### MAC Lookup

Paste MACs or any text containing them (the same regex as MAC Format). Every unique MAC is listed with its vendor, country, type, details, and how many times it appeared.

- **Vendor database:** the IEEE **oui.txt** list (<https://standards-oui.ieee.org/oui/oui.txt>).
  - **Download / Update oui.txt:** downloads the latest list into the app's settings folder as `oui.txt`, next to `settings.json` (see **Settings and saved data**). Progress shows in the status line, and clicking the button again cancels. The new file only replaces the old one after it has fully downloaded and checked out as the real IEEE list, so a failed download never breaks the copy you have.
  - **Automatic on first use:** if no oui.txt is found, opening the MAC Lookup tab downloads it once automatically.
  - **Moved from Documents:** a copy that an earlier version downloaded into Documents is moved to the settings folder automatically the next time the app starts.
  - **Stale warning:** if the list is more than 90 days old, a note suggests clicking **Update oui.txt**.
  - **Where else it looks:** a file picked with **Choose file…** (remembered), the settings folder, next to the app (the folder with `brianstools.py`, the `.exe`, or the `.app`), and Downloads. **IEEE site** opens the download page in a browser if you need to get it by hand. After replacing a file by hand, click **Reload**.
  - **Smaller blocks:** if `mam.txt`, `oui36.txt`, or `iab.txt` from IEEE sit in the same folder, they're loaded too. Blocks smaller than /24 then show the exact company instead of "IEEE Registration Authority".
  - **Other formats:** Wireshark's `manuf` file also works.
- **Special addresses** (identified even without oui.txt):
  - **HSRP:** HSRPv1 `0000.0c07.acXX`, HSRPv2 `0000.0c9f.fXXX`, and HSRP for IPv6 `0005.73a0.0XXX`, with the group number.
  - **VRRP:** IPv4 `0000.5e00.01XX` and IPv6 `0000.5e00.02XX`, with the VRID.
  - **GLBP:** `0007.b4XX.XXYY`, with the group and forwarder.
  - **Broadcast.**
  - **IPv4 multicast** `01:00:5e…`, mapped to its group and named when well known.
  - **IPv6 multicast** `33:33…`, mapped to its group (including solicited-node) and named when well known.
  - **Routing and redundancy protocols named:**
    - OSPF AllSPFRouters / AllDRouters (224.0.0.5/6, ff02::5/6)
    - RIPv2 / RIPng (224.0.0.9, ff02::9)
    - EIGRP (224.0.0.10, ff02::a)
    - PIM (224.0.0.13, ff02::d)
    - VRRP (224.0.0.18, ff02::12)
    - HSRPv1 / HSRPv2 / GLBP / HSRP for IPv6 (224.0.0.2, 224.0.0.102, ff02::66)
    - IS-IS over IP (224.0.0.19–21)
    - IGMPv3, MLDv2, DVMRP, RSVP, MRD, Cisco Auto-RP, NTP, PTP, mDNS, LLMNR, SSDP, DHCP/DHCPv6
  - **Well-known Layer 2 protocols:** STP/BPDU, PVST+, LACP/slow protocols, 802.1X, LLDP, CDP/VTP/DTP/UDLD, IS-IS (AllL1ISs, AllL2ISs, AllISs, AllESs), CFM levels, PTP.
  - **Locally administered** (virtual or randomized) MACs.
- **Results table:** **Filter results** narrows the table, column headings sort it, and the **Selected** box shows the vendor's full address and prefix. **Copy table** copies the table as aligned text (see **Copying tables**).

## Network tools

### DNS Digr

Dig-style DNS lookups, with output formatted like `dig`. Digr is the app's own built-in DNS client, not ISC `dig`.

- **Nothing to install:** the DNS client is built in (pure Python), so `dig`/BIND doesn't need to be installed. It works the same on Windows, macOS, and Linux, including the standalone `.exe` / `.app`.
- **System resolvers:** the Server list includes this computer's own DNS servers. On macOS and Linux these come from `/etc/resolv.conf`. On Windows they come from the active network adapters' settings in the registry, static servers first, then DHCP.
- **Server:** pick a public resolver (Google, Cloudflare, Quad9, OpenDNS), your system resolver (macOS/Linux), or a root server, or type any IP or hostname.
- **Trace from root (default):** resolves step by step like `dig +trace`, starting at a random root-hints server or one you choose (a–m). Each referral (root → TLD → authoritative) is shown, and glue-less name servers and CNAME chains are followed.
- **Record types:** A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV, CAA, NAPTR, DS, DNSKEY, RRSIG, NSEC, TLSA, SSHFP, HTTPS/SVCB, ANY. Class IN or CH (e.g. `version.bind` / `hostname.bind` with CH TXT).
- **Options:** TCP, recursion desired (RD), DNSSEC (DO bit), trace over IPv6, port, and timeout. Truncated UDP replies are retried over TCP automatically.
- **Reverse lookups:** an IP in the Name box is looked up as PTR automatically.
- **Results:** a short **answers** box (Copy answers) above the full output (Copy output). Recent names are remembered.
- **Firewalls:** queries go straight from your computer on UDP/TCP port 53. If a firewall blocks outbound DNS to the internet, trace mode and public resolvers will time out; your internal resolver still works.

### Ping

Pings several hosts at once and keeps statistics and a full history for each.

- **Tab count:** while targets are pinging, the tab shows how many, e.g. **Ping (3)**, so you can see pings running from any other tool. The number is colored by the worst running target: green when all are answering, yellow when any has had loss, red when any isn't answering right now, and plain when no replies have come back yet. The count goes away when they all stop.
- **Adding targets:** type one or more hosts or IPs separated by spaces or commas (e.g. `8.8.8.8, 1.1.1.1 core-r1`), then press **Add & start**. Ranges (`10.0.0.1-5`) and small subnets expand. Up to 256 targets.
- **Notes:** each target can have a short note, shown in the table's **Note** column, the details heading, the summary, and saved history.
  - **One or a few targets:** type the note in the **Note** box next to the target box. It goes on every target added that time, and the box clears afterwards.
  - **A list, each with its own note:** use **Add list…** (a multi-line box) or **Paste list** (from the clipboard). Put one target per line with the note after a space or comma, e.g. `192.0.2.1 Core router` or `192.0.2.10, Office printer`. A range on one line gives every address the same note. Lines starting with `#` are skipped.
  - **Changing a note:** double-click it in the table (Enter saves, Esc cancels), or right-click → **Edit note…**. Re-adding a target with a note also updates it.
  - **From Ping Sweep:** reverse-DNS names become the note.
- **Targets table:** one live row per target with IP, packet size, state (Pinging / Stopped / Finished / Error), sent, OK, failed, loss %, last result, best / average / worst RTT, and run time.
  - **Size:** the payload bytes the target was started with (your system's default, 56 on macOS / Linux or 32 on Windows, when the box is blank). Sizes over 1024 bytes show in **bold**, so large-MTU tests stand out. Copy table and Send to give ordinary digits.
  - Row colors: green when every reply came back, orange when there has been some loss, and red when the last probe failed.
  - **Selected row:** with one target selected in light mode, its text keeps the status color (green, orange, red) on the dark highlight.
  - **Start all / Stop all / Remove all**, plus **Start**, **Stop**, **Restart (clear history)**, and **Remove** for the selected rows. Right-click a row for the same options, traceroute, or copy.
- **Selected target's details:** select a row to see its tiles (sent, succeeded, failed, loss, best / average / worst, jitter, longest outage, total time), start and end times, the exact command, and its **history**. Nothing is shown below the table until a row is selected.
- **History:** every probe is recorded for every target, including ones that aren't selected. Selecting a target shows its full history, newest probe at the top, which keeps updating live. If you scroll down to read older probes, new ones don't push your place around. Copy history and Save history… are newest first too. **Failures only** filters it. **Copy history** and **Save history…** export the whole history with a summary.
- **Stopping and starting again:** stopping a target and starting it again continues the same history. **Restart** begins a fresh one.
- **Saved between runs:** the target list and notes are restored the next time the app opens, but not started. Histories are kept while the app is open.
- **Options** (apply when a target starts): count (0 = until stopped), interval, timeout, packet size, IPv6.
- **How it works:** each name is resolved once, then your system's `ping` runs once per probe, so every probe gets an exact result on macOS, Linux, and Windows without admin rights. Windows "Reply from … Destination host unreachable" counts as a failure.

### Ping Sweep

Pings every address in a list, subnet, or range and shows which ones are alive.

- **Input:**
  - single IPs
  - subnets (`10.0.0.0/24`, or `10.0.0.0 255.255.255.0`); network and broadcast addresses are skipped
  - ranges (`10.0.0.1-10.0.0.50` or `10.0.0.1-50`)
  - IPv6 addresses and small IPv6 prefixes
  - host names on their own line
  - any pasted text, e.g. `show ip arp` output
  Found addresses are highlighted and counted. The limit is 4,096 addresses per sweep.
- **Options:** pings per address (default 2), timeout, how many addresses to ping at once (default 64), and optional reverse-DNS names. It uses the system `ping`, so no admin rights are needed. A /24 takes a few seconds.
- **Results table:** IP, status, replies (e.g. 2/2), best and average RTT, TTL, name, and details, sorted by IP. Rows are green when every ping was answered, orange when some were lost, and red when none were answered. **Show** filters to alive or not-alive addresses. **Copy alive**, **Copy not alive**, and **Copy table** copy the results.
- **▶ Ping:** every row, alive or not, has a **▶ Ping** button in its first column. It adds that address to the Ping tool's list and starts it, alongside anything already being pinged. Double-clicking a row does the same. **▶ Ping selected** adds every selected row (Shift/Ctrl/⌘-click to pick several), and **▶ Ping all alive** adds every address that answered. Right-click a row for traceroute, reverse DNS, or copy.
- **From IP Calc:** right-click a subnet in the IP Calc split table and choose **Ping sweep** to sweep it.

### Traceroute

Runs your system's traceroute (`traceroute` on macOS/Linux, `tracert` on Windows, so no admin rights are needed) and fills a table live as each hop answers.

- **Resolve hostnames (DNS)** on or off. Off adds `-n` (`-d` on Windows) and skips reverse lookups, which is faster.
- **Options:** IPv6, max hops, probes per hop, wait per probe, and ICMP instead of UDP (macOS; on Linux ICMP needs root; Windows is always ICMP). The exact command is shown.
- **Table columns:** hop, host(s), IP(s), address type (private, CGNAT, public, …), every probe time, average, loss %, and notes (`!H`/`!N`, MPLS labels, Windows messages). Hops where several routers answered show all of them. Full loss is grey and partial loss orange.
- **Hops:** **Stop** ends a trace early. Double-click a hop to open its IP in IP Calc, or right-click to copy it or run a reverse DNS lookup in DNS Digr.
- **Copy table** (aligned text) and **Copy output** (the raw text).

### Whois

Who announces an IP address or prefix, and who owns an ASN, BGP AS path, or domain name. Pick the **Source** for IPs and ASNs: **Ask [Team Cymru](https://www.team-cymru.com)** (the default) uses Team Cymru's IP to ASN mapping service (`whois.cymru.com`): the origin AS and BGP prefix covering an address, plus the AS name, country, registry and allocation date, for a whole list in one query. **ARIN and the other registries (RDAP)** asks ARIN's Whois-RWS REST API (`whois.arin.net/rest`) item by item, following other registries over RDAP: net names, organizations, reassigned customers, and abuse contacts. The choice is remembered.

- **Input:** type one item or paste any text, e.g. a firewall log. IPv4/IPv6 addresses, prefixes (`8.8.8.0/24`), and ASNs (`AS15169` or plain `15169`) are picked out and highlighted. A prefix is looked up by its first address. Bare ARIN handles (`GOGL`, `NET-8-8-8-0-2`) still go to ARIN, since Team Cymru only maps IPs and ASNs.
- **AS paths:** paste a BGP AS path and every ASN in it is looked up, with no "AS" prefix needed. The **AS path owners** box shows the chain in order, e.g. `AS3356 ×3 (Level 3) → AS174 (Cogent) → AS3320 (Deutsche Telekom AG) → AS15169 (Google LLC)`, with **Copy paths**.
  - **Recognised formats:** a bare path (`3356 174 15169`), `AS path: 6939 13335 I` (Junos), IOS-XR/IOS detail lines (`3356 2914 15169, (received & used)`), and `show ip bgp` table rows. In table rows, the metric, local-pref, and weight columns are skipped.
  - **Path details:** prepends are collapsed (×N), AS-sets `{…}` and confederations `(…)` are handled, and asdot (`1.10`) is converted. Private, documentation, and AS_TRANS ASNs are flagged instead of looked up.
  - **Tick boxes:** choose which kinds of item to look up (IPs, ASNs, plain numbers as ASNs), e.g. ASNs only when pasting `show bgp` output.
- **Results table ([Team Cymru](https://www.team-cymru.com)):** query, BGP prefix (network), origin AS, owner (the origin's AS name), country, type and registry, and allocation date. An address that isn't announced in BGP shows **not announced** in grey; a prefix with more than one origin AS lists them all (`AS13335 / AS64500`) in orange. The **Details** pane shows the full record.
- **One query for the whole list ([Team Cymru](https://www.team-cymru.com)):** every IP and ASN goes to [Team Cymru](https://www.team-cymru.com) in a single bulk whois request (TCP port 43), so even hundreds of items come back in a second or two. Up to 2,000 items per lookup. Private, CGNAT, and other special-use addresses are skipped by default.
- **Ask [Team Cymru](https://www.team-cymru.com) via:** **Auto** uses whois on TCP port 43 and switches to DNS by itself if port 43 is blocked (the status line says so). **whois (TCP 43)** never falls back. **DNS** asks TXT records under `origin.asn.cymru.com`, `origin6.asn.cymru.com` and `asn.cymru.com` through this computer's resolver: slower (a query or two per item, AS names cached), but it works where only DNS gets out. If DNS isn't answering at all, the lookup gives up after three failures instead of waiting on every item. Before trusting DNS it checks one record that always exists (AS15169's); if a filtering resolver hides it, every row says so instead of wrongly showing **not announced**.
- **Results table (ARIN):** the columns change to network/CIDR, net name, organization (or reassigned customer), country, allocation type, and abuse email. The **Details** pane shows a whois-style record with net range, parent, origin AS, org address, comments, and abuse/NOC/tech contacts.
- **Fewer queries (ARIN):** private, CGNAT, and other special-use addresses are skipped by default. Addresses in a network already returned reuse that result instead of another query, and replies are cached for the session.
- **Other registries (ARIN):** for addresses and ASNs registered with RIPE, APNIC, LACNIC, or AFRINIC, ARIN only points to that registry. The owner, network/AS name, country, and abuse email are then fetched from that registry over RDAP (via ARIN's RDAP redirector, `rdap.arin.net`), so every hop in a path gets a real owner. Untick "Get owners from other registries" to stay ARIN-only.
- **Domain names:** `example.com`, host names like `www.mail.example.co.uk` (looked up as their registered domain), or domains in any pasted text, such as a phishing report. Only names ending in a real TLD count, so `invoice.pdf` or `v1.2.3` are ignored.
  - **RDAP first:** IANA's bootstrap file (cached for a week) gives each TLD's RDAP server, e.g. Verisign for .com or Nominet for .uk. The registrar's RDAP is then followed for registrant org and country.
  - **Not registered:** if the registry has no record of the name, the row says **Not registered (domain not found)** and the details explain it, instead of showing an error. If RDAP can't be reached, port-43 WHOIS is asked before deciding. An error appears only when neither could be reached.
  - **Certificates:** HTTPS lookups are verified against this computer's own trusted certificates: the Windows certificate store, `/etc/ssl` on Linux, and on macOS the **Keychain** (Apple's built-in roots plus any admin- or MDM-installed roots in the System keychain). Python can't read the Keychain itself, so the app loads it, which means python.org Python and the compiled `.app` both work without "Install Certificates.command". If a server still can't be verified (e.g. an intercepting proxy whose root isn't trusted), the lookup retries without certificate checking, then over plain HTTP, and the status line says so.
  - **Port-43 WHOIS fallback:** for TLDs without RDAP (e.g. .io, .de), `whois.iana.org` gives the registry's WHOIS server and the common fields are parsed from its reply. DENIC's `-T dn,ace` and JPRS's `/e` query formats are handled.
  - **Results:** the table shows registered domain, registrant org (or "not published"), country, created date (in the Allocated column), and the registrar and expiry in Notes (with ARIN as the source: registrar, abuse email and expiry in their own columns), with orange highlighting when expiry is under 30 days. Details include created/updated/expires dates, status codes, name servers, DNSSEC, registrar and abuse contacts, the source servers, and the raw WHOIS text when port 43 was used.
  - **Links:** right-click a domain row to dig, ping, or traceroute it. **Open in ICANN Lookup** opens the record on lookup.icann.org.
- **Right-click a row:** copy the address, then whatever the source gives: origin AS, AS name, and the BGP prefix in IP Calc (Team Cymru), or the abuse email and the network in IP Calc (ARIN). Ping or traceroute an address from here too. The Details button opens the item on **bgp.he.net** (Team Cymru) or **ARIN Search** (ARIN).
- **About [Team Cymru](https://www.team-cymru.com)'s data:** [Team Cymru](https://www.team-cymru.com) builds the mapping from BGP feeds and the registries' delegation files. Country, registry and allocation date describe the registry allocation that covers the prefix, not the end user. There are no contacts or net names; switch the Source to ARIN and the other registries when you need abuse contacts. See <https://www.team-cymru.com/ip-asn-mapping>.
- **Terms of use:** with the ARIN source, data is subject to ARIN's Whois Terms of Use.

### Route Table

Paste or open the output of `show ip route` / `show route` and get summary tables. The platform is detected automatically: Cisco IOS / IOS-XE (`show ip route`, `show ipv6 route`), IOS-XR (`show route`), NX-OS (`show ip route`), Juniper Junos (`show route`, every table, e.g. inet.0 and inet6.0), or Arista EOS (`show ip route`).

- **Tiles:** total routes, protocols, distinct next hops, routes changed in the last 5 minutes, unusual metrics, and ECMP routes (more than one next hop).
- **Routes by protocol:** count and share for each protocol, with sub-types (e.g. OSPF IA / E2, IS-IS L1 / L2, iBGP / eBGP, EIGRP EX).
- **Routes by interface** and **Next hops:** every next-hop IP and its interface, with how many routes use it and from which protocols. A recursive next hop (BGP, or static via an IP) is shown as "(recursive)", and the interface table attributes it through the IGP route that reaches it.
- **Changed in the last 5 minutes:** routes whose age is under 5:00. Arista EOS and IOS IPv6 output don't include ages, and the tab says so.
- **Unusually high metrics**, judged by the route's protocol:
  - **Protocol maximums:** OSPF max-metric (65535+), IS-IS max-metric / overload (16777214+), EIGRP infinity, RIP 15–16, and BGP max-MED.
  - **Statistical outliers:** a metric far above the other routes of the same protocol and sub-type in this table (above Q3 + 3×IQR and at least 4× the median).
- **All routes:** sortable and searchable, with orange for an unusual metric and green for a recent change.
  - **Filtering:** click a protocol, interface, or next hop above to list just its routes. One filter applies at a time. The row you clicked stays highlighted, and a **Filter: … ✕** chip above the list names it.
  - **Turning it off:** click the ✕, press Esc, or click the highlighted row again.
  - **Count:** the heading shows how many routes are listed out of the total (e.g. "showing 9 of 17 routes"). **Find** has its own ✕ to clear the search.
- **Export:** **Copy summary** copies a plain-text report for a ticket, and each table has its own **Copy**. Large tables (full Internet tables) are read in the background, and the all-routes list shows the first 5,000 matches.
- Only active / best routes are counted. Junos non-active alternatives and NX-OS non-best paths are left out, and the tab says how many.

### IRR / RPKI

Builds BGP prefix filters from the IRR, the way bgpq4 does, and checks every route object against RPKI on the way.

- **Query:** one or more ASNs or AS-SETs, e.g. `AS65000`, `AS-EXAMPLE`, or `AS65000:AS-CUSTOMERS`. Route-sets (`RS-…`) work too, but their prefixes have no origin AS, so they can't be RPKI-checked.
- **Prefixes:** enter a prefix (`192.0.2.0/24`) or an address (`2001:db8::1`) to see the route / route6 objects registered for it, with origin, IRR source database(s), and description. They can be mixed with ASNs in one query. **Prefixes match** picks what's included:
  - **Exact and covering (less specific)** (default): the exact prefix plus every object covering it. An address finds the objects that contain it.
  - **Exact and more specific:** the exact prefix plus any registered more-specifics.
  - **Exact only.**
  - Each object is RPKI-checked against its own origin, so stale or conflicting registrations stand out (e.g. an old object with a different origin shows as RPKI invalid). The **Found by** column says how each was found.
- **IRR server and sources:** `whois.radb.net` by default (or `rr.ntt.net`, ARIN's own IRR at `rr.arin.net`, or your own IRRd as `host` or `host:port`). RADb and NTT mirror the ARIN IRR as source `ARIN`, so `ARIN` in **Sources** limits a lookup to ARIN's database. **Sources** limits which databases are searched (e.g. `RPKI,RIPE,ARIN,APNIC,AFRINIC,LACNIC,RADB`). Blank uses the server's default list.
- **How it queries:** over port 43 with the IRRd commands bgpq4 uses. `!i` expands the AS-SET recursively, then `!g` (IPv4) and `!6` (IPv6) fetch each ASN's route objects. Prefixes use `!r` (with `,L` for covering objects or `,M` for more-specifics). Queries are pipelined, so large sets are quick.
- **Networks for each ASN from:** a toggle for where each member ASN's prefixes come from:
  - **IRR / RPKI records only** (default): the ASN's IRR route objects, plus any ROAs for that ASN in the VRP list (when **Check RPKI** is on). A prefix that has a ROA but no route object shows up with Source **ROA**.
  - **Also BGP announcements and ARIN registrations:** adds what each ASN actually originates in BGP (RIPEstat's announced-prefixes, from RIPE RIS route collectors, over the last two weeks). It also adds the networks registered at ARIN to the organization that holds the ASN (ARIN Whois-RWS). This is done for the first 50 ASNs of a large AS-SET. ASNs from other registries simply get no ARIN rows.
  - **Source column:** where each prefix was seen, e.g. `IRR, ROA, BGP`. The summary counts each source and how many prefixes are **not in the IRR**; **Show → Not in IRR** lists them, which is handy for spotting missing route objects.
  - **Leave out prefixes with no IRR route object:** a filter option that keeps BGP-, ROA-, or ARIN-only prefixes out of the generated filter while still listing them.
- **RPKI check:** RFC 6811 origin validation against a VRP list. Each route is **Valid** (a ROA covers it for that origin and length), **Invalid** (wrong origin, or longer than the ROA's max length, with the reason shown), or **Not found** (no ROA covers it).
  - **Where the VRPs come from:** Cloudflare (`rpki.cloudflare.com/rpki.json`) by default, or the rpki-client console. Any JSON VRP export works, including your own validator, e.g. Routinator's `http://validator:8323/json`.
  - **Caching:** the list is saved as `rpki-vrps.json` in the settings folder and refreshed automatically after 6 hours, or straight away with **Update VRPs**.
- **Results:** the ASN table shows how many IPv4 and IPv6 objects each member AS has. The route-object table shows prefix, origin, RPKI state and detail, and whether it's in the filter (green valid, red invalid, grey left out). **Show** filters to invalid, not found, valid, or left-out rows.
- **In filter:** follows the generated filter exactly, and updates whenever a filter option changes or you press **Look up**:
  - **Yes – exact:** it has its own exact entry.
  - **Yes – PREFIX le N:** it has its own entry with a range.
  - **Yes – inside PREFIX le N:** it's covered by a wider entry's range.
  - **No – reason:** RPKI invalid, or longer than the limit.
  - **Warning:** if a left-out prefix (for example an RPKI-invalid more-specific) is still matched by a wider entry's `le` range, the row says so and a ⚠ note appears above the output. Turn off **Accept more-specifics** or lower its length if you need those blocked.
- **Prefix filter options:**
  - **Leave out RPKI-invalid routes** (on by default).
  - **Leave out prefixes longer than** /24 (IPv4) and /48 (IPv6), both adjustable.
  - **Accept more-specifics (le) up to** /24 and /48: each entry allows more-specifics up to that length, and prefixes already inside a wider entry's range are dropped (like bgpq4 `-R`).
- **Formats:** IPv4 goes in `NAME-V4` and IPv6 in `NAME-V6`. The name defaults to the query (e.g. `AS-EXAMPLE`) and can be changed. Each output replaces the old list, and the first lines are comments saying where the data came from and when.
  - **Cisco IOS-XR:** `prefix-set NAME-V4 … end-set`, entries separated by commas, `le` for ranges.
  - **Cisco IOS-XE and NX-OS:** `no ip prefix-list NAME-V4`, then `ip prefix-list NAME-V4 seq 5 permit …` (and `ipv6 prefix-list` for IPv6). An empty list gets a single `deny` so it matches nothing.
  - **Juniper Junos:** `set` commands. A plain `prefix-list` is used when every entry is exact. A `route-filter-list` with `exact` / `upto /N` is used when more-specifics are allowed, since Junos prefix-lists can't hold ranges. Each starts with a `delete` of the old list.
  - **Arista EOS:** `ip prefix-list NAME-V4` with indented `seq 10 permit …` lines.
  - **Nokia SR OS (MD-CLI):** under `/configure policy-options`, a `delete prefix-list "NAME-V4"` then a `prefix-list "NAME-V4" { … }` block with `prefix … type exact` or `type through` / `through-length N` entries. Commit it from `edit-config private` or `exclusive`.
  - **Nokia SR OS (classic CLI):** `/configure router policy-options`, `begin`, `no prefix-list "NAME-V4"`, then `prefix … exact` or `prefix … through N` lines, `exit`, and `commit`.
  - **Nokia SR Linux:** `delete / routing-policy prefix-set NAME-V4`, then `set / routing-policy prefix-set NAME-V4 prefix … mask-length-range exact` (or a range such as `8..24`). Commit from candidate mode with `commit now`.
  - **Plain list:** one prefix per line.
- **Copy config** and **Save…** export the filter. Copy table and Copy work on the two tables.
- **Send to IRR / RPKI:** right-click text such as `neighbor 192.0.2.1 remote-as 64501` or an AS path to look those ASNs up.

### PeeringDB

Look up networks, internet exchanges, facilities and organizations in [PeeringDB](https://www.peeringdb.com), the interconnection database peering coordinators use, and see them laid out the way the website shows them.

- **Input:** an ASN (`10279` or `AS10279`), a [PeeringDB](https://www.peeringdb.com) link such as `https://www.peeringdb.com/net/20321` (also `/ix/`, `/fac/` and `/org/` links, or `ix 26`), an exchange peering IP address (`206.126.110.58` or IPv6), or part of a name to search for. Press Return or **Look up**.
- **Networks, laid out like the website:** the left column lists Organization, Also Known As, Long Name, Company Website and Website Override, Social Media, ASN, IRR as-set, Route Server and Looking Glass URLs, Network Types, IPv4/IPv6 Prefixes, Traffic Levels and Ratios, Geographic Scope, Protocols Supported, the Last Updated dates, Notes and RIR Status. The right column has **Peering Policy Information** (policy URL, general policy, multiple locations, ratio and contract requirements) and **Contact Information** (role, name, visibility, phone, e-mail). Below are **Public Peering Exchange Points** (exchange, ASN, IPv4, IPv6, capacity, port location, RS peer, BFD support, status) and **Interconnection Facilities** (facility, ASN, country, city).
- **Exchanges, facilities and organizations** open the same way: an exchange shows its details, contacts, LAN (MTU, DOT1Q, route server ASN, IX-F export) and prefixes, every peer with their IPs, speed and policy, and its local facilities. A facility shows its address and contacts plus the exchanges and networks there. An organization lists its networks, exchanges and facilities.
- **Exchange IP addresses:** looking up a peering IP finds the network that holds it, says which exchange and port speed, and highlights that row. Handy for an unfamiliar BGP neighbor.
- **Search:** any other text searches network, exchange, facility and organization names (up to 25 matches of each). A single match opens straight away; otherwise double-click one.
- **Links:** **View on PeeringDB ↗** opens the record on peeringdb.com. Inside the results, PeeringDB names (the organization, an exchange or facility row) open here, and **◀ Back** returns to the previous record. Websites, looking glasses and e-mail addresses open in your browser or mail app.
- **Tables:** sort by clicking a heading, drag the grip under a table to resize it, and use **Copy** for an aligned text table. Double-click a row to open it. Right-click a row to open it here or on peeringdb.com, Whois or IRR / RPKI the ASN, ping or copy the IP addresses, or send any cell to another tool. **Copy all** copies the whole record as text.
- **API key (optional):** PeeringDB works without an account, but anonymous queries are rate-limited and some contacts are only shown to logged-in users. Paste a free API key from your PeeringDB profile ([how to get one](https://docs.peeringdb.com/howto/api_keys/)) to raise the limit and see those contacts. The key is saved in `settings.json` and only ever sent to PeeringDB over verified HTTPS. If the rate limit is reached, the tool says so: wait a minute or add a key.
- **Send to:** right-click text anywhere and send it to PeeringDB. A PeeringDB link, an ASN (e.g. from `remote-as 10279`), or an IP address in the text is picked out and looked up.

## Text and log tools

### Compare

Compare two text files or pasted text, e.g. a router config before and after a change.

- **Input:** each side has **Open file…**, **Paste**, and **Clear**, plus a file name and line count. Any text encoding works (UTF-8, UTF-16, Windows/Latin-1). **⇄ Swap** flips the sides. The comparison updates as you type; very large inputs (over about 1 MB) wait for **Compare** or Ctrl/⌘+Return.
- **Options:**
  - whitespace handling: compare all, ignore trailing, ignore leading and trailing, or ignore all whitespace changes
  - ignore case
  - ignore blank lines
  - sort lines first, for lists where order doesn't matter
  - ignore lines matching a regex. The default skips config noise: `^!`, `Building configuration`, `Current configuration`, `ntp clock-period`, and `Last configuration change`.
- **Summary:** changed, added, removed, and identical line counts, % similarity, and how many lines were ignored.
- **Side by side:** line numbers, with both sides scrolling together. Removed lines are red, added lines are green, and changed lines are yellow with the exact changed characters darker. Gaps are shown where a line exists on only one side. **Only differences, context N** folds long runs of identical lines.
- **Unified diff:** `diff -u` style output with `@@` hunks, using the context setting.
- **Unique lines:** lines that appear on only one side, ignoring order and duplicates. Handy for ACLs, prefix lists, VLAN lists, and MAC tables. Each side has a **Copy** button.
- **Navigation and export:** **▲ Prev** / **Next ▼** jump between differences. **Copy diff** and **Save diff…** export the unified diff, or the unique-line lists in that view.
- **Saved settings:** options are saved between runs; file contents aren't.

### Log Times

Open a log file or paste text. Every date/time in it is found and rewritten in another time zone, in place.

- **Formats recognised:**
  - syslog, Cisco IOS and IOS-XR (`*Oct 10 2026 15:02:03.123 UTC:`, `Oct  1 09:00:00`)
  - ISO 8601 / RFC 3339 (`2026-10-10T15:02:03.250Z`, `2026-10-10 15:02:03 -0400`)
  - ctime and `date` output (`Sat Oct 10 15:02:03 UTC 2026`)
  - RFC 2822 and Apache/nginx (`Sat, 10 Oct 2026 15:02:03 GMT`, `10/Oct/2026:15:02:03 +0000`)
  - numeric dates (`10/10/2026 3:02 PM`, `10.10.2026 15:02:03`)
  - Unix epoch seconds or milliseconds (optional)
- **Zones:**
  - Pick the zone the log was written in and the zone to convert to; type in either box to search, or use the UTC and Local buttons.
  - A zone written in the timestamp (`UTC`, `EDT`, `-0400`, `Z`) is used instead, unless you untick that option.
  - Conversions follow daylight saving for each date. Times that fall in a DST gap or overlap are flagged.
- **Clock correction:** shifts every time, e.g. `-2m 13s`, for a device whose clock was off.
- **Year when missing:** syslog lines have no year, so the most recent past date is assumed. You can also pick a year.
- **Numeric dates:** choose month-first or day-first for ambiguous dates like `03/04/2026`.
- **Output:**
  - **Keep each timestamp's format** (default): only the numbers change. The month name, padding, 12/24-hour clock, fractional seconds, and zone style (`EDT`, `-0400`, `Z`) all stay as they were.
  - Other formats: `2026-10-10 07:02:03 EDT`, ISO 8601, or a custom strftime pattern.
  - You can keep the original and add the converted time in `[brackets]`, or add the zone name to times that had none.
- **Results:**
  - Found times are highlighted in both boxes: green where the zone was assumed, blue where it was written in the timestamp.
  - A table lists each one with line, original, converted, format, zone used, and notes. Click a row to find it in the text.
  - **Copy output** and **Save as…** export the converted log.
- **Large logs:** files over about 1 MB convert when you press **Convert**, in the background.

## Keyboard shortcuts

| Action | macOS | Windows / Linux |
|---|---|---|
| Jump to tab 1–9 | ⌘1 – ⌘9 | Ctrl+1 – Ctrl+9 |
| Close the current tab | ⌘W | Ctrl+W |
| Settings | ⌘, | Ctrl+, |
| Help | F1 | F1 |
| Go to IP Calc's input box | ⌘L | Ctrl+L |
| IP Calc: back to the previous block | ⌘[ | Ctrl+[ |
| Run / compare / convert (multi-line boxes) | ⌘Return | Ctrl+Return |
| Save in the settings editor | ⌘S | Ctrl+S |
| Context menu | right-click or Ctrl-click | right-click |

## Network use and privacy

Brian's Tools has no account, no telemetry and no ads. It only goes online when you use a tool that needs to, and only to these services:

| Tool | Contacts |
|---|---|
| Whois | [Team Cymru](https://www.team-cymru.com) (`whois.cymru.com` on TCP port 43, or DNS TXT lookups under `asn.cymru.com` through your resolver) for IPs and ASNs by default; with the ARIN source, ARIN Whois-RWS and RDAP (`whois.arin.net`, `rdap.arin.net`) and the other registries' RDAP servers; ARIN for ARIN handles; IANA's RDAP list (`data.iana.org`) and domain registries' RDAP / WHOIS servers for domain names |
| IRR / RPKI | Your chosen IRR server (default `whois.radb.net`, port 43); the RPKI VRP list (default `rpki.cloudflare.com`); with the wider option, RIPEstat (`stat.ripe.net`) and ARIN |
| PeeringDB | The PeeringDB API (`www.peeringdb.com/api`, HTTPS), with your API key if you enter one |
| MAC Lookup | `standards-oui.ieee.org` (only when downloading oui.txt) |
| DNS Digr | The DNS servers you choose (your system's, a public resolver, or the root servers for a trace) |
| Ping, Ping Sweep, Traceroute | Only the addresses you enter, using your system's own `ping` / `traceroute` / `tracert` |

Everything else (calculators, MAC formatting, Compare, Log Times, Route Table and Bandwidth Cost) works entirely offline. Secure connections use your computer's own certificate store, including the macOS Keychain.

## Troubleshooting

- **A Whois, IRR or RPKI lookup fails:** check that your network allows the services listed above. On a network with an intercepting proxy, lookups fall back to working without certificate checks, and the app says so.
- **Ping or Traceroute says the command isn't installed (Linux):** install it, e.g. `sudo apt install iputils-ping traceroute`.
- **MAC Lookup shows no vendors:** click **Download oui.txt**, or put an `oui.txt` from IEEE in the settings folder and click **Reload**.
- **Time Zones is empty (Windows, running from source):** run `py -m pip install tzdata`. The built app includes it.
- **Scrolling misbehaves:** start the app from a terminal with `BRIANSTOOLS_DEBUG_WHEEL=1` set. Each wheel and trackpad event is printed, which is useful to include in a bug report.
- **Start over:** **☰ Tools → Settings → Reset all settings…** puts everything back to defaults (your oui.txt is kept).
- **First launch is blocked:** on macOS, right-click the app and choose **Open**. On Windows, SmartScreen → **More info** → **Run anyway**.

## About

{{version_line}}

Brian's Tools is made by Brian Dean. Downloads, updates and news are at [brianstools.net](https://brianstools.net).

Versions before 1.0 are numbered by release date: **0.YYYY.MMDD**. For example, 0.2026.1011 was released on October 11, 2026, so a higher number is always newer.
