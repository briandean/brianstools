"""Run with:  python -m unittest test_core"""
import unittest

import subnetcalc_core as core


def rows(iface):
    return dict(core.details(iface))


class IPv4Tests(unittest.TestCase):
    def test_basic(self):
        i = core.parse("172.20.37.130/27")
        r = rows(i)
        self.assertEqual(str(i.network), "172.20.37.128/27")
        self.assertEqual(r["Broadcast"], "172.20.37.159")
        self.assertEqual(r["Netmask"], "255.255.255.224  (/27)")
        self.assertEqual(r["Wildcard"], "0.0.0.31")
        self.assertEqual(r["Host range"], "172.20.37.129 – 172.20.37.158")
        self.assertEqual(r["Usable hosts"], "30")
        self.assertEqual(core.address_type(i.ip), "Private (RFC 1918)")

    def test_input_forms(self):
        self.assertEqual(core.parse("10.1.1.5 255.255.255.0").network.prefixlen, 24)
        self.assertEqual(core.parse("10.1.1.5/255.255.252.0").network.prefixlen, 22)
        self.assertEqual(core.parse("10.1.1.5 0.0.0.255").network.prefixlen, 24)
        self.assertEqual(core.parse("  10.1.1.5 ").network.prefixlen, 32)
        for bad in ["10.1.1.5/33", "10.1.1.256/24", "10.1.1.5 255.0.255.0", "010.1.1.5/24", "hello", ""]:
            self.assertIsNone(core.parse(bad), bad)

    def test_p2p_and_host(self):
        self.assertEqual(rows(core.parse("192.0.2.0/31"))["Usable hosts"], "2 (point-to-point, RFC 3021)")
        self.assertEqual(rows(core.parse("192.0.2.0/31"))["Host range"], "192.0.2.0 – 192.0.2.1")
        self.assertEqual(rows(core.parse("192.0.2.9"))["Usable hosts"], "1 (host route)")

    def test_types(self):
        t = lambda s: core.address_type(core.parse(s).ip)
        self.assertEqual(t("100.72.1.1"), "Shared / CGNAT (RFC 6598)")
        self.assertEqual(t("8.8.8.8"), "Public")
        self.assertEqual(t("239.1.1.1"), "Multicast")
        self.assertEqual(t("255.255.255.255"), "Limited broadcast")

    def test_split(self):
        net = core.parse("10.0.0.0/22").network
        self.assertEqual([str(s) for s in core.split(net, 24)],
                         ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"])
        self.assertEqual(core.subnet_count(net, 30), 256)
        self.assertEqual(len(core.split(net, 32, limit=10)), 10)
        self.assertEqual(core.split(net, 20), [])
        self.assertEqual(core.reverse_zone(net), "0.10.in-addr.arpa")

    def test_summarize(self):
        r = core.summarize("# a, b, c\r\n10.1.0.0/24\n10.1.1.0/24, 10.1.2.0/23\n"
                           "10.1.4.0 255.255.255.0  # comment\n192.168.0.0/24\nbogus\n10.9.9.5 - 10.9.9.6")
        self.assertEqual([str(n) for n in r.aggregated],
                         ["10.1.0.0/22", "10.1.4.0/24", "10.9.9.5/32", "10.9.9.6/32", "192.168.0.0/24"])
        self.assertEqual(r.invalid, ["bogus"])
        self.assertEqual(str(core.summarize("10.1.0.0/24\n10.1.4.0/24").supernet), "10.1.0.0/21")

    def test_copy_formats(self):
        f = dict(core.copy_formats(core.parse("10.1.1.5/24")))
        self.assertEqual(f["IOS"], "ip address 10.1.1.5 255.255.255.0")
        self.assertEqual(f["OSPF"], "network 10.1.1.0 0.0.0.255 area 0")


class IPv6Tests(unittest.TestCase):
    def test_parse_and_compress(self):
        self.assertEqual(str(core.parse("2001:db8:0:0:1:0:0:1").ip), "2001:db8::1:0:0:1")
        self.assertEqual(str(core.parse("fe80::1%en0").ip), "fe80::1")
        self.assertEqual(str(core.parse("[2001:db8::1]/64").network), "2001:db8::/64")
        for bad in ["1::2::3", "12345::", "2001:db8::/129", "2001:db8::/x"]:
            self.assertIsNone(core.parse(bad), bad)

    def test_prefix(self):
        i = core.parse("2001:db8:abcd:12::1/56")
        r = rows(i)
        self.assertEqual(r["Network"], "2001:db8:abcd::/56")
        self.assertEqual(r["Last"], "2001:db8:abcd:ff:ffff:ffff:ffff:ffff")
        self.assertEqual(r["/64 networks"], "256")
        self.assertEqual(r["Addresses"], "2^72")
        self.assertEqual(r["Reverse zone"], "0.0.d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa")
        self.assertEqual(core.address_type(i.ip), "Documentation")
        subs = core.split(i.network, 64)
        self.assertEqual(len(subs), 256)
        self.assertEqual(str(subs[-1]), "2001:db8:abcd:ff::/64")
        self.assertEqual(len(core.split(core.parse("2001:db8::/32").network, 64, limit=2048)), 2048)

    def test_types(self):
        t = lambda s: core.address_type(core.parse(s).ip)
        self.assertEqual(t("fd00::1"), "Unique local (ULA)")
        self.assertEqual(t("2600::1"), "Global unicast")
        self.assertEqual(t("64:ff9b::808:808"), "NAT64 (RFC 6052)")


class DataUnitTests(unittest.TestCase):
    def test_matches_reference_1024(self):
        # Reference values from a common online converter: 177651712 kilobytes, "kilo" = 1024.
        r = {k: core.format_amount(v) for k, v in core.convert_data(core.parse_amount("177651712"), "kilobytes", 1024)}
        self.assertEqual(r["bits"], "1455322824704")
        self.assertEqual(r["bytes"], "181915353088")
        self.assertEqual(r["kilobits"], "1421213696")
        self.assertEqual(r["kilobytes"], "177651712")
        self.assertEqual(r["megabits"], "1387904")
        self.assertEqual(r["megabytes"], "173488")
        self.assertEqual(r["gigabits"], "1355.375")
        self.assertEqual(r["gigabytes"], "169.421875")
        self.assertEqual(r["terabytes"], "0.1654510498046875")  # exact; reference rounds to 0.165451049804688
        self.assertTrue(r["petabytes"].startswith("0.00016157329082489"))

    def test_si(self):
        r = dict(core.convert_data(core.parse_amount("1,000,000,000"), "bits", 1000))
        self.assertEqual(core.format_amount(r["gigabits"]), "1")
        self.assertEqual(core.format_amount(r["megabytes"]), "125")
        self.assertEqual(core.format_amount(r["bytes"]), "125000000")

    def test_parse_amount(self):
        self.assertEqual(core.parse_amount("1e3"), 1000)
        self.assertEqual(core.parse_amount(" 1_500.5 "), core.parse_amount("1500.5"))
        for bad in ["", "-5", "abc", "nan", "inf"]:
            self.assertIsNone(core.parse_amount(bad), bad)
        self.assertEqual(core.format_amount(core.parse_amount("0")), "0")


class TimeZoneTests(unittest.TestCase):
    def test_parse(self):
        from datetime import datetime
        want = datetime(2026, 10, 10, 14, 30)
        for text in ["2026-10-10 14:30", "2026-10-10T14:30", "10/10/2026 2:30 PM", "10/10/2026 2:30pm",
                     " 2026-10-10   14:30:00 "]:
            self.assertEqual(core.parse_datetime(text), want, text)
        self.assertEqual(core.parse_datetime("2026-10-10"), datetime(2026, 10, 10))
        self.assertIsNone(core.parse_datetime("tomorrow"))
        self.assertIsNone(core.parse_datetime("2026-13-01 10:00"))

    def test_convert(self):
        naive = core.parse_datetime("2026-10-10 14:30")
        src, note, rows = core.convert_time(naive, "America/New_York",
                                            ["Asia/Tokyo", "UTC", "America/Los_Angeles", "Asia/Kolkata"])
        self.assertIsNone(note)
        self.assertEqual(core.describe(src), "Sat 2026-10-10 14:30 EDT (UTC−04:00)")
        got = {r.zone: (r.local.strftime("%Y-%m-%d %H:%M"), r.abbrev, r.day_shift) for r in rows}
        self.assertEqual(got["UTC"], ("2026-10-10 18:30", "UTC", 0))
        self.assertEqual(got["Asia/Tokyo"], ("2026-10-11 03:30", "JST", 1))
        self.assertEqual(got["America/Los_Angeles"], ("2026-10-10 11:30", "PDT", 0))
        self.assertEqual(got["Asia/Kolkata"][0], "2026-10-11 00:00")
        self.assertEqual([r.zone for r in rows][0], "America/Los_Angeles")   # sorted by offset
        self.assertEqual(core.format_offset(rows[-1].offset), "UTC+09:00")

    def test_dst_edges(self):
        _, gap, _ = core.convert_time(core.parse_datetime("2026-03-08 02:30"), "America/New_York", ["UTC"])
        self.assertIn("doesn't exist", gap)
        _, overlap, rows = core.convert_time(core.parse_datetime("2026-11-01 01:30"), "America/New_York", ["UTC"])
        self.assertIn("happens twice", overlap)
        self.assertEqual(rows[0].local.strftime("%H:%M"), "05:30")   # first occurrence = EDT

    def test_zone_list(self):
        zones = core.all_timezones()
        self.assertIn("America/New_York", zones)
        self.assertIn("UTC", zones)
        self.assertGreater(len(zones), 300)
        self.assertIn(core.local_timezone_name(), zones)


class DateMathTests(unittest.TestCase):
    def setUp(self):
        from datetime import datetime
        self.dt = datetime

    def test_months_clamp(self):
        r = core.date_math(self.dt(2026, 1, 31, 9, 0), months=1)
        self.assertEqual(r.result, self.dt(2026, 2, 28, 9, 0))
        self.assertTrue(r.notes)
        self.assertEqual(core.date_math(self.dt(2024, 2, 29), years=1).result, self.dt(2025, 2, 28))
        self.assertEqual(core.date_math(self.dt(2026, 3, 15), sign=-1, months=14).result, self.dt(2025, 1, 15))

    def test_days_weeks_time(self):
        start = self.dt(2026, 10, 10, 22, 0)
        r = core.date_math(start, weeks=1, days=2, hours=3, minutes=30)
        self.assertEqual(r.result, self.dt(2026, 10, 20, 1, 30))
        self.assertEqual(core.describe_span(start, r.result), "9 days, 3 hours, 30 minutes later")
        back = core.date_math(start, sign=-1, days=10, seconds=5).result
        self.assertEqual(back, self.dt(2026, 9, 30, 21, 59, 55))
        self.assertEqual(core.describe_span(start, back), "10 days, 0 hours, 0 minutes, 5 seconds earlier")

    def test_business_days(self):
        weekdays = {0, 1, 2, 3, 4}
        fri = self.dt(2026, 10, 9)
        self.assertEqual(core.date_math(fri, days=1, weekdays=weekdays).result, self.dt(2026, 10, 12))   # Mon
        self.assertEqual(core.date_math(fri, days=5, weekdays=weekdays).result, self.dt(2026, 10, 16))   # Fri
        self.assertEqual(core.date_math(fri, days=23, weekdays=weekdays).result, self.dt(2026, 11, 11))
        self.assertEqual(core.date_math(self.dt(2026, 10, 12), sign=-1, days=1, weekdays=weekdays).result,
                         self.dt(2026, 10, 9))
        sat = self.dt(2026, 10, 10)
        self.assertEqual(core.date_math(sat, days=1, weekdays=weekdays).result, self.dt(2026, 10, 12))
        # brute-force check of the week shortcut
        import random
        rnd = random.Random(1)
        for _ in range(300):
            allowed = set(rnd.sample(range(7), rnd.randint(1, 6)))
            n = rnd.randint(-60, 60)
            start = self.dt(2026, 1, 1) + core.timedelta(days=rnd.randint(0, 400))
            d, left, step = start, abs(n), (1 if n > 0 else -1)
            while left:
                d += core.timedelta(days=step)
                if d.weekday() in allowed:
                    left -= 1
            self.assertEqual(core.add_days_on_weekdays(start, n, allowed), d, (start, n, allowed))


class EpochTests(unittest.TestCase):
    def test_epoch(self):
        from datetime import datetime
        self.assertEqual(core.epoch_seconds(datetime(1970, 1, 1)), 0)
        self.assertEqual(core.epoch_seconds(datetime(2026, 10, 10, 14, 30), "UTC"), 1791642600)
        self.assertEqual(core.epoch_seconds(datetime(2026, 10, 10, 14, 30), "America/New_York"), 1791657000)
        self.assertEqual(core.epoch_seconds(datetime(2026, 1, 15, 9, 0), "America/New_York"), 1768485600)


class MacTests(unittest.TestCase):
    SAMPLE = """\
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 100    0011.22aa.bbcc    DYNAMIC     Gi1/0/1
 100    00-11-22-AA-BB-CD DYNAMIC     Gi1/0/2
00:11:22:aa:bb:cc
a:b:c:d:e:f
001122AABBCE
not a mac 192.168.1.1 and 2001:db8::1 and 12345
"""

    def test_formats(self):
        self.assertEqual(core.format_mac("001122aabbcc", "dotted"), "0011.22aa.bbcc")
        self.assertEqual(core.format_mac("001122aabbcc", "dash", upper=True), "00-11-22-AA-BB-CC")
        self.assertEqual(core.format_mac("001122aabbcc", "colon"), "00:11:22:aa:bb:cc")
        self.assertEqual(core.normalize_mac("a:b:c:d:e:f"), "0a0b0c0d0e0f")

    def test_extract_and_stats(self):
        r = core.convert_macs(self.SAMPLE, "colon")
        self.assertEqual(r.output_lines, ["00:11:22:aa:bb:cc", "00:11:22:aa:bb:cd", "00:11:22:aa:bb:cc",
                                          "0a:0b:0c:0d:0e:0f", "00:11:22:aa:bb:ce"])
        self.assertEqual(r.line_count, 8)
        self.assertEqual(len(r.lines_without_mac), 3)          # header, dashes, junk line
        self.assertEqual(r.duplicates, [("001122aabbcc", 2)])
        self.assertEqual(r.unique_count, 4)

    def test_dedupe_and_in_place(self):
        r = core.convert_macs(self.SAMPLE, "dotted", upper=True, dedupe=True)
        self.assertEqual(r.output_lines[0], "0011.22AA.BBCC")
        self.assertEqual(len(r.output_lines), 4)
        r = core.convert_macs(self.SAMPLE, "dash", in_place=True)
        self.assertIn(" 100    00-11-22-aa-bb-cc    DYNAMIC     Gi1/0/1", r.output_lines)
        self.assertEqual(r.output_lines[-1], "not a mac 192.168.1.1 and 2001:db8::1 and 12345")

    def test_not_macs(self):
        for text in ["2001:db8:0:1:2:3:4:5", "fe80::1", "aabb.ccdd.eeff.0011", "0011223344556677",
                     "10.1.1.1", "aa:bb:cc:dd:ee:ff:00", "1234.5678"]:
            self.assertEqual(core.convert_macs(text).macs, [], text)


class OuiTests(unittest.TestCase):
    IEEE = ("OUI/MA-L\t\tOrganization\r\ncompany_id\t\tOrganization\r\n\t\tAddress\r\n\r\n"
            "00-00-0C   (hex)\t\tCisco Systems, Inc\r\n00000C     (base 16)\t\tCisco Systems, Inc\r\n"
            "\t\t\t\t170 WEST TASMAN DRIVE\r\n\t\t\t\tSAN JOSE  CA  95134-1706\r\n\t\t\t\tUS\r\n\r\n"
            "70-B3-D5   (hex)\t\tIEEE Registration Authority\r\n70B3D5     (base 16)\t\tIEEE Registration Authority\r\n"
            "\t\t\t\t445 Hoes Lane\r\n\t\t\t\tPiscataway  NJ  08554\r\n\t\t\t\tUS\r\n\r\n")
    MA_S = ("70-B3-D5   (hex)\t\tSmall Widgets Ltd\n"
            "123000-123FFF     (base 16)\t\tSmall Widgets Ltd\n\t\t\t\tSomewhere\n\t\t\t\tGB\n\n")
    MANUF = "# Wireshark manuf\n00:00:0C\tCisco\tCisco Systems, Inc\n00:1B:C5:00:00/36\tConverg\tConverging Systems Inc.\n"

    def test_ieee_and_longest_prefix(self):
        db = core.OuiDatabase()
        self.assertEqual(db.load_text(self.IEEE), 2)
        e = db.lookup("00000c07ac0a")
        self.assertEqual((e.org, e.country, e.block), ("Cisco Systems, Inc", "US", "MA-L"))
        self.assertEqual(e.address[0], "170 WEST TASMAN DRIVE")
        self.assertTrue(db.lookup("70b3d5123456").is_registry_block)
        db.load_text(self.MA_S)
        e = db.lookup("70b3d5123456")
        self.assertEqual((e.org, e.block, e.country), ("Small Widgets Ltd", "MA-S", "GB"))
        self.assertTrue(db.lookup("70b3d5999999").is_registry_block)     # outside the /36
        self.assertIsNone(db.lookup("aabbcc112233"))

    def test_manuf(self):
        db = core.OuiDatabase()
        db.load_text(self.MANUF)
        self.assertEqual(db.lookup("00000c123456").org, "Cisco Systems, Inc")
        self.assertEqual(db.lookup("001bc5000123").org, "Converging Systems Inc.")
        self.assertIsNone(db.lookup("001bc5999999"))


class MacClassTests(unittest.TestCase):
    def check(self, mac, category, *words, group=None):
        c = core.classify_mac(core.normalize_mac(mac))
        self.assertEqual(c.category, category, (mac, c))
        for w in words:
            self.assertIn(w, c.detail, (mac, c.detail))
        if group is not None:
            self.assertEqual(c.group, group)

    def test_fhrp(self):
        self.check("0000.0c07.ac0a", "FHRP virtual", "HSRPv1", "group 10", group=10)
        self.check("0000.0c9f.f123", "FHRP virtual", "HSRPv2", "group 291", group=291)
        self.check("0005.73a0.0fff", "FHRP virtual", "HSRP for IPv6", "group 4095", group=4095)
        self.check("00:00:5e:00:01:14", "FHRP virtual", "VRRP (IPv4)", "VRID 20", group=20)
        self.check("00:00:5e:00:02:01", "FHRP virtual", "VRRP (IPv6)", "VRID 1", group=1)
        self.check("0007.b400.0a02", "FHRP virtual", "GLBP", "group 10", "forwarder 2", group=10)

    def test_multicast(self):
        self.check("ff:ff:ff:ff:ff:ff", "Broadcast")
        self.check("01:00:5e:00:00:05", "Multicast", "224.0.0.5", "OSPF")
        self.check("01:00:5e:7f:ff:fa", "Multicast", "SSDP / UPnP – IPv4 239.255.255.250")
        self.check("01:00:5e:01:02:03", "Multicast", "224.1.2.3", "1 of 32 IPv4 groups")
        self.check("33:33:00:00:00:01", "Multicast", "ff02::1", "All nodes")
        self.check("33:33:ff:12:34:56", "Multicast", "solicited-node", "ff02::1:ff12:3456")
        self.check("01:80:c2:00:00:00", "Multicast", "STP")
        self.check("01:80:c2:00:00:0e", "Multicast", "LLDP")
        self.check("01:00:0c:cc:cc:cc", "Multicast", "CDP")
        self.check("01:80:c2:00:00:33", "Multicast", "CFM", "level 3")

    def test_unicast(self):
        self.check("00:11:22:33:44:55", "Unicast")
        c = core.classify_mac("02aabbccddee")
        self.assertEqual(c.scope, "Locally administered")
        self.assertIn("randomized", c.detail)


class WellKnownMulticastTests(unittest.TestCase):
    def test_routing_protocol_groups(self):
        for ip, word in [("224.0.0.5", "OSPF"), ("224.0.0.6", "designated"), ("224.0.0.9", "RIPv2"),
                         ("224.0.0.10", "EIGRP"), ("224.0.0.13", "PIM"), ("224.0.0.18", "VRRP"),
                         ("224.0.0.19", "IS-IS"), ("224.0.0.102", "HSRPv2"), ("224.0.0.2", "HSRPv1"),
                         ("ff02::5", "OSPFv3"), ("ff02::9", "RIPng"), ("ff02::a", "EIGRP"), ("ff02::d", "PIM"),
                         ("ff02::12", "VRRP"), ("ff02::66", "HSRP")]:
            self.assertIn(word, core.multicast_name(ip), ip)

    def test_ip_calc_rows(self):
        rows = dict(core.details(core.parse("224.0.0.10")))
        self.assertEqual(rows["Multicast group"], "EIGRP routers")
        self.assertIn("TTL 1", rows["Multicast scope"])
        self.assertEqual(rows["Multicast MAC"], "0100.5e00.000a  ·  01:00:5e:00:00:0a")
        rows = dict(core.details(core.parse("ff02::5")))
        self.assertIn("OSPFv3", rows["Multicast group"])
        self.assertEqual(rows["Multicast scope"], "Link-local")
        self.assertIn("33:33:00:00:00:05", rows["Multicast MAC"])
        rows = dict(core.details(core.parse("239.1.2.3")))
        self.assertNotIn("Multicast group", rows)
        self.assertIn("Administratively scoped", rows["Multicast scope"])
        self.assertNotIn("Multicast scope", dict(core.details(core.parse("10.1.1.1/24"))))

    def test_l2_routing(self):
        self.assertIn("Level 1", core.classify_mac("0180c2000014").detail)
        self.assertIn("Level 2", core.classify_mac("0180c2000015").detail)
        self.assertIn("RIPv2", core.classify_mac("01005e000009").detail)
        self.assertIn("EIGRP", core.classify_mac("33330000000a").detail)


class DnsTests(unittest.TestCase):
    def test_names_and_query(self):
        import dnsdig as d
        self.assertEqual(d.encode_name("www.example.com"), b"\x03www\x07example\x03com\x00")
        self.assertEqual(d.encode_name("."), b"\x00")
        self.assertEqual(d.reverse_name("192.0.2.1"), "1.2.0.192.in-addr.arpa.")
        qid, payload = d.build_query("example.com", d.TYPES["MX"], qid=0x1234, dnssec=True)
        m = d.parse_message(payload)
        self.assertEqual(m.id, 0x1234)
        self.assertEqual(m.question, [("example.com.", 15, 1)])
        self.assertTrue(m.flag("rd"))
        self.assertTrue(m.opt.ttl & 0x8000)          # DO bit

    def test_parse_compressed_answer(self):
        import dnsdig as d, struct
        # reply for example.com A + MX, using compression pointers back to the question name (offset 12)
        hdr = struct.pack(">HHHHHH", 7, 0x8180, 1, 2, 0, 0)
        q = d.encode_name("example.com") + struct.pack(">HH", 1, 1)
        a = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes([192, 0, 2, 1])
        mx = b"\xc0\x0c" + struct.pack(">HHIH", 15, 1, 60, 9) + struct.pack(">H", 10) + b"\x04mail\xc0\x0c"
        m = d.parse_message(hdr + q + a + mx)
        self.assertEqual(m.rcode_name, "NOERROR")
        self.assertEqual(m.flag_names, ["qr", "rd", "ra"])
        self.assertEqual([(r.type_name, r.ttl, r.text) for r in m.answer],
                         [("A", 300, "192.0.2.1"), ("MX", 60, "10 mail.example.com.")])

    def test_bad_packets(self):
        import dnsdig as d
        with self.assertRaises(d.DnsError):
            d.parse_message(b"\x00\x01")
        with self.assertRaises(d.DnsError):          # pointer loop
            d.read_name(b"\xc0\x00", 0)


class TracerouteTests(unittest.TestCase):
    MAC = """traceroute to google.com (142.250.65.78), 30 hops max, 52 byte packets
 1  router.lan (192.168.1.1)  1.402 ms  0.978 ms  0.937 ms
 2  100.64.0.1 (100.64.0.1)  8.210 ms  7.987 ms  9.102 ms
 3  * * *
 4  ae1.cr1.atl.example.net (203.0.113.9)  12.1 ms
    ae2.cr2.atl.example.net (203.0.113.10)  12.6 ms  13.0 ms
 5  142.250.65.78 (142.250.65.78)  20.553 ms !H  20.1 ms *
"""
    LINUX_N = """traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  10.0.0.1  0.512 ms  0.488 ms  0.470 ms
 2  198.51.100.1  5.001 ms <MPLS:L=24005,E=0,S=1,T=1>  4.9 ms  5.2 ms
 3  * 198.51.100.7  7.7 ms *
"""
    WIN = """Tracing route to dns.google [8.8.8.8]
over a maximum of 30 hops:

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     9 ms     8 ms     9 ms  cpe-1.example.net [100.64.12.1]
  3     *        *        *     Request timed out.
  4    14 ms     *       15 ms  8.8.8.8
  5     *       12 ms     *     10.9.9.9  reports: Destination host unreachable.

Trace complete.
"""

    def hops(self, text, kind):
        import tracert as tr
        p = tr.TraceParser(kind)
        for line in text.splitlines():
            p.feed(line)
        return p.hops

    def test_unix(self):
        import tracert as tr
        h = self.hops(self.MAC, "unix")
        self.assertEqual(h[1].responders, [("router.lan", "192.168.1.1")])
        self.assertEqual(h[1].rtts, [1.402, 0.978, 0.937])
        self.assertEqual(h[3].lost, 3)
        self.assertEqual(h[5].notes, "!H")
        self.assertEqual(h[4].responders, [("ae1.cr1.atl.example.net", "203.0.113.9"),
                                           ("ae2.cr2.atl.example.net", "203.0.113.10")])
        self.assertEqual(h[4].rtts, [12.1, 12.6, 13.0])
        self.assertEqual(h[5].lost, 1)
        # continuation line (multiple routers answering hop 4)
        cont = tr.parse_unix_line("    ae2.cr2.atl.example.net (203.0.113.10)  12.6 ms  13.0 ms")
        self.assertIsNone(cont)       # no hop number – caller appends to the previous hop
        h = self.hops(self.LINUX_N, "unix")
        self.assertEqual(h[2].responders, [("198.51.100.1", "198.51.100.1")])
        self.assertIn("MPLS:L=24005", h[2].notes)
        self.assertEqual((h[3].lost, h[3].rtts), (2, [7.7]))

    def test_windows(self):
        h = self.hops(self.WIN, "windows")
        self.assertEqual(sorted(h), [1, 2, 3, 4, 5])
        self.assertEqual(h[1].rtts, [0.5, 0.5, 0.5])
        self.assertEqual(h[2].responders, [("cpe-1.example.net", "100.64.12.1")])
        self.assertEqual((h[3].lost, h[3].message), (3, "Request timed out."))
        self.assertEqual((h[4].rtts, h[4].lost), ([14.0, 15.0], 1))
        self.assertIn("unreachable", h[5].notes)

    def test_commands(self):
        import tracert as tr
        self.assertEqual(tr.build_command("x.com", resolve=False, kind="unix"),
                         ["traceroute", "-n", "-m", "30", "-q", "3", "-w", "2", "x.com"])
        self.assertEqual(tr.build_command("x.com", resolve=True, icmp=True, max_hops=20, kind="unix"),
                         ["traceroute", "-I", "-m", "20", "-q", "3", "-w", "2", "x.com"])
        self.assertEqual(tr.build_command("x.com", resolve=False, kind="windows"),
                         ["tracert", "-d", "-h", "30", "-w", "2000", "-4", "x.com"])
        self.assertEqual(tr.build_command("x.com", ipv6=True, kind="unix", tool="/usr/sbin/traceroute6")[0:2],
                         ["/usr/sbin/traceroute6", "-m"])


class PingTests(unittest.TestCase):
    def test_parse(self):
        import pinger as p
        mac = ("PING 8.8.8.8 (8.8.8.8): 56 data bytes\n64 bytes from 8.8.8.8: icmp_seq=0 ttl=117 time=12.345 ms\n"
               "\n--- 8.8.8.8 ping statistics ---\n1 packets transmitted, 1 packets received, 0.0% packet loss\n")
        r = p.parse_output(mac)
        self.assertEqual((r.ok, r.rtt, r.ttl, r.status), (True, 12.345, 117, "Reply"))
        win = "Pinging 8.8.8.8 with 32 bytes of data:\nReply from 8.8.8.8: bytes=32 time=9ms TTL=117\n"
        self.assertEqual(p.parse_output(win).rtt, 9.0)
        self.assertEqual(p.parse_output("Reply from 192.168.1.1: bytes=32 time<1ms TTL=64").rtt, 0.5)
        r = p.parse_output("Pinging 10.9.9.9 with 32 bytes of data:\nReply from 192.168.1.1: Destination host unreachable.\n")
        self.assertEqual((r.ok, r.status), (False, "Unreachable"))
        self.assertEqual(p.parse_output("Pinging x\nRequest timed out.\n").status, "Timeout")
        mac_fail = "PING 10.9.9.9 (10.9.9.9): 56 data bytes\n\n--- 10.9.9.9 ping statistics ---\n1 packets transmitted, 0 packets received, 100.0% packet loss\n"
        self.assertEqual(p.parse_output(mac_fail, 2).status, "Timeout")
        linux_unreach = "PING 10.0.0.9 (10.0.0.9) 56(84) bytes of data.\nFrom 10.0.0.1 icmp_seq=1 Destination Host Unreachable\n"
        self.assertEqual(p.parse_output(linux_unreach, 1).status, "Unreachable")
        self.assertEqual(p.parse_output("From 10.1.1.1 icmp_seq=1 Time to live exceeded").status, "TTL expired")

    def test_commands(self):
        import pinger as p
        self.assertEqual(p.build_command("8.8.8.8", 2, kind="mac"), ["ping", "-c", "1", "-W", "2000", "8.8.8.8"])
        self.assertEqual(p.build_command("2001:db8::1", 2, ipv6=True, kind="mac"), ["ping6", "-c", "1", "2001:db8::1"])
        self.assertEqual(p.build_command("8.8.8.8", 1.5, 100, kind="linux"),
                         ["ping", "-c", "1", "-W", "2", "-s", "100", "8.8.8.8"])
        self.assertEqual(p.build_command("8.8.8.8", 2, kind="windows"), ["ping", "-n", "1", "-w", "2000", "-4", "8.8.8.8"])

    def test_stats(self):
        import pinger as p
        s = p.PingStats()
        seq = [10.0, None, None, 12.0, 14.0, None, 11.0]
        for v in seq:
            s.add(p.ProbeResult(v is not None, v, 64 if v else None))
        self.assertEqual((s.sent, s.ok, s.failed), (7, 4, 3))
        self.assertAlmostEqual(s.loss_pct, 300 / 7)
        self.assertEqual((s.best, s.worst, s.average), (10.0, 14.0, 11.75))
        self.assertAlmostEqual(s.jitter, (2 + 2 + 3) / 3)
        self.assertEqual(s.longest_outage, 2)
        self.assertEqual(p.format_duration(3725), "01:02:05")
        self.assertEqual(p.format_duration(90061), "1d 01:01:01")


class ArinWhoisTests(unittest.TestCase):
    def test_badgerfish_helpers(self):
        import arinwhois as w
        self.assertEqual(w.text({"$": "x"}), "x")
        self.assertEqual(w.text([{"$": "a"}, {"$": "b"}]), "a, b")
        self.assertEqual(w.as_list({"a": 1}), [{"a": 1}])
        self.assertEqual(w.lines({"line": [{"@number": "1", "$": "two"}, {"@number": "0", "$": "one"}]}), ["one", "two"])
        self.assertEqual(w.lines({"line": {"@number": "0", "$": "only"}}), ["only"])
        self.assertEqual(w.child({"ns4:net": 1}, "net"), 1)

    def test_parse_net_single_and_list(self):
        import arinwhois as w
        t = lambda v: {"$": v}
        base = {"handle": t("NET-1"), "startAddress": t("192.0.2.0"), "endAddress": t("192.0.2.255"),
                "orgRef": {"@handle": "EX", "@name": "Example"}}
        one = dict(base, netBlocks={"netBlock": {"cidrLength": t("24"), "startAddress": t("192.0.2.0"),
                                                 "type": t("DA"), "description": t("Direct Allocation")}})
        many = dict(base, netBlocks={"netBlock": [{"cidrLength": t("25"), "startAddress": t("192.0.2.0")},
                                                  {"cidrLength": t("25"), "startAddress": t("192.0.2.128")}]})
        self.assertEqual(w.parse_net({"net": one}).cidrs, "192.0.2.0/24")
        self.assertEqual(w.parse_net({"net": many}).cidrs, "192.0.2.0/25, 192.0.2.128/25")
        n = w.parse_net({"net": one})
        self.assertEqual((n.org_handle, n.org_name, n.type_name), ("EX", "Example", "Direct Allocation"))
        self.assertTrue(n.contains("192.0.2.77"))
        self.assertFalse(n.contains("192.0.3.1"))

    def test_queries(self):
        import arinwhois as w
        self.assertEqual(w.classify_query("as15169"), ("asn", "AS15169"))
        self.assertEqual(w.classify_query("8.8.8.0/24"), ("cidr", "8.8.8.0/24"))
        self.assertEqual(w.extract_queries("from 203.0.113.5:443 to 8.8.8.8, 8.8.8.8, AS15169, v1.2.3"),
                         ["203.0.113.5", "8.8.8.8", "AS15169"])
        self.assertEqual(w.local_note("100.64.1.1"), "Shared/CGNAT (RFC 6598)")
        label, url = w.other_rir("RIPE", "RIPE Network Coordination Centre")
        self.assertTrue(label.startswith("RIPE"))


class AsPathTests(unittest.TestCase):
    def test_lines(self):
        import arinwhois as w
        f = w.as_path_from_line
        self.assertEqual(f("3356 174 15169"), [3356, 174, 15169])
        self.assertEqual(f("                AS path: 6939 13335 I"), [6939, 13335])
        self.assertEqual(f("  3356 2914 15169, (received & used)"), [3356, 2914, 15169])
        self.assertEqual(f("*> 8.8.8.0/24       203.0.113.1              0    100      0 3356 15169 i"), [3356, 15169])
        self.assertEqual(f("*                   198.51.100.9             0             0 174 15169 i"), [174, 15169])
        self.assertIsNone(f("*> 10.0.0.0/8       0.0.0.0                  0         32768 i"))
        self.assertEqual(f("65010 (65020) {64512,15169} i"), [65010, 65020, 64512, 15169])
        self.assertEqual(f("Path: 1.10 3356"), [65546, 3356])
        self.assertIsNone(f("Oct 10 11:02:01 FW deny tcp port 443 count 12"))

    def test_extract(self):
        import arinwhois as w
        txt = "  3356 3356 3356 15169\n  174 15169, (received & used)\nnext hop 203.0.113.1"
        self.assertEqual(w.extract_as_paths(txt), [[(3356, 3), (15169, 1)], [(174, 1), (15169, 1)]])
        self.assertEqual(w.extract_queries(txt), ["AS3356", "AS15169", "AS174", "203.0.113.1"])
        self.assertEqual(w.extract_queries(txt, bare_asns=False), ["203.0.113.1"])
        self.assertEqual(w.local_note("AS65001"), "Private ASN (RFC 6996)")

    def test_rdap_parse(self):
        import arinwhois as w
        data = {"handle": "AS3320", "name": "DTAG", "startAutnum": 3320, "port43": "whois.ripe.net",
                "entities": [{"handle": "X-RR", "roles": ["registrant"],
                              "vcardArray": ["vcard", [["fn", {}, "text", "X-RR"], ["kind", {}, "text", "group"]]]},
                             {"handle": "ORG-1", "roles": ["registrant"],
                              "vcardArray": ["vcard", [["fn", {}, "text", "Deutsche Telekom AG"], ["kind", {}, "text", "org"]]]},
                             {"handle": "AB-1", "roles": ["abuse"],
                              "vcardArray": ["vcard", [["email", {}, "text", "abuse@telekom.de"]]]}]}
        info = w.parse_rdap(data)
        self.assertEqual((info.org, info.name, info.abuse_emails), ("Deutsche Telekom AG", "DTAG", ["abuse@telekom.de"]))


class DomainWhoisTests(unittest.TestCase):
    def test_parse_whois_text(self):
        import domainwhois as d
        text = ("Domain Name: EXAMPLE.IO\nRegistrar: Example Registrar, LLC\nRegistrar IANA ID: 9999\n"
                "Creation Date: 2010-01-02T03:04:05Z\nRegistry Expiry Date: 2030-01-02T03:04:05Z\n"
                "Registrant Organization: REDACTED FOR PRIVACY\nRegistrant Country: CA\n"
                "Name Server: NS1.EXAMPLE.NET\nName Server: ns2.example.net\nDNSSEC: signedDelegation\n"
                "Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n")
        i = d.parse_whois_text(text, d.DomainInfo(query="example.io"))
        self.assertEqual((i.registrar, i.registrar_id, i.created, i.expires), ("Example Registrar, LLC", "9999",
                                                                              "2010-01-02", "2030-01-02"))
        self.assertEqual(i.registrant_org, "")            # redacted values are ignored
        self.assertEqual(i.registrant_country, "CA")
        self.assertEqual(i.nameservers, ["ns1.example.net", "ns2.example.net"])
        self.assertEqual(i.statuses, ["clientTransferProhibited"])

    def test_rdap_and_helpers(self):
        import domainwhois as d
        data = {"ldhName": "EXAMPLE.COM", "events": [{"eventAction": "expiration", "eventDate": "2030-05-06T00:00:00Z"}],
                "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}], "secureDNS": {"delegationSigned": True},
                "entities": [{"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
                              "vcardArray": ["vcard", [["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]],
                              "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@x.test"]]]}]}]}
        i = d.DomainInfo(query="example.com")
        d.apply_rdap(i, data)
        self.assertEqual((i.domain, i.expires, i.dnssec, i.registrar_id, i.abuse_email),
                         ("example.com", "2030-05-06", "signed", "376", "abuse@x.test"))
        self.assertTrue(d.is_domain("3com.com") and d.is_domain("www.bbc.co.uk"))
        self.assertFalse(any(d.is_domain(x) for x in ("8.8.8.8", "8.8.8.0/24", "AS15169", "GOGL", "NET-8-8-8-0-2", "2001:db8::1")))
        self.assertEqual(d.candidates("www.example.co.uk"), ["www.example.co.uk", "example.co.uk", "co.uk"])
        self.assertEqual(d.extract_domains("see www.example.com, notes.txt and v1.2.3 or 10.0.0.1", d.COMMON_TLDS),
                         ["www.example.com"])


class TextDiffTests(unittest.TestCase):
    A = "hostname r1\ninterface Gi0/1\n description uplink\n ip address 10.0.0.1 255.255.255.0\n!\nend\n"
    B = "hostname r1\ninterface Gi0/1\n description UPLINK to core\n ip address 10.0.0.1 255.255.255.0\n shutdown\n!\nend\n"

    def test_compare_basic(self):
        import textdiff as t
        rows, st = t.compare(self.A, self.B)
        self.assertEqual([r.tag for r in rows], ["equal", "equal", "replace", "equal", "insert", "equal", "equal"])
        self.assertEqual((st.equal, st.changed, st.added, st.removed), (5, 1, 1, 0))
        self.assertFalse(st.identical)
        r = rows[2]
        self.assertEqual((r.left.no, r.right.no), (3, 3))
        self.assertTrue(r.left_spans and r.right_spans)
        self.assertIn("UPLINK to core"[0], r.right.text[r.right_spans[0][0]:r.right_spans[-1][1]])
        self.assertAlmostEqual(st.similarity, 100 * 5 / 7)

    def test_options(self):
        import textdiff as t
        a, b = "Foo  bar\n\nntp clock-period 123\nx\n", "foo bar \nntp clock-period 999\nx\n"
        self.assertFalse(t.compare(a, b)[1].identical)
        opts = t.Options(ignore_case=True, whitespace="all", ignore_blank=True, ignore_regex="^ntp clock-period")
        rows, st = t.compare(a, b, opts)
        self.assertTrue(st.identical)
        self.assertEqual((st.ignored_left, st.ignored_right), (2, 1))
        self.assertEqual(rows[0].left.text, "Foo  bar")     # original text kept
        self.assertTrue(t.compare("b\na\n", "a\nb\n", t.Options(sort_lines=True))[1].identical)
        self.assertEqual(t.normalize("  a  b  ", t.Options(whitespace="trailing")), "  a  b")
        self.assertEqual(t.normalize("  a  b  ", t.Options(whitespace="ends")), "a  b")
        with self.assertRaises(ValueError):
            t.compare("a", "b", t.Options(ignore_regex="("))

    def test_replace_uneven_and_empty(self):
        import textdiff as t
        rows, st = t.compare("a\nX\nY\nZ\nb", "a\nQ\nb")
        self.assertEqual([r.tag for r in rows], ["equal", "replace", "delete", "delete", "equal"])
        self.assertEqual((st.changed, st.removed), (1, 2))
        rows, st = t.compare("", "one\ntwo")
        self.assertEqual((st.added, st.similarity), (2, 0.0))
        self.assertTrue(t.compare("", "")[1].identical)

    def test_unified(self):
        import textdiff as t
        u = t.unified(self.A, self.B, left_name="old.cfg", right_name="new.cfg")
        self.assertTrue(u.startswith("--- old.cfg\n+++ new.cfg\n@@ -1,6 +1,7 @@"))
        self.assertIn("\n- description uplink\n+ description UPLINK to core\n", u)
        self.assertIn("\n+ shutdown\n", u)
        self.assertEqual(t.unified(self.A, self.A), "")
        # agrees with difflib when no options are used
        import difflib
        ref = list(difflib.unified_diff(self.A.splitlines(), self.B.splitlines(), "old.cfg", "new.cfg", lineterm=""))
        self.assertEqual(u.splitlines(), [l.rstrip() if l.startswith(("---", "+++")) else l for l in ref])

    def test_set_compare(self):
        import textdiff as t
        only_a, only_b, both = t.set_compare("vlan 10\nvlan 20\nvlan 30\nvlan 10", "VLAN 30\nvlan 40\nvlan 10",
                                             t.Options(ignore_case=True))
        self.assertEqual((only_a, only_b, both), (["vlan 20"], ["vlan 40"], ["vlan 10", "vlan 30"]))

    def test_read_text_file(self):
        import tempfile, os, textdiff as t
        from pathlib import Path
        d = tempfile.mkdtemp()
        cases = {"u8.txt": "caf\u00e9\n".encode("utf-8"), "bom.txt": "\ufeffcaf\u00e9\n".encode("utf-8"),
                 "u16.txt": "caf\u00e9\n".encode("utf-16"), "lat.txt": "caf\u00e9\n".encode("latin-1")}
        for name, data in cases.items():
            p = os.path.join(d, name)
            Path(p).write_bytes(data)
            self.assertEqual(t.read_text_file(p), "caf\u00e9\n", name)
        p = os.path.join(d, "big.txt")
        Path(p).write_bytes(b"x" * 2000)
        with self.assertRaises(ValueError):
            t.read_text_file(p, max_bytes=1000)


class LogTimeTests(unittest.TestCase):
    def conv(self, text, **kw):
        import logtime as L
        from datetime import datetime
        kw.setdefault("source_zone", "UTC")
        kw.setdefault("target_zone", "America/New_York")
        return L.convert_text(text, L.Options(now=datetime(2026, 10, 10, 12), **kw))

    def test_formats_keep_style(self):
        cases = {
            "*Oct 10 2026 15:02:03.123 UTC: %LINK": "*Oct 10 2026 11:02:03.123 EDT: %LINK",
            "Oct  1 23:30:00 r1 sshd": "Oct  1 19:30:00 r1 sshd",
            "Oct 10 03:15:00.456: %SYS": "Oct  9 23:15:00.456: %SYS",
            "2026-10-10T15:02:03.123456Z x": "2026-10-10T11:02:03.123456-04:00 x",
            "2026-10-10 15:02:03 +0000": "2026-10-10 11:02:03 -0400",
            "[10/Oct/2026:15:02:03 +0000]": "[10/Oct/2026:11:02:03 -0400]",
            "Sat, 10 Oct 2026 15:02:03 GMT": "Sat, 10 Oct 2026 11:02:03 EDT",
            "Sat Oct 10 15:02:03 UTC 2026": "Sat Oct 10 11:02:03 EDT 2026",
            "Sun Oct 11 01:00:00 2026": "Sat Oct 10 21:00:00 2026",
            "10/10/2026 3:02:03 PM": "10/10/2026 11:02:03 AM",
            "10.10.2026 15:02:03": "10.10.2026 11:02:03",
            "13/10/2026 01:00": "12/10/2026 21:00",
            "OCTOBER 10, 2026 15:02": "OCTOBER 10, 2026 11:02",
        }
        for src, want in cases.items():
            self.assertEqual(self.conv(src).text, want, src)

    def test_not_timestamps(self):
        text = "v1.2.3 11:02 10/10/2026 Oct 10 11:02:03 2001:db8::1 rx -10 dBm 99:99:99 1791630123"
        r = self.conv(text)
        self.assertEqual(len(r.stamps), 1)
        self.assertEqual(r.stamps[0].original, "Oct 10 11:02:03")
        self.assertIn("2001:db8::1", r.text)

    def test_zone_rules_and_dst(self):
        # stamp's own zone wins unless told otherwise
        self.assertEqual(self.conv("Oct 10 11:02:03 EDT", target_zone="UTC").text, "Oct 10 15:02:03 UTC")
        self.assertEqual(self.conv("Oct 10 11:02:03 EDT", target_zone="UTC", trust_stamp_zone=False,
                                   source_zone="Asia/Tokyo").text, "Oct 10 02:02:03 UTC")
        # DST-aware both ways: a January line is EST, a July line EDT
        r = self.conv("2026-01-15 12:00:00 / 2026-07-15 12:00:00", add_zone=True)
        self.assertEqual(r.text, "2026-01-15 07:00:00 EST / 2026-07-15 08:00:00 EDT")
        r = self.conv("2026-03-08 02:30:00", source_zone="America/New_York", target_zone="UTC")
        self.assertIn("doesn't exist", r.stamps[0].note)
        # year guess: a December line read in October 2026 is from 2025 only if it's in the future
        r = self.conv("Dec 31 23:00:00", target_zone="UTC")
        self.assertEqual(r.stamps[0].source.year, 2025)
        self.assertEqual(self.conv("Dec 31 23:00:00", target_zone="UTC", year=2026).stamps[0].source.year, 2026)

    def test_output_modes_and_shift(self):
        import logtime as L
        r = self.conv("a 2026-10-10 15:02:03.5 b", output="iso")
        self.assertEqual(r.text, "a 2026-10-10T11:02:03.5-04:00 b")
        r = self.conv("a Oct 10 15:02:03 b", output="readable", append=True)
        self.assertEqual(r.text, "a Oct 10 15:02:03 [2026-10-10 11:02:03 EDT] b")
        st = r.stamps[0]
        self.assertEqual(r.text[st.out_col:st.out_end_col], "2026-10-10 11:02:03 EDT")
        r = self.conv("Oct 10 15:02:03", output="custom", custom_format="%d.%m.%Y %H:%M %Z")
        self.assertEqual(r.text, "10.10.2026 11:02 EDT")
        r = self.conv("Oct 10 15:02:03 x 1791630123456", target_zone="UTC", shift_seconds=-3600, epoch=True)
        self.assertEqual(r.text, "Oct 10 14:02:03 x 2026-10-10 10:02:03.456 UTC")
        self.assertEqual([L.parse_shift(x) for x in ("", "+5h", "-1:30", "90s", "2d 3h", "-00:00:42", "1h30m")],
                         [0, 18000, -5400, 90, 183600, -42, 5400])
        with self.assertRaises(ValueError):
            L.parse_shift("soon")

    def test_columns(self):
        text = "x Oct 10 15:02:03 y 2026-10-10 15:02:03Z\nline2 Oct 10 01:00:00"
        r = self.conv(text, target_zone="Asia/Kolkata", add_zone=True)
        src_lines, out_lines = text.splitlines(), r.text.splitlines()
        for st in r.stamps:
            self.assertEqual(src_lines[st.line - 1][st.col:st.end_col], st.original)
            self.assertEqual(out_lines[st.line - 1][st.out_col:st.out_end_col], st.converted)
        self.assertEqual(r.text, "x Oct 10 20:32:03 IST y 2026-10-10 20:32:03+05:30\nline2 Oct 10 06:30:00 IST")


class SweepTests(unittest.TestCase):
    def test_expand(self):
        import sweep as S
        t = S.expand_targets("gw.example.com\n10.0.0.0/30 10.0.1.5-7 10.0.2.250-10.0.2.251\n"
                             "172.16.0.0 255.255.255.252 10.0.0.1 2001:db8::/126 ::1 v1.2.3 999.1.1.1")
        self.assertEqual(t.hosts, ["gw.example.com", "10.0.0.1", "10.0.0.2", "10.0.1.5", "10.0.1.6", "10.0.1.7",
                                   "10.0.2.250", "10.0.2.251", "172.16.0.1", "172.16.0.2",
                                   "2001:db8::1", "2001:db8::2", "2001:db8::3", "::1"])
        self.assertEqual(S.expand_targets("10.9.9.9/32 10.8.8.8/31").hosts, ["10.9.9.9", "10.8.8.8", "10.8.8.9"])
        big = S.expand_targets("10.0.0.0/16", limit=100)
        self.assertEqual((len(big.hosts), big.hosts[0], bool(big.warnings)), (100, "10.0.0.1", True))
        self.assertEqual(S.expand_targets("show ip arp\nfoo").hosts, [])

    def test_ping_host_status(self):
        import sweep as S, pinger
        seq = {"10.0.0.1": [True, True], "10.0.0.2": [False, True], "10.0.0.3": ["U", "U"], "10.0.0.4": [False, False]}

        def fake(cmd, timeout):
            v = seq[cmd[-1]].pop(0)
            if v is True:
                return pinger.ProbeResult(True, 1.25, 64, "Reply")
            if v == "U":
                return pinger.ProbeResult(False, status="Unreachable", detail="Destination Host Unreachable")
            return pinger.ProbeResult(False, status="Timeout")
        old = pinger.find_tool
        pinger.find_tool = lambda *a, **k: "ping"
        try:
            out = []
            S.sweep(list(seq), out.append, count=2, workers=4, runner=fake)
        finally:
            pinger.find_tool = old
        got = {r.host: (r.status, r.received, r.sent, r.alive) for r in out}
        self.assertEqual(got, {"10.0.0.1": ("Alive", 2, 2, True), "10.0.0.2": ("Partial", 1, 2, True),
                               "10.0.0.3": ("Unreachable", 0, 2, False), "10.0.0.4": ("No reply", 0, 2, False)})
        self.assertEqual(sorted(["10.0.0.10", "10.0.0.9", "host", "::1"], key=S.ip_sort_key),
                         ["10.0.0.9", "10.0.0.10", "::1", "host"])


class CustomerDetailsTests(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(core.customer_details(core.parse("203.0.113.10/29")),
                         "Network:      203.0.113.8/29\n"
                         "Gateway:      203.0.113.9\n"
                         "Usable range: 203.0.113.10 - 203.0.113.14  (5 addresses)\n"
                         "Subnet mask:  255.255.255.248\n"
                         "Broadcast:    203.0.113.15")
        t = core.customer_details(core.parse("192.0.2.4/30"))
        self.assertIn("Gateway:      192.0.2.5", t)
        self.assertIn("Usable range: 192.0.2.6  (1 address)", t)
        t = core.customer_details(core.parse("192.0.2.6/31"))
        self.assertIn("Gateway:      192.0.2.6", t)
        self.assertIn("Broadcast:    n/a", t)
        self.assertIn("n/a (single address)", core.customer_details(core.parse("192.0.2.9/32")))
        t = core.customer_details(core.parse("2001:db8:10::/64"))
        self.assertIn("Gateway:       2001:db8:10::1", t)
        self.assertIn("2001:db8:10::2 - 2001:db8:10:0:ffff:ffff:ffff:ffff", t)
        self.assertIn("Usable range:  2001:db8::1  (1 address)", core.customer_details(core.parse("2001:db8::/127")))


class WindowsResolverTests(unittest.TestCase):
    def test_registry(self):
        import dnsdig

        class FakeReg:
            HKEY_LOCAL_MACHINE = "HKLM"
            tree = {
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces": {
                    "{wifi}": {"DhcpIPAddress": "192.168.1.20", "DhcpNameServer": "192.168.1.1 8.8.8.8"},
                    "{static}": {"IPAddress": ["10.0.0.5"], "NameServer": "10.0.0.53,10.0.0.54",
                                 "DhcpNameServer": "1.2.3.4"},
                    "{down}": {"DhcpIPAddress": "0.0.0.0", "DhcpNameServer": "172.16.0.1"},
                },
                r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces": {
                    "{wifi}": {"DhcpNameServer": "2001:db8::53 fec0:0:0:ffff::1"},
                },
            }

            def OpenKey(self, parent, name):
                if parent == "HKLM":
                    if name not in self.tree:
                        raise OSError
                    return self.tree[name]
                if name not in parent:
                    raise OSError
                return parent[name]

            def EnumKey(self, key, i):
                keys = list(key)
                if i >= len(keys):
                    raise OSError
                return keys[i]

            def QueryValueEx(self, key, name):
                if name not in key:
                    raise OSError
                return key[name], 1

        self.assertEqual(dnsdig.windows_resolvers(FakeReg()),
                         ["192.168.1.1", "8.8.8.8", "10.0.0.53", "10.0.0.54", "2001:db8::53"])


class TrustStoreTests(unittest.TestCase):
    def test_keychain_pems_and_loading(self):
        import ssl, arinwhois as a
        der = ssl.create_default_context().get_ca_certs(binary_form=True)
        if len(der) < 2:
            self.skipTest("no system CA certificates to test with")
        pems = [ssl.DER_cert_to_PEM_cert(d) for d in der[:2]]
        bad = "-----BEGIN CERTIFICATE-----\nnot a cert\n-----END CERTIFICATE-----"
        calls = []

        class R:
            def __init__(self, out): self.stdout = out

        def fake_run(cmd, **kw):
            calls.append(cmd[-1])
            return R(pems[0] + "\n" + bad + "\n" if len(calls) == 1 else pems[0] + pems[1])
        got = a.keychain_pems(fake_run)
        self.assertEqual(calls, list(a.MAC_KEYCHAINS))
        self.assertEqual(len(got), 3)                      # duplicates dropped, junk kept for add_pems to skip
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(a.add_pems(ctx, got), 2)
        self.assertEqual(ctx.cert_store_stats()["x509_ca"], 2)


class RouteTableTests(unittest.TestCase):
    IOS = """Codes: L - local, C - connected, S - static, B - BGP, O - OSPF
Gateway of last resort is 10.0.0.1 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 10.0.0.1
      10.0.0.0/8 is variably subnetted, 4 subnets, 2 masks
C        10.0.0.0/24 is directly connected, GigabitEthernet0/0
L        10.0.0.2/32 is directly connected, GigabitEthernet0/0
O IA     10.1.7.0/24 [110/12] via 10.0.0.5, 00:00:45, GigabitEthernet0/1
                     [110/12] via 10.0.0.6, 00:00:45, GigabitEthernet0/2
O E2     172.16.0.0/16 [110/20] via 10.0.0.5, 2d03h, GigabitEthernet0/1
      172.20.0.0/24 is subnetted, 1 subnets
C        172.20.1.0 is directly connected, Vlan20
B        192.168.0.0/16 [200/0] via 10.0.0.5, 1w2d
"""
    NXOS = """IP Route Table for VRF "default"
10.1.1.0/24, ubest/mbest: 2/0
    *via 10.0.0.5, Eth1/1, [110/41], 00:03:12, ospf-1, intra
    *via 10.0.0.6, Eth1/2, [110/41], 00:03:12, ospf-1, intra
192.168.0.0/16, ubest/mbest: 1/0
    *via 10.255.0.9%default, [200/0], 1d02h, bgp-65000, internal, tag 65000
"""
    JUNOS = """inet.0: 3 destinations, 4 routes (3 active, 0 holddown, 0 hidden)
10.1.1.0/24        *[OSPF/10] 00:02:11, metric 2
                    > to 10.0.0.5 via ge-0/0/1.0
192.168.0.0/16     *[BGP/170] 1d 02:11:33, MED 0, localpref 100, from 10.255.0.9
                      AS path: 65001 I
                    > to 10.0.0.5 via ge-0/0/1.0
                    [BGP/170] 1d 02:11:33, localpref 100, from 10.255.0.10
                    > to 10.0.0.6 via ge-0/0/2.0
10.0.0.0/24        *[Direct/0] 3w2d 04:11:20
                    > via ge-0/0/0.0
"""
    EOS = """VRF: default
Codes: C - connected, S - static, K - kernel,
       B I - iBGP, B E - eBGP, I L2 - IS-IS level 2
 O        10.1.1.0/24 [110/20] via 10.0.0.5, Ethernet2
                               via 10.0.0.6, Ethernet3
 B E      192.168.0.0/16 [200/0] via 10.0.0.9, Ethernet4
 I L2     10.255.0.1/32 [115/20] via 10.0.0.5, Ethernet2
"""
    XR = """Codes: C - connected, S - static, R - RIP, B - BGP, (>) - Diversion path
i L2 10.255.0.1/32 [115/20] via 10.0.0.5, 1d02h, Bundle-Ether1
i L2 10.255.0.4/32 [115/16777214] via 10.0.0.9, 00:00:31, Bundle-Ether2
C    10.0.0.4/30 is directly connected, 3w2d, Bundle-Ether1
"""

    def test_ages(self):
        import routetable as rt
        self.assertEqual([rt.parse_age(x) for x in ("00:01:23", "1d02h", "2w3d", "3y4w", "1d 02:11:33",
                                                     "3w2d 04:11:20", "5m3s", "never")],
                         [83, 93600, 1468800, 97027200, 94293, 2002280, 303, None])

    def test_platforms(self):
        import routetable as rt
        got = {name: rt.parse(txt).platform for name, txt in
               (("ios", self.IOS), ("nxos", self.NXOS), ("junos", self.JUNOS), ("eos", self.EOS), ("xr", self.XR))}
        self.assertEqual(got, {"ios": "Cisco IOS / IOS-XE", "nxos": "Cisco NX-OS", "junos": "Juniper Junos",
                               "eos": "Arista EOS", "xr": "Cisco IOS-XR"})

    def test_ios(self):
        import routetable as rt
        p = rt.parse(self.IOS)
        self.assertEqual([r.prefix for r in p.routes], ["0.0.0.0/0", "10.0.0.0/24", "10.0.0.2/32", "10.1.7.0/24",
                                                       "172.16.0.0/16", "172.20.1.0/24", "192.168.0.0/16"])
        r = p.routes[3]
        self.assertEqual((r.protocol, r.subtype, r.distance, r.metric, r.age), ("OSPF", "IA", 110, 12, 45))
        self.assertEqual([h.key for h in r.next_hops], [("10.0.0.5", "GigabitEthernet0/1"),
                                                       ("10.0.0.6", "GigabitEthernet0/2")])
        s = rt.summarise(p)
        self.assertEqual(s.total, 7)
        self.assertEqual(dict((x[0], x[1]) for x in s.by_protocol),
                         {"OSPF": 2, "Connected": 2, "Static": 1, "Local": 1, "BGP": 1})
        self.assertIn(("10.0.0.5", "GigabitEthernet0/1", 2), [n[:3] for n in s.next_hops])
        self.assertIn(("10.0.0.5", "", 1, "BGP"), s.next_hops)            # recursive BGP next hop
        self.assertEqual(s.interfaces[0], ("GigabitEthernet0/1", 3, 1))      # BGP borrows Gi0/1 via 10.0.0.5
        self.assertEqual([r.prefix for r in s.recent], ["10.1.7.0/24"])
        self.assertEqual(s.ecmp, 1)

    def test_other_platforms(self):
        import routetable as rt
        p = rt.parse(self.NXOS)
        self.assertEqual([(r.protocol, r.subtype, len(r.next_hops), r.age) for r in p.routes],
                         [("OSPF", "", 2, 192), ("BGP", "iBGP", 1, 93600)])
        p = rt.parse(self.JUNOS)
        self.assertEqual([(r.prefix, r.protocol, r.metric) for r in p.routes],
                         [("10.1.1.0/24", "OSPF", 2), ("192.168.0.0/16", "BGP", 0), ("10.0.0.0/24", "Connected", None)])
        self.assertEqual(p.inactive, 1)
        self.assertEqual(p.routes[1].next_hops[0].key, ("10.0.0.5", "ge-0/0/1.0"))
        p = rt.parse(self.EOS)
        self.assertEqual([(r.protocol, r.subtype, len(r.next_hops)) for r in p.routes],
                         [("OSPF", "", 2), ("BGP", "eBGP", 1), ("IS-IS", "L2", 1)])
        self.assertFalse(p.has_ages)
        p = rt.parse(self.XR)
        self.assertEqual([r.flag != "" for r in p.routes], [False, True, False])

    def test_statistical_outlier(self):
        import routetable as rt
        lines = [f"O        10.9.{i}.0/24 [110/{10 + i % 5}] via 10.0.0.5, 1d02h, Gi0/1" for i in range(20)]
        lines.append("O        10.9.99.0/24 [110/4000] via 10.0.0.5, 1d02h, Gi0/1")
        p = rt.parse("Codes: O - OSPF\n" + "\n".join(lines))
        flagged = [r.prefix for r in p.routes if r.flag]
        self.assertEqual(flagged, ["10.9.99.0/24"])
        self.assertIn("Much higher than other OSPF routes", p.routes[-1].flag)


class OuiDownloadTests(unittest.TestCase):
    """oui.txt download into Documents, served from a local HTTP server."""

    @classmethod
    def setUpClass(cls):
        import http.server
        import threading
        lines = []
        for i in range(1200):
            lines.append(f"{i >> 16 & 255:02X}-{i >> 8 & 255:02X}-{i & 255:02X}   (hex)\t\tVendor {i}\n")
        cls.body = ("OUI/MA-L  Organization\n\n" + "".join(lines)).encode()
        body = cls.body

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/oui.txt":
                    data, code, ctype = body, 200, "text/plain"
                elif self.path == "/html":
                    data, code, ctype = b"<html>Access denied</html>", 200, "text/html"
                else:
                    data, code, ctype = b"nope", 404, "text/plain"
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        from pathlib import Path
        self.dest = Path(self.tmp.name) / "Documents" / "oui.txt"

    def tearDown(self):
        self.tmp.cleanup()

    def test_documents_folder(self):
        from pathlib import Path
        import ouidownload as od
        home = Path("/home/u")
        self.assertEqual(od.documents_folder("darwin", home), home / "Documents")
        self.assertEqual(od.documents_folder("win32", home, windows_lookup=lambda: Path("D:/OneDrive/Docs")),
                         Path("D:/OneDrive/Docs"))
        def boom():
            raise OSError("no shell32")
        self.assertEqual(od.documents_folder("win32", home, windows_lookup=boom), home / "Documents")

        class R:
            def __init__(self, out):
                self.stdout = out
        self.assertEqual(od.documents_folder("linux", home, run=lambda *a, **k: R("/home/u/Dokumente\n")),
                         Path("/home/u/Dokumente"))
        self.assertEqual(od.documents_folder("linux", home, run=lambda *a, **k: R("/home/u\n")),
                         home / "Documents")
        self.assertEqual(od.default_oui_path(platform="darwin", home=home), home / "Documents" / "oui.txt")

    def test_download_success(self):
        import ouidownload as od
        seen = []
        r = od.download_oui(self.dest, self.base + "/oui.txt", progress=lambda d, t: seen.append((d, t)))
        self.assertEqual(r.entries, 1200)
        self.assertEqual(self.dest.read_bytes(), self.body)
        self.assertEqual(seen[-1], (len(self.body), len(self.body)))
        self.assertFalse(self.dest.with_name("oui.txt.download").exists())
        db = core.OuiDatabase()
        db.load_file(str(self.dest))
        self.assertEqual(len(db), 1200)

    def test_bad_downloads_keep_existing_file(self):
        import ouidownload as od
        self.dest.parent.mkdir(parents=True)
        self.dest.write_text("old copy")
        with self.assertRaises(od.DownloadError) as cm:
            od.download_oui(self.dest, self.base + "/html")
        self.assertIn("isn't the IEEE oui.txt", str(cm.exception))
        with self.assertRaises(od.DownloadError) as cm:
            od.download_oui(self.dest, self.base + "/missing")
        self.assertIn("HTTP 404", str(cm.exception))
        with self.assertRaises(od.DownloadError) as cm:
            od.download_oui(self.dest, "http://127.0.0.1:1/oui.txt", timeout=3)
        self.assertIn("Couldn't reach", str(cm.exception))
        self.assertEqual(self.dest.read_text(), "old copy")
        self.assertEqual(sorted(p.name for p in self.dest.parent.iterdir()), ["oui.txt"])

    def test_cancel(self):
        import threading
        import ouidownload as od
        stop = threading.Event()
        stop.set()
        with self.assertRaises(od.DownloadCancelled):
            od.download_oui(self.dest, self.base + "/oui.txt", stop=stop)
        self.assertFalse(self.dest.exists())

    def test_tls_fallback_flag(self):
        import ssl
        import urllib.error
        import ouidownload as od
        calls = []

        def opener(url, timeout, verify):
            calls.append(verify)
            if verify:
                raise urllib.error.URLError(ssl.SSLError("CERTIFICATE_VERIFY_FAILED"))
            return od._open(self.base + "/oui.txt", timeout, True)
        r = od.download_oui(self.dest, "https://example.invalid/oui.txt", opener=opener)
        self.assertEqual(calls, [True, False])
        self.assertFalse(r.verified)


class SendToTests(unittest.TestCase):
    def test_pick_parts(self):
        import sendto as st
        self.assertEqual(st.first_subnet("interface Gi0/1\n ip address 10.1.2.3 255.255.255.0"), "10.1.2.3 255.255.255.0")
        self.assertEqual(st.first_subnet("route 10.20.0.0/22 via 192.0.2.1"), "10.20.0.0/22")
        self.assertEqual(st.first_subnet("prefix 2001:db8::/48 here"), "2001:db8::/48")
        self.assertEqual(st.first_target("2026-10-10 14:30:00 core1.example.com up"), "core1.example.com")
        self.assertEqual(st.first_target(" 3  ae1.cr1.example.net (203.0.113.9)"), "ae1.cr1.example.net")
        self.assertEqual(st.first_target("mac aa:bb:cc:dd:ee:ff ip fe80::1"), "fe80::1")
        self.assertEqual(st.data_amount("10 Gbps"), ("10", "gigabits"))
        self.assertEqual(st.data_amount("1.5GB file"), ("1.5", "gigabytes"))
        self.assertEqual(st.data_amount("1,500"), ("1500", None))
        self.assertEqual(st.data_amount("none"), (None, None))
        self.assertEqual(st.token_at("ip address 10.1.1.1 255.255.255.0", 13), "10.1.1.1 255.255.255.0")
        self.assertEqual(st.token_at("see example.com.", 8), "example.com")
        self.assertEqual(st.token_at("a  b", 2), "")
        self.assertEqual(str(st.first_datetime("2026-10-01 08:00 x")), "2026-10-01 08:00:00")
        self.assertIsNone(st.first_datetime("no date here"))
        self.assertEqual(st.preview("one\ntwo\n\nthree"), "one  (+2 lines)")

    def test_ping_list(self):
        import re
        import sendto as st
        acc = lambda t: bool(re.match(r"[\d.:/-]+$|.*\.\w+$", t))
        self.assertEqual(st.ping_list("192.0.2.1 Core router\n198.51.100.1-4 Lab", acc),
                         "192.0.2.1 Core router\n198.51.100.1-4 Lab\n")
        self.assertEqual(st.ping_list("Oct 10 rtr1 neighbor 203.0.113.5 Down\nnbr 2001:db8::9", acc),
                         "203.0.113.5\n2001:db8::9\n")
        self.assertEqual(st.ping_list("8.8.8.8 1.1.1.1", acc), "8.8.8.8\n1.1.1.1\n")
        self.assertEqual(st.ping_list("router1", acc), "router1\n")
        self.assertEqual(st.ping_list("nothing useful", acc), "")


class TextTableTests(unittest.TestCase):
    def test_format_table(self):
        import texttable as tt
        out = tt.format_table(("Name", "Count", "Note"), [("a", 5, "x"), ("longer", 120, "")])
        self.assertEqual(out.splitlines(), ["Name    Count  Note", "------  -----  ----",
                                            "a           5  x", "longer    120"])
        self.assertEqual(tt.format_table(("Size",), [("\U0001D7ED\U0001D7F1\U0001D7EC\U0001D7EC",)]).splitlines()[2],
                         "1500")
        self.assertEqual(tt.format_table(None, []), "")

    def test_align_tabs(self):
        import texttable as tt
        text = ";; ANSWER SECTION:\nexample.com.\t3600\tIN\tA\t192.0.2.1\nwww.example.com.\t300\tIN\tCNAME\texample.com.\n"
        lines = tt.align_tabs(text).splitlines()
        self.assertEqual(lines[0], ";; ANSWER SECTION:")
        self.assertEqual(lines[1].index("IN"), lines[2].index("IN"))
        self.assertNotIn("\t", tt.align_tabs(text))


class IrrRpkiTests(unittest.TestCase):
    """IRR expansion against a tiny in-process IRRd, RFC 6811 validation, and the filter renderers."""

    @classmethod
    def setUpClass(cls):
        import socketserver
        import threading
        sets = {"AS-EXAMPLE": ["AS64500", "AS64501", "AS-SUB"], "AS-SUB": ["AS64502", "AS-EXAMPLE"]}
        v4 = {"AS64500": "192.0.2.0/24 198.51.100.0/24 198.51.100.128/25", "AS64501": "203.0.113.0/24",
              "AS64502": "100.64.0.0/10 100.64.1.0/26"}
        v6 = {"AS64500": "2001:db8::/32 2001:db8:1::/48"}

        def flat(name, seen):
            out = []
            for m in sets.get(name, []):
                if m in sets:
                    if m not in seen:
                        seen.add(m)
                        out += flat(m, seen)
                elif m not in out:
                    out.append(m)
            return out

        class H(socketserver.StreamRequestHandler):
            def handle(self):
                for line in self.rfile:
                    q = line.decode().strip()
                    if q in ("!!", ""):
                        continue
                    if q == "q":
                        return
                    if q[:2] in ("!n", "!s"):
                        self.wfile.write(b"C\n")
                        continue
                    if q.startswith("!r"):
                        pfx, _, opt = q[2:].partition(",")
                        objs = {"192.0.2.0/24": "route: 192.0.2.0/24\ndescr: Customer A\norigin: AS64500\nsource: RADB",
                                "192.0.0.0/16": "route: 192.0.0.0/16\norigin: AS64999\nsource: RIPE",
                                "192.0.2.128/25": "route: 192.0.2.128/25\norigin: AS64501\nsource: RADB"}
                        hit = {"": ["192.0.2.0/24"], "L": ["192.0.2.0/24", "192.0.0.0/16"],
                               "M": ["192.0.2.128/25"]}.get(opt, []) if pfx == "192.0.2.0/24" else []
                        data = "\n\n".join(objs[h] for h in hit)
                        self.wfile.write(b"A%d\n%s\nC\n" % (len(data), data.encode()) if data else b"D\n")
                        continue
                    if q.startswith("!i"):
                        name = q[2:].split(",")[0]
                        if name not in sets:
                            self.wfile.write(b"D\n")
                            continue
                        data = " ".join(flat(name, {name}))
                    else:
                        data = (v4 if q[1] == "g" else v6).get(q[2:], "")
                    if not data:
                        self.wfile.write(b"C\n")
                    else:
                        self.wfile.write(b"A%d\n%s\nC\n" % (len(data), data.encode()))

        cls.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
        cls.srv.daemon_threads = True
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_parse_queries(self):
        import irrtool as it
        good, bad = it.parse_queries("as65000, AS-foo 64500 AS15169:AS-GOOGLE junk!")
        self.assertEqual(good, ["AS65000", "AS-FOO", "AS64500", "AS15169:AS-GOOGLE"])
        self.assertEqual(bad, ["junk!"])
        self.assertEqual(it.default_name(["AS15169:AS-GOOGLE"]), "AS15169_AS-GOOGLE")

    def test_expand(self):
        import irrtool as it
        res = it.expand(["AS-EXAMPLE", "AS-MISSING"], "127.0.0.1", "RADB", port=self.srv.server_address[1])
        self.assertEqual(res.asns, ["AS64500", "AS64501", "AS64502"])
        self.assertEqual(res.per_asn["AS64500"], (3, 2))
        self.assertEqual(len(res.routes), 8)
        self.assertTrue(any("AS-MISSING" in w for w in res.warnings))

    def test_prefix_lookup(self):
        import irrtool as it
        q, bad = it.parse_queries("192.0.2.0/24 2001:db8::1 192.0.2.999")
        self.assertEqual(q, ["192.0.2.0/24", "2001:db8::1/128"])
        self.assertEqual(bad, ["192.0.2.999"])
        port = self.srv.server_address[1]
        res = it.expand(["192.0.2.0/24"], "127.0.0.1", port=port)
        got = {(r.prefix, r.origin, r.source, r.found) for r in res.routes}
        self.assertEqual(got, {("192.0.2.0/24", "AS64500", "RADB", "exact 192.0.2.0/24"),
                               ("192.0.0.0/16", "AS64999", "RIPE", "covering 192.0.2.0/24")})
        self.assertEqual(res.per_asn["AS64999"], (1, 0))
        more = it.expand(["192.0.2.0/24"], "127.0.0.1", port=port, prefix_match="Exact and more specific")
        self.assertEqual(sorted(r.prefix for r in more.routes), ["192.0.2.0/24", "192.0.2.128/25"])
        objs = it.parse_rpsl("route: 192.0.2.0/24\ndescr: one\ndescr: two\norigin: AS1\n\nroute6: 2001:db8::/32\norigin: AS2")
        self.assertEqual(objs[0]["descr"], "one / two")
        self.assertEqual(objs[1]["route6"], "2001:db8::/32")

    def test_other_sources(self):
        import json
        import irrtool as it
        vrps = json.dumps({"roas": [{"prefix": "198.18.0.0/15", "maxLength": 24, "asn": "AS64500"},
                                    {"asn": 64500, "prefix": "192.0.2.0/24", "maxLength": 24},
                                    {"prefix": "203.0.113.0/24", "maxLength": 24, "asn": "AS64999"}]})
        self.assertEqual(sorted(it.roas_for_asns(vrps, ["AS64500"])),
                         [("192.0.2.0/24", 24, "AS64500"), ("198.18.0.0/15", 24, "AS64500")])
        res = it.Expansion(["AS64500"], asns=["AS64500"], members=["AS64500"],
                           routes=[it.Route("192.0.2.0/24", "AS64500", 4)])
        it.merge_route(res, "192.0.2.0/24", "AS64500", "BGP")
        it.merge_route(res, "198.18.0.0/16", "AS64500", "BGP", found="announced in BGP")
        it.merge_route(res, "2001:db8::/32", "AS64500", "BGP", ipv6=False)
        it.finish_expansion(res)
        rows = {r.prefix: r for r in res.routes}
        self.assertEqual(rows["192.0.2.0/24"].where, "IRR, BGP")
        self.assertFalse(rows["198.18.0.0/16"].in_irr)
        self.assertNotIn("2001:db8::/32", rows)
        self.assertEqual(res.per_asn["AS64500"], (2, 0))
        it.apply_filters(res.routes, require_irr=True)
        self.assertEqual(rows["198.18.0.0/16"].excluded, "No IRR route object")

    def test_asn_sources(self):
        import asnsources
        import arinwhois

        def fake_fetch(url, accept="application/json", timeout=15.0, cache=None, source=""):
            if "ripestat" in url:
                return {"data": {"prefixes": [{"prefix": "192.0.2.0/24"}, {"prefix": "198.18.0.0/16"}]}}
            if url.endswith("/asn/AS64500.json"):
                return {"asn": {"orgRef": {"@handle": "EXO-1", "@name": "Example Org"}}}
            if url.endswith("/asn/AS64501.json"):
                return {"asn": {"orgRef": {"@handle": "RIPE", "@name": "RIPE NCC"}}}
            if url.endswith("/org/EXO-1/nets.json"):
                return {"nets": {"netRef": {"@startAddress": "198.18.0.0", "@endAddress": "198.19.255.255",
                                            "@handle": "NET-1", "@name": "BENCH"}}}
            err = arinwhois.WhoisError("No record found")
            err.not_found = True
            raise err

        orig = arinwhois.fetch_url
        arinwhois.fetch_url = fake_fetch
        try:
            self.assertEqual(asnsources.announced_prefixes("AS64500", url="https://ripestat/{asn}"),
                             ["192.0.2.0/24", "198.18.0.0/16"])
            org, nets, note = asnsources.arin_networks("AS64500", base="https://arin/rest")
            self.assertEqual((org, nets, note), ("Example Org", [("198.18.0.0/15", "NET-1", "BENCH")], ""))
            self.assertIn("RIPE", asnsources.arin_networks("AS64501", base="https://arin/rest")[2])
            self.assertEqual(asnsources.arin_networks("AS64502", base="https://arin/rest"), ("", [], ""))
        finally:
            arinwhois.fetch_url = orig

    def test_rpki_and_render(self):
        import json
        import irrtool as it
        res = it.expand(["AS-EXAMPLE"], "127.0.0.1", port=self.srv.server_address[1])
        vrps = json.dumps({"roas": [
            {"prefix": "192.0.2.0/24", "maxLength": 24, "asn": "AS64500"},
            {"asn": 64500, "prefix": "198.51.100.0/24", "maxLength": 24},
            {"prefix": "203.0.113.0/24", "maxLength": 24, "asn": "AS64999"},
            {"prefix": "2001:db8::/32", "maxLength": 48, "asn": "AS64500"}]})
        it.check_rpki(res.routes, vrps)
        state = {r.prefix: r.rpki for r in res.routes}
        self.assertEqual(state["192.0.2.0/24"], "Valid")
        self.assertEqual(state["198.51.100.128/25"], "Invalid")      # too specific
        self.assertEqual(state["203.0.113.0/24"], "Invalid")         # wrong origin
        self.assertEqual(state["100.64.0.0/10"], "Not found")
        self.assertEqual(state["2001:db8:1::/48"], "Valid")
        it.apply_filters(res.routes, leave_out_invalid=True, max4=24, max6=48)
        v4 = it.build_entries(res.routes, 4)
        v6 = it.build_entries(res.routes, 6, more_specifics=48)
        self.assertEqual([e.prefix for e in v4], ["100.64.0.0/10", "192.0.2.0/24", "198.51.100.0/24"])
        self.assertEqual([(e.prefix, e.le) for e in v6], [("2001:db8::/32", 48)])
        xr = it.render(it.FORMATS[0], "AS-EXAMPLE", v4, v6)
        self.assertIn("prefix-set AS-EXAMPLE-V4\n  100.64.0.0/10,\n  192.0.2.0/24,\n  198.51.100.0/24\nend-set", xr)
        self.assertIn("2001:db8::/32 le 48\nend-set", xr)
        xe = it.render(it.FORMATS[1], "X", v4, [])
        self.assertIn("ip prefix-list X-V4 seq 5 permit 100.64.0.0/10", xe)
        self.assertIn("ipv6 prefix-list X-V6 seq 5 deny ::/0", xe)
        junos = it.render(it.FORMATS[3], "X", v4, v6)
        self.assertIn("set policy-options prefix-list X-V4 192.0.2.0/24", junos)
        self.assertIn("set policy-options route-filter-list X-V6 2001:db8::/32 upto /48", junos)
        eos = it.render(it.FORMATS[4], "X", v4, v6)
        self.assertIn("ip prefix-list X-V4\n   seq 10 permit 100.64.0.0/10", eos)
        it.mark_in_filter(res.routes, v4 + v6)
        status = {r.prefix: r.in_filter for r in res.routes}
        self.assertEqual(status["192.0.2.0/24"], "Yes – exact")
        self.assertEqual(status["2001:db8::/32"], "Yes – 2001:db8::/32 le 48")
        self.assertEqual(status["2001:db8:1::/48"], "Yes – inside 2001:db8::/32 le 48")
        self.assertEqual(status["203.0.113.0/24"], "No – RPKI invalid")
        bad = it.Route("2001:db8:ff::/48", "AS64999", 6, rpki="Invalid")
        it.apply_filters([bad])
        it.mark_in_filter([bad], v6)
        self.assertTrue(bad.leaks)
        self.assertIn("still matches it", bad.in_filter)
        md = it.render("Nokia SR OS (MD-CLI)", "X", v4, v6)
        self.assertIn('prefix-list "X-V4" {\n    prefix 100.64.0.0/10 type exact {\n    }', md)
        self.assertIn("prefix 2001:db8::/32 type through {\n        through-length 48\n    }", md)
        classic = it.render("Nokia SR OS (classic CLI)", "X", v4, v6)
        self.assertIn('no prefix-list "X-V6"\nprefix-list "X-V6"\n    prefix 2001:db8::/32 through 48\nexit', classic)
        self.assertTrue(classic.rstrip().endswith("commit"))
        srl = it.render("Nokia SR Linux (prefix-set)", "X", v4, v6)
        self.assertIn("set / routing-policy prefix-set X-V6 prefix 2001:db8::/32 mask-length-range 32..48", srl)
        self.assertIn("prefix-set X-V4 prefix 192.0.2.0/24 mask-length-range exact", srl)


class PingExplainTests(unittest.TestCase):
    def test_explain(self):
        import pinger
        mac = pinger.explain_command("ping -c 1 -W 2000 8.8.8.8", "mac")
        self.assertIn("-W 2000: wait up to 2000 ms", mac)
        self.assertIn("packet size: default (56 bytes", mac)
        self.assertIn("-s 1500: 1500-byte payload", pinger.explain_command("ping -c 1 -W 2 -s 1500 1.1.1.1", "linux"))
        self.assertIn("default (32 bytes", pinger.explain_command("ping -n 1 -w 2000 -4 1.1.1.1", "windows"))


class BandwidthCostTests(unittest.TestCase):
    def test_compute(self):
        import bwcost as b
        r = b.compute(b.Quote(monthly=1500, term_months=36, mbps=10000, one_time=1800, users=450, utilization=40))
        self.assertAlmostEqual(r.effective_monthly, 1550)
        self.assertAlmostEqual(r.total, 55800)
        self.assertAlmostEqual(r.per_mbps, 0.155)
        self.assertAlmostEqual(r.per_gbps, 155)
        self.assertAlmostEqual(r.per_user, 1550 / 450)
        self.assertAlmostEqual(r.mbps_per_user, 10000 / 450)
        # 10 Gbps at 40% for an average month: 10e9/8 * 2629746 s * 0.4 = 1,314,873 GB
        self.assertAlmostEqual(r.gb_per_month, 1314873, places=0)
        with self.assertRaises(ValueError):
            b.compute(b.Quote(monthly=100, term_months=0, mbps=100))
        up = b.compute(b.Quote(monthly=1500, term_months=36, mbps=10000, one_time=1800, spread_one_time=False,
                               users=450))
        self.assertAlmostEqual(up.effective_monthly, 1500)
        self.assertAlmostEqual(up.first_month, 3300)
        self.assertAlmostEqual(up.total, 55800)                 # one-time cost still counted in the total
        self.assertAlmostEqual(up.per_mbps, 0.15)
        self.assertAlmostEqual(up.per_user_term, 55800 / 450)
        cap = b.compute(b.Quote(monthly=0, term_months=60, mbps=None, one_time=50000, users=1000))
        self.assertAlmostEqual(cap.per_user, 50000 / 60 / 1000)
        self.assertAlmostEqual(cap.per_user_term, 50.0)
        self.assertIsNone(cap.per_mbps)
        self.assertIsNone(cap.per_gb)
        with self.assertRaises(ValueError):                        # no bandwidth and no users
            b.compute(b.Quote(monthly=100, term_months=12, mbps=None))
        with self.assertRaises(ValueError):                        # nothing to divide
            b.compute(b.Quote(monthly=0, term_months=12, mbps=None, users=10))

    def test_format_and_parse(self):
        import bwcost as b
        self.assertEqual(b.parse_number("$1,250.50"), 1250.5)
        self.assertEqual(b.parse_number("1.5k"), 1500)
        self.assertIsNone(b.parse_number("abc"))
        self.assertEqual(b.money(1234.5), "$1,234.50")
        self.assertEqual(b.money(0.155), "$0.1550")
        self.assertEqual(b.money(0.000456), "$0.000456")
        self.assertEqual(b.rate(10000), "10 Gbps")
        self.assertEqual(b.term_text(36), "3 years (36 months)")


class BadgeTests(unittest.TestCase):
    def test_badge_png(self):
        import base64
        import struct
        import badge
        data, w, h = badge.render([("(", "#000000"), ("12", "#15803d"), (")", "#000000")], 18)
        raw = base64.b64decode(data)
        self.assertTrue(raw.startswith(b"\x89PNG"))
        self.assertEqual(struct.unpack(">II", raw[16:24]), (w, h))
        self.assertEqual(h, 18)
        self.assertGreater(w, 20)
        self.assertTrue(badge.count_badge(3, "#dc2626", "#000000", 16))


class VersionTests(unittest.TestCase):
    def test_format(self):
        import re
        import version
        self.assertRegex(version.VERSION, r"^0\.\d{4}\.\d{3,4}(\.\d+)?$")
        y, md = version.VERSION.split(".")[1:3]
        self.assertEqual(version.RELEASE_DATE.replace("-", ""), y + md.zfill(4))
        t = version.version_tuple()
        self.assertEqual(len(t), 4)
        self.assertTrue(all(0 <= n <= 65535 for n in t))     # Windows version fields are 16-bit
        self.assertTrue(version.WEBSITE.startswith("https://"))
        self.assertIn(version.VERSION, version.USER_AGENT)
        self.assertTrue(re.match(r"^[A-Z][a-z]+ \d{1,2}, \d{4}$", version.pretty_date()))

    def test_windows_resource_parses(self):
        import ast
        import version
        text = version.windows_version_resource()
        ast.parse(text)                                           # PyInstaller evals this
        self.assertIn(version.VERSION, text)
        self.assertIn(version.BUILD_NAME + ".exe", text)


class HelpGenTests(unittest.TestCase):
    def test_convert(self):
        import helpgen
        md = ("# Title\n\nIntro with **bold**, `a<b>` and [site](https://x.net).\n\n## Part one\n\n"
              "- one\n  - nested\n- two\n\n1. first\n2. second\n\n### Sub\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n"
              "```\ncode <x>\n```\n\n## Part one\n")
        body, toc = helpgen.convert(md)
        self.assertIn("<strong>bold</strong>", body)
        self.assertIn("<code>a&lt;b&gt;</code>", body)
        self.assertIn('<a href="https://x.net" target="_blank" rel="noopener">site</a>', body)
        self.assertIn("<ul><li>one<ul><li>nested</li></ul></li><li>two</li></ul>", body.replace("\n", ""))
        self.assertIn("<ol><li>first</li><li>second</li></ol>", body.replace("\n", ""))
        self.assertIn("<th>A</th>", body)
        self.assertIn("<pre><code>code &lt;x&gt;</code></pre>", body)
        self.assertEqual([t[1] for t in toc], ["part-one", "sub", "part-one-2"])
        for tag in ("ul", "ol", "li", "table", "p"):
            self.assertEqual(body.count(f"<{tag}>") + body.count(f"<{tag} "), body.count(f"</{tag}>"), tag)

    def test_build(self):
        import tempfile
        from pathlib import Path
        import helpgen
        import version
        with tempfile.TemporaryDirectory() as d:
            out = helpgen.build(output=Path(d) / "help" / "index.html")
            page = out.read_text(encoding="utf-8")
        self.assertIn(version.VERSION, page)
        self.assertIn(version.WEBSITE, page)
        self.assertNotIn("{{", page)
        self.assertIn("Keyboard shortcuts", page)


BULK_SAMPLE = """Bulk mode; whois.cymru.com [2026-10-12 14:02:11 +0000]
15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 2023-12-28 | GOOGLE - Google LLC, US
15169   | 8.8.8.0          | 8.8.8.0/24          | US | arin     | 2023-12-28 | GOOGLE - Google LLC, US
NA      | 192.0.2.77       | NA                  |    | other    |            | NA
13335   | 203.0.113.9      | 203.0.113.0/24      | AU | apnic    | 2011-08-11 | CLOUDFLARENET - Cloudflare, Inc., US
64500   | 203.0.113.9      | 203.0.113.0/24      | AU | apnic    | 2011-08-11 | EXAMPLE-AS - Example, US
15169   | 2001:4860:4860::8888 | 2001:4860::/32   | US | arin     | 2005-03-14 | GOOGLE - Google LLC, US
15169   | US | arin     | 2000-03-30 | GOOGLE - Google LLC, US
3356    | US | arin     | 2000-03-10 | LEVEL3 - Level 3 Parent, LLC, US
4294967 |    |          |            | NA
"""


class CymruTests(unittest.TestCase):
    def test_query_key(self):
        import cymru
        self.assertEqual(cymru.query_key("AS15169"), ("asn", "15169"))
        self.assertEqual(cymru.query_key("as 15169"), ("asn", "15169"))
        self.assertEqual(cymru.query_key("AS1.10"), ("asn", "65546"))
        self.assertEqual(cymru.query_key("8.8.8.0/24"), ("ip", "8.8.8.0"))
        self.assertEqual(cymru.query_key("2001:DB8::1"), ("ip", "2001:db8::1"))
        with self.assertRaises(cymru.CymruError):
            cymru.query_key("NET-8-8-8-0-2")

    def test_build_and_parse(self):
        import cymru
        self.assertEqual(cymru.build_bulk([("ip", "8.8.8.8"), ("asn", "15169")]),
                         b"begin\nverbose\n8.8.8.8\nAS15169\nend\n")
        ips, asns, errs = cymru.parse_bulk(BULK_SAMPLE + "Error: no ASN or IP match on line 9.\n")
        self.assertEqual(set(ips), {"8.8.8.8", "8.8.8.0", "192.0.2.77", "203.0.113.9", "2001:4860:4860::8888"})
        self.assertEqual(len(ips["203.0.113.9"]), 2)
        self.assertEqual(set(asns), {"15169", "3356", "4294967"})
        self.assertEqual(len(errs), 1)
        r = cymru.record_from_ip_rows("8.8.8.8", ips["8.8.8.8"])
        self.assertEqual((r.origin, r.prefix, r.cc, r.registry_name, r.allocated, r.as_name),
                         ("AS15169", "8.8.8.0/24", "US", "ARIN", "2023-12-28", "GOOGLE - Google LLC, US"))
        moas = cymru.record_from_ip_rows("203.0.113.9", ips["203.0.113.9"])
        self.assertEqual(moas.origin, "AS13335 / AS64500")
        self.assertIn("Multiple origins", moas.note)
        dark = cymru.record_from_ip_rows("192.0.2.77", ips["192.0.2.77"])
        self.assertFalse(dark.announced)
        self.assertIn("Not announced", dark.note)
        self.assertEqual(dark.prefix, "")
        a = cymru.record_from_asn_rows("AS3356", asns["3356"])
        self.assertEqual((a.asn, a.as_name, a.registry_name), ("3356", "LEVEL3 - Level 3 Parent, LLC, US", "ARIN"))
        self.assertTrue(cymru.record_from_asn_rows("AS4294967", asns["4294967"]).error)

    def _server(self, reply: str):
        import socket
        import threading
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        got = []

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                data = b""
                while not data.endswith(b"end\n"):
                    chunk = c.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                got.append(data.decode())
                c.sendall(reply.encode())
                c.close()
        threading.Thread(target=serve, daemon=True).start()
        self.addCleanup(srv.close)
        return srv.getsockname()[1], got

    def test_whois_bulk_against_mock(self):
        import cymru
        port, got = self._server(BULK_SAMPLE)
        qs = ["8.8.8.8", "8.8.8.0/24", "AS15169", "15169", "2001:4860:4860::8888", "198.51.100.1", "bogus!"]
        out = cymru.whois_bulk(qs, host="127.0.0.1", port=port, timeout=5)
        self.assertEqual(len(got), 1)                          # one connection for the whole list
        self.assertEqual(got[0].count("8.8.8.0"), 1)
        self.assertEqual(got[0].count("AS15169"), 1)           # duplicates asked once
        self.assertEqual(out["8.8.8.8"].origin, "AS15169")
        self.assertEqual(out["8.8.8.0/24"].prefix, "8.8.8.0/24")
        self.assertIn("first address", out["8.8.8.0/24"].note)
        self.assertEqual(out["15169"].as_name, "GOOGLE - Google LLC, US")
        self.assertEqual(out["2001:4860:4860::8888"].prefix, "2001:4860::/32")
        self.assertTrue(out["198.51.100.1"].error)
        self.assertTrue(out["bogus!"].error)

    def test_auto_falls_back_to_dns(self):
        import cymru
        answers = {
            "8.8.8.8.origin.asn.cymru.com": ["15169 | 8.8.8.0/24 | US | arin | 2023-12-28",
                                             "15169 | 8.0.0.0/9 | US | arin | 1992-12-01"],
            "AS15169.asn.cymru.com": ["15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"],
            "AS13335.asn.cymru.com": ["13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"],
            "AS64500.asn.cymru.com": ["64500 | US | arin | 2010-07-14 | EXAMPLE"],
            "1.1.1.1.origin.asn.cymru.com": ["13335 64500 | 1.1.1.0/24 | AU | apnic | 2011-08-11"],
        }
        asked = []

        def resolver(name, server, timeout):
            asked.append(name)
            return answers.get(name, [])

        def refuse(addr, timeout=None):
            raise ConnectionRefusedError(111, "Connection refused")
        out, note = cymru.lookup_many(["8.8.8.8", "AS15169", "1.1.1.1", "192.0.2.1"], via="auto",
                                      connect=refuse, resolver=resolver, dns_server="192.0.2.53")
        self.assertIn("used DNS", note)
        r = out["8.8.8.8"]
        self.assertEqual((r.prefix, r.as_name, r.source), ("8.8.8.0/24", "GOOGLE - Google LLC, US", "DNS"))
        self.assertEqual(out["AS15169"].allocated, "2000-03-30")
        self.assertEqual(out["1.1.1.1"].origin, "AS13335 / AS64500")
        self.assertFalse(out["192.0.2.1"].announced)
        self.assertEqual(asked.count("AS15169.asn.cymru.com"), 1)          # AS names cached
        out, note = cymru.lookup_many(["8.8.8.8"], via="whois", connect=refuse)
        self.assertTrue(out["8.8.8.8"].error)
        calls = []

        def dead(name, server, timeout):
            calls.append(name)
            raise OSError("no reply")
        out, note = cymru.lookup_many([f"8.8.8.{i}" for i in range(10)], via="dns", resolver=dead, dns_server="x")
        self.assertEqual(len(calls), 1)                                    # the sanity check fails: stop there
        self.assertTrue(all(r.error for r in out.values()))
        self.assertIn("DNS lookup failed", note)
        out, note = cymru.lookup_many(["8.8.8.8", "AS3356"], via="dns", resolver=lambda *a: [], dns_server="x")
        self.assertTrue(all("can't be trusted" in r.error for r in out.values()))   # filtered resolver
        flaky = {"n": 0}

        def some_dead(name, server, timeout):
            if name == "AS15169.asn.cymru.com":
                return ["15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"]
            flaky["n"] += 1
            raise OSError("no reply")
        out, _ = cymru.lookup_many([f"8.8.8.{i}" for i in range(10)], via="dns", resolver=some_dead, dns_server="x")
        self.assertEqual(flaky["n"], 3)                                    # gives up after 3 dead queries

    def test_origin6_and_format(self):
        import cymru
        n = cymru.origin_name("2001:db8::1")
        self.assertTrue(n.startswith("1.0.0.0.") and n.endswith("8.b.d.0.1.0.0.2.origin6.asn.cymru.com"))
        self.assertEqual(len(n.split(".")), 32 + 4)
        rec = cymru.CymruRecord(query="8.8.8.8", kind="ip", asns=["15169"], prefix="8.8.8.0/24", cc="US",
                                registry="arin", allocated="2023-12-28", as_name="GOOGLE", source="whois")
        text = cymru.format_record(rec)
        self.assertIn("AS15169", text)
        self.assertIn("8.8.8.0/24", text)


def pdb_fixture():
    """A small fake PeeringDB: path -> rows, built from AS10279's public record."""
    net = {"id": 20321, "org_id": 27000, "name": "West Carolina Communications",
           "aka": "West Carolina Telephone, WCFIBER/UPCOUNTRY FIBER", "name_long": "", "website": "http://www.wctel.com",
           "social_media": [], "asn": 10279, "looking_glass": "", "route_server": "", "irr_as_set": "AS-WCCOM",
           "info_type": "NSP", "info_types": ["NSP"], "info_prefixes4": 142, "info_prefixes6": 0, "info_traffic": "",
           "info_ratio": "Mostly Inbound", "info_scope": "Regional", "info_unicast": True, "info_multicast": False,
           "info_ipv6": False, "info_never_via_route_servers": False, "notes": "",
           "netixlan_updated": "2024-07-24T16:31:39Z", "netfac_updated": "2022-08-24T19:17:49Z",
           "poc_updated": "2026-10-06T17:11:30Z", "policy_url": "", "policy_general": "Selective",
           "policy_locations": "Not Required", "policy_ratio": False, "policy_contracts": "Not Required",
           "netfac_set": [
               {"id": 1, "name": "Digital Realty CLT (113 N Myers St)", "city": "Charlotte", "country": "US",
                "fac_id": 501, "local_asn": 10279},
               {"id": 2, "name": "CoreSite - Atlanta (AT1)", "city": "Atlanta", "country": "US", "fac_id": 502,
                "local_asn": 10279}],
           "netixlan_set": [{"id": 9, "ix_id": 800, "name": "Digital Realty Atlanta", "ixlan_id": 801, "speed": 100000,
                             "asn": 10279, "ipaddr4": "206.126.110.58", "ipaddr6": "2001:504:17:110::58",
                             "is_rs_peer": False, "bfd_support": False, "operational": True, "net_side_id": 502}],
           "poc_set": [{"id": 3, "role": "NOC", "visible": "Public", "name": "NOC", "phone": "",
                        "email": "noc@wctel.com", "url": ""}],
           "status_dashboard": "", "rir_status": "ok", "rir_status_updated": "2024-06-26T04:47:55Z",
           "updated": "2026-10-06T17:11:31Z", "status": "ok"}
    org = {"id": 27000, "name": "West Carolina Communications, LLC", "website": "", "aka": "", "name_long": "",
           "address1": "233 Highway 28 Bypass", "city": "Abbeville", "state": "SC", "zipcode": "29620",
           "country": "US", "updated": "2026-01-01T00:00:00Z"}
    ix = {"id": 800, "org_id": 27001, "name": "Digital Realty Atlanta", "city": "Atlanta", "country": "US",
          "region_continent": "North America", "media": "Ethernet", "proto_unicast": True, "proto_ipv6": True,
          "proto_multicast": False, "tech_email": "noc@example.net", "website": "https://example.net"}
    other = dict(net, id=555, name="Example Transit", asn=64500, org_id=27001, netixlan_set=[], netfac_set=[],
                 poc_set=[], policy_general="Open")
    routes = {
        ("net", (("asn", "10279"), ("depth", "2"))): [net],
        ("net/20321", (("depth", "2"),)): [net],
        ("net/555", (("depth", "2"),)): [other],
        ("org/27000", (("depth", "0"),)): [org],
        ("org/27001", (("depth", "0"),)): [{"id": 27001, "name": "Digital Realty"}],
        ("netixlan", (("ipaddr4", "206.126.110.58"),)): [dict(net["netixlan_set"][0], net_id=20321)],
        ("netixlan", (("ipaddr6", "2001:504:17:110::58"),)): [dict(net["netixlan_set"][0], net_id=20321)],
        ("ix/800", (("depth", "0"),)): [ix],
        ("netixlan", (("ix_id", "800"), ("limit", "5000"))): [
            dict(net["netixlan_set"][0], net_id=20321),
            {"net_id": 555, "asn": 64500, "ipaddr4": "206.126.110.9", "ipaddr6": None, "speed": 400000,
             "is_rs_peer": True, "bfd_support": True}],
        ("net", (("ix_id", "800"), ("limit", "5000"))): [net, other],
        ("ixfac", (("ix_id", "800"),)): [{"fac_id": 502, "name": "CoreSite - Atlanta (AT1)", "city": "Atlanta",
                                         "country": "US"}],
        ("ixlan", (("depth", "2"), ("ix_id", "800"))): [{"id": 801, "mtu": 1500, "dot1q_support": False,
                                                          "ixpfx_set": [{"protocol": "IPv4",
                                                                         "prefix": "206.126.110.0/23",
                                                                         "in_dfz": True}]}],
        ("net", (("limit", "25"), ("name__contains", "carolina"))): [net],
        ("ix", (("limit", "25"), ("name__contains", "carolina"))): [],
        ("fac", (("limit", "25"), ("name__contains", "carolina"))): [],
        ("org", (("limit", "25"), ("name__contains", "carolina"))): [org],
    }
    return routes


def pdb_fake_fetch(routes, seen=None):
    import arinwhois
    import urllib.parse

    def fetch(url, accept, timeout, cache, source, headers=None):
        if seen is not None:
            seen.append((url, headers))
        u = urllib.parse.urlsplit(url)
        path = u.path.split("/api/", 1)[1]
        key = (path, tuple(sorted(urllib.parse.parse_qsl(u.query))))
        if key not in routes:
            if path.split("/")[0] in ("net", "ix", "fac", "org") and "/" in path:
                return {"data": []}
            if path in ("netixlan", "net", "ix", "fac", "org", "ixfac", "netfac", "ixlan"):
                return {"data": []}
            err = arinwhois.WhoisError("No record found")
            err.not_found, err.status = True, 404
            raise err
        return {"data": routes[key]}
    return fetch


class PeeringDBTests(unittest.TestCase):
    def client(self, key="", seen=None):
        import peeringdb
        return peeringdb.Client(api_key=key, base="https://pdb.test/api", fetch=pdb_fake_fetch(pdb_fixture(), seen))

    def test_classify(self):
        import peeringdb as p
        self.assertEqual(p.classify("https://www.peeringdb.com/net/20321"), ("net", 20321))
        self.assertEqual(p.classify("peeringdb.com/ix/26"), ("ix", 26))
        self.assertEqual(p.classify("fac 501"), ("fac", 501))
        self.assertEqual(p.classify("AS10279"), ("asn", 10279))
        self.assertEqual(p.classify(" 10279 "), ("asn", 10279))
        self.assertEqual(p.classify("AS1.10"), ("asn", 65546))
        self.assertEqual(p.classify("206.126.110.58"), ("ip", "206.126.110.58"))
        self.assertEqual(p.classify("2001:504:17:110::58"), ("ip", "2001:504:17:110::58"))
        self.assertEqual(p.classify("west carolina"), ("search", "west carolina"))
        self.assertEqual(p.classify("   "), ("", ""))

    def test_speed_and_country(self):
        import peeringdb as p
        self.assertEqual([p.speed(x) for x in (100, 1000, 10000, 100000, 400000, 1200000, None)],
                         ["100M", "1G", "10G", "100G", "400G", "1.2T", ""])
        self.assertEqual(p.country("us"), "United States of America")
        self.assertEqual(p.country("ZZ"), "ZZ")

    def test_network_by_asn(self):
        import peeringdb as p
        seen = []
        rec = p.load(self.client(seen=seen), "asn", 10279)
        self.assertEqual((rec.kind, rec.title, rec.url), ("net", "West Carolina Communications",
                                                          "https://www.peeringdb.com/net/20321"))
        f = {x.label: x for x in rec.main[0].fields}
        labels = [x.label for x in rec.main[0].fields]
        self.assertEqual(labels[:3], ["Organization", "Also Known As", "Long Name"])
        self.assertEqual(f["Organization"].value, "West Carolina Communications, LLC")
        self.assertEqual(f["Organization"].link, "pdb:org/27000")
        self.assertEqual(f["Company Website Override"].link, "http://www.wctel.com")
        self.assertEqual(f["IRR as-set"].value, "AS-WCCOM")
        self.assertEqual(f["Traffic Levels"].value, "Not Disclosed")
        self.assertIn("☑ Unicast IPv4", f["Protocols Supported"].value)
        self.assertIn("☐ IPv6", f["Protocols Supported"].value)
        pol = {x.label: x.value for x in rec.side[0].fields}
        self.assertEqual((pol["General Policy"], pol["Ratio Requirement"]), ("Selective", "No"))
        cols, rows = rec.side[1].table
        self.assertEqual(rows, [["NOC", "NOC", "Public", "", "noc@wctel.com"]])
        self.assertIn("API key", rec.side[1].note)
        ixt, fact = rec.tables
        self.assertEqual(ixt.rows[0][:6], ["Digital Realty Atlanta", "10279", "206.126.110.58",
                                           "2001:504:17:110::58", "100G", "CoreSite - Atlanta (AT1)"])
        self.assertEqual(ixt.targets, ["pdb:ix/800"])
        self.assertEqual([r[0] for r in fact.rows], ["CoreSite - Atlanta (AT1)", "Digital Realty CLT (113 N Myers St)"])
        self.assertEqual(fact.rows[0][2], "United States of America")
        self.assertTrue(all(h is None for _, h in seen))                  # no key: no Authorization header
        text = p.record_text(rec)
        self.assertIn("IRR as-set", text)
        self.assertIn("Interconnection Facilities (2)", text)

    def test_api_key_header_and_errors(self):
        import arinwhois
        import peeringdb as p
        seen = []
        c = self.client(key=" abc123 ", seen=seen)
        rec = p.load(c, "net", 20321)
        self.assertEqual(seen[0][1], {"Authorization": "Api-Key abc123"})
        self.assertEqual(rec.side[1].note, "")
        calls = c.calls
        p.load(c, "net", 20321)
        self.assertEqual(c.calls, calls)                                   # cached
        with self.assertRaises(p.PdbError) as cm:
            p.load(self.client(), "asn", 64999)
        self.assertTrue(cm.exception.not_found)

        def limited(*a, **k):
            e = arinwhois.WhoisError("PeeringDB returned HTTP 429")
            e.status = 429
            raise e
        with self.assertRaises(p.PdbError) as cm:
            p.Client(fetch=limited).get("net", asn=1)
        self.assertIn("rate limit", str(cm.exception))
        self.assertIn("API key", str(cm.exception))

    def test_ip_ix_search_org(self):
        import peeringdb as p
        rec = p.load(self.client(), "ip", "2001:504:17:110::58")
        self.assertEqual(rec.tables[0].highlight, 0)
        self.assertIn("AS10279 West Carolina Communications on Digital Realty Atlanta (100G)", rec.note)
        with self.assertRaises(p.PdbError):
            p.load(self.client(), "ip", "192.0.2.1")
        ix = p.load(self.client(), "ix", 800)
        self.assertEqual(ix.url, "https://www.peeringdb.com/ix/800")
        peers = ix.tables[0]
        self.assertEqual([r[0] for r in peers.rows], ["Example Transit", "West Carolina Communications"])
        self.assertEqual(peers.rows[0][4:], ["400G", "Open", "Yes", "Yes"])
        self.assertEqual(peers.targets[1], "pdb:net/20321")
        self.assertTrue(any(s.title == "Prefixes" for s in ix.side))
        found = p.load(self.client(), "search", "carolina")
        self.assertEqual([r[:2] for r in found.tables[0].rows],
                         [["Network", "West Carolina Communications"], ["Organization", "West Carolina Communications, LLC"]])
        self.assertEqual(found.tables[0].targets, ["pdb:net/20321", "pdb:org/27000"])
        org = p.load(self.client(), "org", 27000)
        self.assertIn("Abbeville, SC 29620", [f for f in org.main[0].fields if f.label == "Address"][0].value)

    def test_no_insecure_fallback_with_key(self):
        import inspect
        import arinwhois
        src = inspect.getsource(arinwhois.fetch_url)
        self.assertIn("secret or isinstance(exc, urllib.error.HTTPError)", src)


if __name__ == "__main__":
    unittest.main()
