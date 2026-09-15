import XCTest
@testable import Ghostty

// The scanner's testable half. Everything here is the arithmetic, the
// reconciliation and the vault writes — the parts that can be wrong without a
// radio. The sockets themselves are exercised by running a real scan on a real
// network, which no unit test can honestly simulate.

// MARK: - Subnet arithmetic

final class LANSubnetTests: XCTestCase {
    func testParsesDottedQuads() {
        XCTAssertEqual(LANSubnet.parse("10.0.0.41"), 0x0a00_0029)
        XCTAssertEqual(LANSubnet.parse("255.255.255.0"), 0xffff_ff00)
        XCTAssertEqual(LANSubnet.parse("0.0.0.0"), 0)
        XCTAssertNil(LANSubnet.parse("10.0.0"))
        XCTAssertNil(LANSubnet.parse("10.0.0.256"))
        XCTAssertNil(LANSubnet.parse("10.0.0.a"))
        XCTAssertNil(LANSubnet.parse("10.0.0.1.1"))
        XCTAssertNil(LANSubnet.parse(""))
    }

    func testRendersDottedQuads() {
        XCTAssertEqual(LANSubnet.string(from: 0x0a00_0029), "10.0.0.41")
        XCTAssertEqual(LANSubnet.string(from: 0xffff_ffff), "255.255.255.255")
    }

    func testPrefixLengthFromMask() {
        XCTAssertEqual(LANSubnet.prefixLength(ofMask: 0xffff_ff00), 24)
        XCTAssertEqual(LANSubnet.prefixLength(ofMask: 0xffff_0000), 16)
        XCTAssertEqual(LANSubnet.prefixLength(ofMask: 0xffff_ffff), 32)
        XCTAssertEqual(LANSubnet.prefixLength(ofMask: 0), 0)
        XCTAssertEqual(LANSubnet.prefixLength(ofMask: 0xffff_fffc), 30)
    }

    func testRejectsDiscontiguousMask() {
        // 255.255.0.255 — legal to write, meaningless to enumerate. Guessing
        // what the user meant is how a scanner ends up sweeping the internet.
        XCTAssertNil(LANSubnet.prefixLength(ofMask: 0xffff_00ff))
        XCTAssertNil(LANSubnet(address: "10.0.0.41", netmask: "255.255.0.255"))
    }

    func testSlashTwentyFourEnumeratesHostsOnly() throws {
        let subnet = try XCTUnwrap(LANSubnet(address: "10.0.0.41", netmask: "255.255.255.0"))
        XCTAssertEqual(subnet.prefixLength, 24)
        XCTAssertEqual(subnet.cidr, "10.0.0.0/24")

        let addresses = subnet.hostAddresses()
        // 256 minus network, minus broadcast, minus ourselves.
        XCTAssertEqual(addresses.count, 253)
        XCTAssertEqual(addresses.first, "10.0.0.1")
        XCTAssertEqual(addresses.last, "10.0.0.254")
        XCTAssertFalse(addresses.contains("10.0.0.0"))
        XCTAssertFalse(addresses.contains("10.0.0.255"))
        XCTAssertFalse(addresses.contains("10.0.0.41"), "must not knock on ourselves")
        XCTAssertTrue(addresses.contains("10.0.0.42"))
    }

    func testKeepingSelfIsOptional() throws {
        let subnet = try XCTUnwrap(LANSubnet(address: "10.0.0.41", netmask: "255.255.255.0"))
        XCTAssertEqual(subnet.hostAddresses(excludingSelf: false).count, 254)
    }

    func testSlashTwentyFiveStaysInsideItsHalf() throws {
        let subnet = try XCTUnwrap(LANSubnet(address: "192.168.1.200", netmask: "255.255.255.128"))
        XCTAssertEqual(subnet.cidr, "192.168.1.128/25")
        let addresses = subnet.hostAddresses()
        XCTAssertEqual(addresses.first, "192.168.1.129")
        XCTAssertEqual(addresses.last, "192.168.1.254")
        XCTAssertFalse(addresses.contains("192.168.1.100"))
    }

    func testSlashThirty() throws {
        let subnet = try XCTUnwrap(LANSubnet(address: "10.9.9.2", netmask: "255.255.255.252"))
        XCTAssertEqual(subnet.hostAddresses(excludingSelf: false), ["10.9.9.1", "10.9.9.2"])
        XCTAssertEqual(subnet.hostAddresses(), ["10.9.9.1"])
    }

    func testSlashThirtyOneHasNoBroadcastToSkip() throws {
        let subnet = try XCTUnwrap(LANSubnet(address: "10.9.9.0", netmask: "255.255.255.254"))
        XCTAssertEqual(subnet.hostAddresses(excludingSelf: false), ["10.9.9.0", "10.9.9.1"])
    }

    func testWideNetworksAreClampedToASlashTwentyTwo() throws {
        let subnet = try XCTUnwrap(LANSubnet(address: "172.16.40.5", netmask: "255.255.0.0"))
        XCTAssertEqual(subnet.prefixLength, 16)
        XCTAssertTrue(subnet.isClamped)
        XCTAssertTrue(subnet.isLarge)
        XCTAssertEqual(subnet.effectivePrefixLength, 22)
        // The /22 containing .40.5, not the /22 at the bottom of the /16.
        XCTAssertEqual(subnet.cidr, "172.16.40.0/22")
        XCTAssertEqual(subnet.hostAddresses().count, 1021)
    }

    func testSlashTwentyFourIsNotWarnedAbout() throws {
        let subnet = try XCTUnwrap(LANSubnet(address: "10.0.0.41", netmask: "255.255.255.0"))
        XCTAssertFalse(subnet.isClamped)
        XCTAssertFalse(subnet.isLarge)
    }

    func testSlashTwentyThreeIsLargeButNotClamped() throws {
        let subnet = try XCTUnwrap(LANSubnet(address: "10.0.1.5", netmask: "255.255.254.0"))
        XCTAssertFalse(subnet.isClamped)
        XCTAssertTrue(subnet.isLarge)
        XCTAssertEqual(subnet.cidr, "10.0.0.0/23")
    }

    func testProbeCount() throws {
        let subnet = try XCTUnwrap(LANSubnet(address: "10.0.0.41", netmask: "255.255.255.0"))
        XCTAssertEqual(subnet.probeCount(ports: 18), 253 * 18)
    }

    func testAddressesSortNumericallyNotLexically() {
        let sorted = ["10.0.0.100", "10.0.0.9", "10.0.0.41"]
            .sorted(by: LANResultsMerge.addressLess)
        XCTAssertEqual(sorted, ["10.0.0.9", "10.0.0.41", "10.0.0.100"])
    }

    func testRealInterfaceLooksSane() throws {
        // Not an assertion about *this* machine's address — just that whatever
        // getifaddrs hands back parses and is not loopback or link-local.
        guard let interface = LANInterface.current() else {
            throw XCTSkip("no non-loopback IPv4 interface on this machine")
        }
        let subnet = try XCTUnwrap(interface.subnet)
        XCTAssertFalse(interface.address.hasPrefix("127."))
        XCTAssertFalse(interface.address.hasPrefix("169.254."))
        XCTAssertGreaterThan(subnet.hostAddresses().count, 0)
    }
}

// MARK: - Port → service mapping

final class PortCatalogTests: XCTestCase {
    func testCuratedPortsAreUnique() {
        let ports = PortCatalog.curated.map(\.port)
        XCTAssertEqual(Set(ports).count, ports.count)
    }

    func testSSHPortsAreFlaggedAndComeFirst() {
        XCTAssertTrue(PortCatalog.isSSH(22))
        XCTAssertTrue(PortCatalog.isSSH(2222))
        XCTAssertTrue(PortCatalog.isSSH(22222))
        XCTAssertTrue(PortCatalog.isSSH(830))
        XCTAssertFalse(PortCatalog.isSSH(80))
        XCTAssertFalse(PortCatalog.isSSH(445))

        // Port-major sweep order means the SSH ports being first is what makes
        // SSH hosts appear in the first seconds of a long scan.
        XCTAssertEqual(PortCatalog.curated.prefix(4).map(\.port), [22, 2222, 22222, 830])
    }

    func testServiceNamesAndSchemes() {
        XCTAssertEqual(PortCatalog.guess(for: 8006).service, "Proxmox VE")
        XCTAssertEqual(PortCatalog.guess(for: 8006).scheme, "https")
        XCTAssertEqual(PortCatalog.guess(for: 8123).service, "Home Assistant")
        XCTAssertEqual(PortCatalog.guess(for: 32400).service, "Plex")
        XCTAssertEqual(PortCatalog.guess(for: 443).scheme, "https")
        XCTAssertEqual(PortCatalog.guess(for: 80).scheme, "http")
        // Things a browser cannot open get no scheme, so the UI shows a bare
        // address rather than a link that fails.
        XCTAssertNil(PortCatalog.guess(for: 445).scheme)
        XCTAssertNil(PortCatalog.guess(for: 5900).scheme)
        XCTAssertNil(PortCatalog.guess(for: 3389).scheme)
    }

    func testUnknownPort() {
        let guess = PortCatalog.guess(for: 4711)
        XCTAssertEqual(guess.port, 4711)
        XCTAssertEqual(guess.service, "unknown")
        XCTAssertFalse(guess.isSSH)
        XCTAssertNil(guess.scheme)
    }

    func testLowPortsCoverOneToTenTwentyFour() {
        XCTAssertEqual(PortCatalog.lowPorts.count, 1024)
        XCTAssertEqual(PortCatalog.lowPorts.first, 1)
        XCTAssertEqual(PortCatalog.lowPorts.last, 1024)
    }

    func testBannerPromotesAnUnlistedPortToSSH() {
        // sshd on 2022 is not in the catalogue, but it introduced itself.
        let open = LANOpenPort(port: 2022, banner: "SSH-2.0-OpenSSH_9.6p1")
        XCTAssertTrue(open.isSSH)
        XCTAssertEqual(open.serviceName, "SSH")
    }

    func testSilentPortOnTwentyTwoIsStillTreatedAsSSH() {
        // The catalogue's opinion stands when nothing spoke.
        let open = LANOpenPort(port: 22, banner: nil)
        XCTAssertTrue(open.isSSH)
    }
}

// MARK: - Banner reading

final class TCPProbeBannerTests: XCTestCase {
    func testReadsFirstLine() {
        let data = Data("SSH-2.0-OpenSSH_9.6p1 Debian-3\r\nrest of the handshake".utf8)
        XCTAssertEqual(TCPProbe.banner(from: data), "SSH-2.0-OpenSSH_9.6p1 Debian-3")
    }

    func testStripsControlBytes() {
        // A banner ends up in a list row and in a host's notes; a rogue escape
        // sequence must not be able to travel from a scanned host into either.
        let data = Data("SSH-2.0-\u{1b}[31mEVIL\u{07}".utf8)
        XCTAssertEqual(TCPProbe.banner(from: data), "SSH-2.0-[31mEVIL")
    }

    func testEmptyAndBlankInputs() {
        XCTAssertNil(TCPProbe.banner(from: Data()))
        XCTAssertNil(TCPProbe.banner(from: Data("\r\n".utf8)))
        XCTAssertNil(TCPProbe.banner(from: Data("   \r\n".utf8)))
    }

    func testTruncatesRunawayBanners() {
        let data = Data(String(repeating: "A", count: 4096).utf8)
        XCTAssertEqual(TCPProbe.banner(from: data)?.count, 120)
    }
}

// MARK: - Bonjour name cleanup

final class BonjourNameTests: XCTestCase {
    func testStripsWorkstationMACSuffix() {
        XCTAssertEqual(BonjourDiscovery.cleanName("noether [00:11:22:33:44:55]"), "noether")
    }

    func testUnescapesSpaces() {
        XCTAssertEqual(BonjourDiscovery.cleanName("Andy\\032Mac"), "Andy Mac")
    }

    func testLeavesOrdinaryNamesAlone() {
        XCTAssertEqual(BonjourDiscovery.cleanName("pi-a"), "pi-a")
    }

    func testServiceTypesMatchTheInfoPlist() throws {
        let plist = Bundle(for: BonjourNameTests.self).url(forResource: nil, withExtension: nil)
        _ = plist
        // The app bundle under test is the host app; read its Info.plist so a
        // service type added in code but not declared is caught here rather
        // than as an inexplicably empty browse at runtime.
        let declared = Bundle.main.object(forInfoDictionaryKey: "NSBonjourServices") as? [String]
        guard let declared else { throw XCTSkip("no NSBonjourServices in the test host bundle") }
        XCTAssertEqual(Set(declared), Set(BonjourDiscovery.serviceTypes))
    }

    func testShortType() {
        let service = BonjourService(name: "n", type: "_sftp-ssh._tcp", address: "10.0.0.1", port: 22)
        XCTAssertEqual(service.shortType, "sftp-ssh")
    }
}

// MARK: - Merging the three sources

final class LANResultsMergeTests: XCTestCase {
    private let early = Date(timeIntervalSince1970: 1_000)
    private let late = Date(timeIntervalSince1970: 2_000)

    func testProbeBonjourAndReverseDNSCombineIntoOneHost() {
        // The probe knows ports, Bonjour knows the name and the service types,
        // reverse DNS knows a different name. One host comes out.
        let probed = LANHost(
            address: "10.0.0.41",
            hostname: nil,
            openPorts: [LANOpenPort(port: 22, banner: "SSH-2.0-OpenSSH_9.6p1"), LANOpenPort(port: 80)],
            lastSeen: early
        )
        let advertised = LANScanner.hosts(from: [
            BonjourService(name: "pi-a", type: "_ssh._tcp", address: "10.0.0.41", port: 22),
            BonjourService(name: "pi-a", type: "_http._tcp", address: "10.0.0.41", port: 80),
        ])

        let merged = LANResultsMerge.merge(existing: [probed], incoming: advertised)

        XCTAssertEqual(merged.count, 1)
        let host = try? XCTUnwrap(merged.first)
        XCTAssertEqual(host?.address, "10.0.0.41")
        XCTAssertEqual(host?.hostname, "pi-a")
        XCTAssertEqual(host?.bonjourServices, ["_http._tcp", "_ssh._tcp"])
        XCTAssertEqual(host?.openPorts.map(\.port), [22, 80])
        XCTAssertEqual(host?.sshPorts.first?.banner, "SSH-2.0-OpenSSH_9.6p1")
    }

    func testABannerSurvivesASweepThatDidNotGetOne() {
        let withBanner = LANHost(
            address: "10.0.0.81",
            openPorts: [LANOpenPort(port: 22, banner: "SSH-2.0-OpenSSH_9.9")],
            lastSeen: early
        )
        let without = LANHost(
            address: "10.0.0.81",
            openPorts: [LANOpenPort(port: 22, banner: nil)],
            lastSeen: late
        )

        let merged = LANResultsMerge.merge(existing: [withBanner], incoming: [without])
        XCTAssertEqual(merged.first?.openPorts.first?.banner, "SSH-2.0-OpenSSH_9.9")
        XCTAssertEqual(merged.first?.lastSeen, late, "last-seen still advances")
    }

    func testANewBannerReplacesAnOldOne() {
        let old = LANHost(address: "10.0.0.81", openPorts: [LANOpenPort(port: 22, banner: "SSH-2.0-OpenSSH_8.4")])
        let new = LANHost(address: "10.0.0.81", openPorts: [LANOpenPort(port: 22, banner: "SSH-2.0-OpenSSH_9.9")])
        let merged = LANResultsMerge.merge(existing: [old], incoming: [new])
        XCTAssertEqual(merged.first?.openPorts.first?.banner, "SSH-2.0-OpenSSH_9.9")
    }

    func testANameIsNeverErasedByASweepThatCouldNotResolveOne() {
        let named = LANHost(address: "10.0.0.41", hostname: "pi-a", openPorts: [LANOpenPort(port: 22)])
        let anonymous = LANHost(address: "10.0.0.41", hostname: nil, openPorts: [LANOpenPort(port: 443)])
        let merged = LANResultsMerge.merge(existing: [named], incoming: [anonymous])
        XCTAssertEqual(merged.first?.hostname, "pi-a")
        XCTAssertEqual(merged.first?.openPorts.map(\.port), [22, 443])
    }

    func testHostsAccumulateAcrossScans() {
        // A machine asleep during one sweep must not vanish from the list.
        let first = [LANHost(address: "10.0.0.41", openPorts: [LANOpenPort(port: 22)])]
        let second = [LANHost(address: "10.0.0.42", openPorts: [LANOpenPort(port: 80)])]
        let merged = LANResultsMerge.merge(existing: first, incoming: second)
        XCTAssertEqual(merged.map(\.address), ["10.0.0.41", "10.0.0.42"])
    }

    func testResultsAreSortedByOctet() {
        let hosts = [
            LANHost(address: "10.0.0.100"),
            LANHost(address: "10.0.0.9"),
            LANHost(address: "10.0.0.41"),
        ]
        let merged = LANResultsMerge.merge(existing: [], incoming: hosts)
        XCTAssertEqual(merged.map(\.address), ["10.0.0.9", "10.0.0.41", "10.0.0.100"])
    }

    func testSSHAndOtherPortsSplitCorrectly() {
        let host = LANHost(
            address: "10.0.0.42",
            openPorts: [
                LANOpenPort(port: 443),
                LANOpenPort(port: 22, banner: "SSH-2.0-OpenSSH_9.6p1"),
                LANOpenPort(port: 2222),
                LANOpenPort(port: 8096),
            ]
        )
        XCTAssertEqual(host.sshPorts.map(\.port), [22, 2222])
        XCTAssertEqual(host.otherPorts.map(\.port), [443, 8096])
        XCTAssertTrue(host.hasSSH)
        XCTAssertEqual(host.summary, "22 SSH · 443 HTTPS · 2222 SSH (alt) · 8096 Jellyfin")
    }

    func testBonjourOnlyHostsBecomeResults() {
        let hosts = LANScanner.hosts(from: [
            BonjourService(name: "nas", type: "_smb._tcp", address: "10.0.0.100", port: 445)
        ])
        XCTAssertEqual(hosts.count, 1)
        XCTAssertEqual(hosts.first?.displayName, "nas")
        XCTAssertEqual(hosts.first?.openPorts.map(\.port), [445])
        XCTAssertFalse(hosts.first?.hasSSH ?? true)
    }

    func testDisplayNameFallsBackToTheAddress() {
        XCTAssertEqual(LANHost(address: "10.0.0.7").displayName, "10.0.0.7")
    }
}

// MARK: - Local services

final class LocalServiceTests: XCTestCase {
    func testURLForABrowsableService() {
        let service = LocalService(
            alias: "proxmox", address: "10.0.0.10", port: 8006,
            serviceType: "Proxmox VE", scheme: "https"
        )
        XCTAssertEqual(service.urlString, "https://10.0.0.10:8006")
        XCTAssertEqual(service.url?.absoluteString, "https://10.0.0.10:8006")
    }

    func testBareAddressForSomethingABrowserCannotOpen() {
        let service = LocalService(
            alias: "nas", address: "10.0.0.100", port: 445,
            serviceType: "SMB", scheme: nil
        )
        XCTAssertEqual(service.urlString, "10.0.0.100:445")
        XCTAssertNil(service.url, "no link for a protocol Safari cannot speak")
    }
}

// MARK: - Import round-trip

@MainActor
final class LANImportTests: XCTestCase {
    private var directory: URL!
    private var vault: Vault!

    override func setUpWithError() throws {
        try super.setUpWithError()
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("LANTests-\(UUID().uuidString)", isDirectory: true)
        vault = Vault(keychain: InMemoryKeychain(), directory: directory)
    }

    override func tearDownWithError() throws {
        vault = nil
        if let directory { try? FileManager.default.removeItem(at: directory) }
        directory = nil
        try super.tearDownWithError()
    }

    private func results() -> [LANHost] {
        [
            LANHost(
                address: "10.0.0.41",
                hostname: "pi-a.lan",
                bonjourServices: ["_ssh._tcp"],
                openPorts: [
                    LANOpenPort(port: 22, banner: "SSH-2.0-OpenSSH_9.6p1"),
                    LANOpenPort(port: 443),
                    LANOpenPort(port: 8123),
                ],
                lastSeen: Date(timeIntervalSince1970: 1_000)
            ),
            LANHost(
                address: "10.0.0.100",
                openPorts: [LANOpenPort(port: 445), LANOpenPort(port: 5900)],
                lastSeen: Date(timeIntervalSince1970: 1_000)
            ),
        ]
    }

    func testSSHPortsBecomeHostsAndTheRestBecomeServices() {
        let summary = LANImporter.import(
            results(), into: vault, username: "andy", term: "xterm-256color"
        )

        XCTAssertEqual(summary.hostsAdded, 1)
        XCTAssertEqual(summary.servicesAdded, 4)
        XCTAssertEqual(summary.hostsRefreshed, 0)

        let host = vault.hosts.first
        XCTAssertEqual(vault.hosts.count, 1)
        XCTAssertEqual(host?.hostname, "10.0.0.41")
        XCTAssertEqual(host?.port, 22)
        XCTAssertEqual(host?.username, "andy")
        XCTAssertEqual(host?.group, Host.localGroup)
        XCTAssertEqual(host?.alias, "pi-a.lan")
        XCTAssertEqual(host?.term, "xterm-256color")
        XCTAssertEqual(host?.tags, ["bonjour"])
        XCTAssertEqual(host?.notes, "SSH-2.0-OpenSSH_9.6p1", "the banner is the note")
        XCTAssertNotNil(host?.lastSeen)

        XCTAssertEqual(vault.localServices.map(\.port), [443, 8123, 445, 5900])
        XCTAssertEqual(
            vault.localServices.first(where: { $0.port == 8123 })?.serviceType,
            "Home Assistant"
        )
        // An unnamed host's services are labelled by address, not left blank.
        XCTAssertEqual(vault.localServices.first(where: { $0.port == 445 })?.alias, "10.0.0.100")
    }

    func testAnEditedAliasWins() {
        LANImporter.import(
            results(), into: vault, username: "andy", term: "xterm-256color",
            aliases: ["10.0.0.41": "  pi-a  ", "10.0.0.100": "unas"]
        )
        XCTAssertEqual(vault.hosts.first?.alias, "pi-a", "trimmed")
        XCTAssertEqual(vault.localServices.first(where: { $0.port == 445 })?.alias, "unas")
    }

    func testAnEmptyEditFallsBackRatherThanSavingABlankName() {
        LANImporter.import(
            results(), into: vault, username: "andy", term: "xterm-256color",
            aliases: ["10.0.0.41": "   "]
        )
        XCTAssertEqual(vault.hosts.first?.alias, "pi-a.lan")
    }

    func testReimportingRefreshesRatherThanDuplicating() {
        LANImporter.import(results(), into: vault, username: "andy", term: "xterm-256color")
        let firstSeen = vault.hosts.first?.lastSeen

        var later = results()
        later[0].lastSeen = Date(timeIntervalSince1970: 9_000)
        let second = LANImporter.import(later, into: vault, username: "andy", term: "xterm-256color")

        XCTAssertEqual(second.hostsAdded, 0)
        XCTAssertEqual(second.hostsRefreshed, 1)
        XCTAssertEqual(second.servicesAdded, 0)
        XCTAssertEqual(vault.hosts.count, 1)
        XCTAssertEqual(vault.localServices.count, 4)
        XCTAssertGreaterThan(
            try XCTUnwrap(vault.hosts.first?.lastSeen),
            try XCTUnwrap(firstSeen)
        )
    }

    func testARenamedHostIsStillMatchedOnItsEndpoint() throws {
        LANImporter.import(results(), into: vault, username: "andy", term: "xterm-256color")
        var renamed = try XCTUnwrap(vault.hosts.first)
        renamed.alias = "the pi in the cupboard"
        vault.upsert(renamed)

        LANImporter.import(results(), into: vault, username: "andy", term: "xterm-256color")
        XCTAssertEqual(vault.hosts.count, 1)
        XCTAssertEqual(vault.hosts.first?.alias, "the pi in the cupboard")
    }

    func testTwoSSHPortsOnOneHostBecomeTwoHosts() {
        let host = LANHost(
            address: "10.0.0.81",
            hostname: "noether",
            openPorts: [LANOpenPort(port: 22), LANOpenPort(port: 2222)]
        )
        LANImporter.import([host], into: vault, username: "andy", term: "xterm-256color")
        XCTAssertEqual(vault.hosts.map(\.port).sorted(), [22, 2222])
    }

    func testImportSurvivesAReopen() throws {
        LANImporter.import(results(), into: vault, username: "andy", term: "xterm-256color")
        let reopened = Vault(keychain: InMemoryKeychain(), directory: directory)
        XCTAssertEqual(reopened.localHosts.count, 1)
        XCTAssertEqual(reopened.localServices.count, 4)
        XCTAssertEqual(reopened.hosts.first?.lastSeen, vault.hosts.first?.lastSeen)
    }

    func testLocalServicesAreRenameableAndDeletable() throws {
        LANImporter.import(results(), into: vault, username: "andy", term: "xterm-256color")
        let service = try XCTUnwrap(vault.localServices.first)
        vault.renameLocalService(service, to: "home assistant")
        XCTAssertEqual(vault.localServices.first?.alias, "home assistant")
        vault.deleteLocalService(service)
        XCTAssertEqual(vault.localServices.count, 3)
    }

    func testAHostAlreadySavedByHandIsNotDuplicatedByAScan() {
        var manual = Host(alias: "work", hostname: "10.0.0.41", port: 22, username: "me")
        manual.group = "Work"
        vault.upsert(manual)

        let summary = LANImporter.import(
            results(), into: vault, username: "andy", term: "xterm-256color"
        )

        // The endpoint is already in the vault, so the scan refreshes it and
        // leaves its group, username and alias alone. Finding a machine you
        // already configured is not a reason to configure it again.
        XCTAssertEqual(summary.hostsAdded, 0)
        XCTAssertEqual(summary.hostsRefreshed, 1)
        XCTAssertEqual(vault.hosts.count, 1)
        XCTAssertEqual(vault.hosts.first?.group, "Work")
        XCTAssertEqual(vault.hosts.first?.username, "me")
        XCTAssertNotNil(vault.hosts.first?.lastSeen)
    }

    func testOnlyLocalHostsAreOfferedForPinning() {
        var manual = Host(alias: "work", hostname: "10.0.0.9", port: 22, username: "me")
        manual.group = "Work"
        vault.upsert(manual)
        LANImporter.import(results(), into: vault, username: "andy", term: "xterm-256color")

        // "Work" is not offered even though it is on the same subnet: pinning
        // is scoped to what this scan imported, not to the whole vault.
        let offered = LANImporter.sshHosts(
            in: vault,
            matching: results() + [LANHost(address: "10.0.0.9", openPorts: [LANOpenPort(port: 22)])]
        )
        XCTAssertEqual(offered.count, 1)
        XCTAssertEqual(offered.first?.group, Host.localGroup)
        XCTAssertEqual(offered.first?.hostname, "10.0.0.41")
    }

    func testSummaryText() {
        XCTAssertEqual(LANImporter.Summary().description, "Nothing to import.")
        XCTAssertEqual(
            LANImporter.Summary(hostsAdded: 1, hostsRefreshed: 0, servicesAdded: 3).description,
            "1 SSH host, 3 local services."
        )
        XCTAssertEqual(
            LANImporter.Summary(hostsAdded: 2, hostsRefreshed: 1, servicesAdded: 1).description,
            "2 SSH hosts, 1 refreshed, 1 local service."
        )
    }
}

// MARK: - Pin host keys

/// Stands in for a real handshake.
///
/// It writes through `Vault.trust` exactly as the live path does — the real
/// prober does not record anything itself either, it lets the session's TOFU
/// check do it — so this exercises the property that matters: after pin-all,
/// known-hosts has an entry per reachable host.
@MainActor
private final class StubProber: HostKeyProbing {
    /// hostname → the key that endpoint will present, or nil to be down.
    var keys: [String: (type: String, line: String)] = [:]
    private(set) var probed: [String] = []
    private let vault: Vault

    init(vault: Vault) {
        self.vault = vault
    }

    func probe(hostname: String, port: Int, username: String) async -> HostKeyPinResult.Outcome {
        probed.append("\(hostname):\(port)")
        guard let key = keys[hostname] else {
            return .unreachable("The connection timed out.")
        }

        let existing = vault.knownHost(hostname: hostname, port: port)
        let fingerprint = SSHFingerprint.sha256(publicKeyLine: key.line) ?? "SHA256:unknown"

        switch vault.verify(
            hostname: hostname,
            port: port,
            presentedType: key.type,
            presentedFingerprint: fingerprint,
            presentedLine: key.line
        ) {
        case .trusted:
            return .unchanged(fingerprint: fingerprint)
        case .mismatch(let expected, _, let presented):
            return .changed(expected: expected.fingerprint, presented: presented)
        case .unknown(let type, let presentedFingerprint, let line):
            _ = try? vault.trust(
                hostname: hostname, port: port, keyType: type,
                fingerprint: presentedFingerprint, publicKeyLine: line
            )
            return existing == nil
                ? .pinned(fingerprint: presentedFingerprint, keyType: type)
                : .unchanged(fingerprint: presentedFingerprint)
        }
    }
}

@MainActor
final class HostKeyPinnerTests: XCTestCase {
    private var directory: URL!
    private var vault: Vault!
    private var prober: StubProber!
    private var pinner: HostKeyPinner!

    private let keyA =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMDUXm/8yg/ZUUXNP6RM90rYQnGDLGqUqAhfXjs4hCKw"
    private let keyB =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIpcTPFZ9U+kuxL3Ed6fboQpp+ysOxlfOObeL9G29kmz"

    override func setUpWithError() throws {
        try super.setUpWithError()
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("PinTests-\(UUID().uuidString)", isDirectory: true)
        vault = Vault(keychain: InMemoryKeychain(), directory: directory)
        prober = StubProber(vault: vault)
        pinner = HostKeyPinner(vault: vault, prober: prober)
    }

    override func tearDownWithError() throws {
        pinner = nil
        prober = nil
        vault = nil
        if let directory { try? FileManager.default.removeItem(at: directory) }
        directory = nil
        try super.tearDownWithError()
    }

    private func localHost(_ address: String, port: Int = 22) -> Host {
        Host(
            alias: address, hostname: address, port: port,
            username: "andy", group: Host.localGroup
        )
    }

    func testPinAllWritesAKnownHostPerHost() async throws {
        prober.keys = ["10.0.0.41": ("ssh-ed25519", keyA), "10.0.0.81": ("ssh-ed25519", keyB)]
        let hosts = [localHost("10.0.0.41"), localHost("10.0.0.81")]
        hosts.forEach { vault.upsert($0) }

        await pinner.pin(hosts)

        XCTAssertEqual(vault.knownHosts.count, 2)
        XCTAssertEqual(
            Set(vault.knownHosts.map(\.id)), ["10.0.0.41:22", "10.0.0.81:22"]
        )
        XCTAssertEqual(pinner.results.count, 2)
        XCTAssertEqual(pinner.summary, "2 pinned")
        XCTAssertEqual(pinner.progress, 1)
        XCTAssertFalse(pinner.isRunning)

        // Every pinned host also gets a fingerprint to show and a last-seen.
        for result in pinner.results {
            guard case .pinned(let fingerprint, let keyType) = result.outcome else {
                return XCTFail("expected a pin, got \(result.outcome)")
            }
            XCTAssertTrue(fingerprint.hasPrefix("SHA256:"))
            XCTAssertEqual(keyType, "ssh-ed25519")
        }
        XCTAssertTrue(vault.localHosts.allSatisfy { $0.lastSeen != nil })
    }

    func testPinningIsIdempotent() async {
        prober.keys = ["10.0.0.41": ("ssh-ed25519", keyA)]
        let hosts = [localHost("10.0.0.41")]
        hosts.forEach { vault.upsert($0) }

        await pinner.pin(hosts)
        await pinner.pin(hosts)

        XCTAssertEqual(vault.knownHosts.count, 1)
        XCTAssertEqual(pinner.summary, "all already pinned")
        if case .unchanged = pinner.results.first?.outcome {} else {
            XCTFail("second pin should report unchanged, got \(String(describing: pinner.results.first?.outcome))")
        }
    }

    func testAChangedKeyIsFlaggedAndTheOldPinIsKept() async throws {
        prober.keys = ["10.0.0.41": ("ssh-ed25519", keyA)]
        let hosts = [localHost("10.0.0.41")]
        hosts.forEach { vault.upsert($0) }
        await pinner.pin(hosts)
        let original = try XCTUnwrap(vault.knownHosts.first?.fingerprint)

        // Same endpoint, different key: a re-imaged box, or something worse.
        prober.keys = ["10.0.0.41": ("ssh-ed25519", keyB)]
        await pinner.pin(hosts)

        XCTAssertEqual(vault.knownHosts.count, 1)
        XCTAssertEqual(vault.knownHosts.first?.fingerprint, original, "the pin is never overwritten")
        XCTAssertTrue(pinner.results.contains(where: \.isProblem))
        XCTAssertEqual(pinner.summary, "1 CHANGED")

        guard case .changed(let expected, let presented) = pinner.results.first?.outcome else {
            return XCTFail("expected a mismatch")
        }
        XCTAssertEqual(expected, original)
        XCTAssertNotEqual(presented, original)
    }

    func testUnreachableHostsAreReportedAndNotMarkedSeen() async {
        prober.keys = ["10.0.0.41": ("ssh-ed25519", keyA)]
        let hosts = [localHost("10.0.0.41"), localHost("10.0.0.99")]
        hosts.forEach { vault.upsert($0) }

        await pinner.pin(hosts)

        XCTAssertEqual(vault.knownHosts.count, 1)
        XCTAssertEqual(pinner.summary, "1 pinned, 1 unreachable")
        XCTAssertNil(vault.hosts.first { $0.hostname == "10.0.0.99" }?.lastSeen)
        XCTAssertNotNil(vault.hosts.first { $0.hostname == "10.0.0.41" }?.lastSeen)
    }

    func testNonDefaultPortsArePinnedPerEndpoint() async {
        prober.keys = ["10.0.0.41": ("ssh-ed25519", keyA)]
        let hosts = [localHost("10.0.0.41"), localHost("10.0.0.41", port: 2222)]
        hosts.forEach { vault.upsert($0) }

        await pinner.pin(hosts)

        XCTAssertEqual(Set(vault.knownHosts.map(\.id)), ["10.0.0.41:22", "10.0.0.41:2222"])
        XCTAssertEqual(prober.probed, ["10.0.0.41:22", "10.0.0.41:2222"])
    }

    func testPinningNothingDoesNothing() async {
        await pinner.pin([])
        XCTAssertTrue(pinner.results.isEmpty)
        XCTAssertTrue(vault.knownHosts.isEmpty)
    }
}

// MARK: - Console resolution of scanned aliases

final class ScannedAliasResolutionTests: XCTestCase {
    func testFirstLabelOfADNSName() {
        XCTAssertEqual(SessionManager.firstLabel(of: "noether.lan"), "noether")
        XCTAssertEqual(SessionManager.firstLabel(of: "PI-A.local"), "pi-a")
        XCTAssertEqual(SessionManager.firstLabel(of: "noether"), "noether")
    }

    func testAnAddressIsLeftWhole() {
        // Otherwise `ssh 10` would resolve to 10.0.0.41.
        XCTAssertEqual(SessionManager.firstLabel(of: "10.0.0.41"), "10.0.0.41")
    }
}
