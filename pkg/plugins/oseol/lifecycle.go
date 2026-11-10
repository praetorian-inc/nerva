package oseol

// Dates are the final day of vendor security support, not end-of-sale or
// ordinary bug-fix maintenance. Unknown releases intentionally have no verdict.
type lifecycleRule struct {
	end, source string
}

var linuxLifecycleSources = map[family]string{
	familyUbuntu: "https://ubuntu.com/about/release-cycle",
	familyDebian: "https://wiki.debian.org/LTS",
	familyRHEL:   "https://access.redhat.com/support/policy/updates/errata",
	familyCentOS: "https://www.centos.org/centos-linux-eol/",
}

const fedoraLifecycleSource = "https://endoflife.date/fedora" // Mirrors Fedora's published release EOL dates.
const freeBSDLifecycleSource = "https://www.freebsd.org/security/unsupported/"
const windowsLifecycleSource = "https://learn.microsoft.com/en-us/lifecycle/products/"
const iosXELifecycleSource = "https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/ios-xe-17/"

var lifecycleDates = map[string]map[string]lifecycleRule{
	"fedoraproject:fedora": {
		"1":  {"2004-09-20", fedoraLifecycleSource},
		"2":  {"2005-04-11", fedoraLifecycleSource},
		"3":  {"2006-01-16", fedoraLifecycleSource},
		"4":  {"2006-08-07", fedoraLifecycleSource},
		"5":  {"2007-07-02", fedoraLifecycleSource},
		"6":  {"2007-12-07", fedoraLifecycleSource},
		"7":  {"2008-06-13", fedoraLifecycleSource},
		"8":  {"2009-01-07", fedoraLifecycleSource},
		"9":  {"2009-07-10", fedoraLifecycleSource},
		"10": {"2009-12-17", fedoraLifecycleSource},
		"11": {"2010-06-25", fedoraLifecycleSource},
		"12": {"2010-12-02", fedoraLifecycleSource},
		"13": {"2011-06-24", fedoraLifecycleSource},
		"14": {"2011-12-09", fedoraLifecycleSource},
		"15": {"2012-06-26", fedoraLifecycleSource},
		"16": {"2013-02-12", fedoraLifecycleSource},
		"17": {"2013-07-30", fedoraLifecycleSource},
		"18": {"2014-01-14", fedoraLifecycleSource},
		"19": {"2015-01-06", fedoraLifecycleSource},
		"20": {"2015-06-23", fedoraLifecycleSource},
		"21": {"2015-12-01", fedoraLifecycleSource},
		"22": {"2016-07-19", fedoraLifecycleSource},
		"23": {"2016-12-20", fedoraLifecycleSource},
		"24": {"2017-08-08", fedoraLifecycleSource},
		"25": {"2017-12-12", fedoraLifecycleSource},
		"26": {"2018-05-29", fedoraLifecycleSource},
		"27": {"2018-11-30", fedoraLifecycleSource},
		"28": {"2019-05-28", fedoraLifecycleSource},
		"29": {"2019-11-26", fedoraLifecycleSource},
		"30": {"2020-05-26", fedoraLifecycleSource},
		"31": {"2020-11-24", fedoraLifecycleSource},
		"32": {"2021-05-25", fedoraLifecycleSource},
		"33": {"2021-11-30", fedoraLifecycleSource},
		"34": {"2022-06-07", fedoraLifecycleSource},
		"35": {"2022-12-13", fedoraLifecycleSource},
		"36": {"2023-05-16", fedoraLifecycleSource},
		"37": {"2023-12-05", fedoraLifecycleSource},
		"38": {"2024-05-21", fedoraLifecycleSource},
		"39": {"2024-11-26", fedoraLifecycleSource},
		"40": {"2025-05-13", fedoraLifecycleSource},
		"41": {"2025-12-15", fedoraLifecycleSource},
		"42": {"2026-05-27", fedoraLifecycleSource},
	},
	"freebsd:freebsd": {
		"4.11": {"2007-01-31", freeBSDLifecycleSource},
		"5.3":  {"2006-10-31", freeBSDLifecycleSource},
		"5.4":  {"2006-10-31", freeBSDLifecycleSource},
		"5.5":  {"2008-05-31", freeBSDLifecycleSource},
		"6.0":  {"2006-11-30", freeBSDLifecycleSource},
		"6.1":  {"2008-05-31", freeBSDLifecycleSource},
		"6.2":  {"2008-05-31", freeBSDLifecycleSource},
		"6.3":  {"2010-01-31", freeBSDLifecycleSource},
		"6.4":  {"2010-11-30", freeBSDLifecycleSource},
		"7.0":  {"2009-04-30", freeBSDLifecycleSource},
		"7.1":  {"2011-02-28", freeBSDLifecycleSource},
		"7.2":  {"2010-06-30", freeBSDLifecycleSource},
		"7.3":  {"2012-03-31", freeBSDLifecycleSource},
		"7.4":  {"2013-02-28", freeBSDLifecycleSource},
		"8.0":  {"2010-11-30", freeBSDLifecycleSource},
		"8.1":  {"2012-07-31", freeBSDLifecycleSource},
		"8.2":  {"2012-07-31", freeBSDLifecycleSource},
		"8.3":  {"2014-04-30", freeBSDLifecycleSource},
		"8.4":  {"2015-08-01", freeBSDLifecycleSource},
		"9.0":  {"2013-03-31", freeBSDLifecycleSource},
		"9.1":  {"2014-12-31", freeBSDLifecycleSource},
		"9.2":  {"2014-12-31", freeBSDLifecycleSource},
		"9.3":  {"2016-12-31", freeBSDLifecycleSource},
		"10.0": {"2015-02-28", freeBSDLifecycleSource},
		"10.1": {"2016-12-31", freeBSDLifecycleSource},
		"10.2": {"2016-12-31", freeBSDLifecycleSource},
		"10.3": {"2018-04-30", freeBSDLifecycleSource},
		"10.4": {"2018-10-31", freeBSDLifecycleSource},
		"11.0": {"2017-11-30", freeBSDLifecycleSource},
		"11.1": {"2018-09-30", freeBSDLifecycleSource},
		"11.2": {"2019-10-31", freeBSDLifecycleSource},
		"11.3": {"2020-09-30", freeBSDLifecycleSource},
		"11.4": {"2021-09-30", freeBSDLifecycleSource},
		"12.0": {"2020-02-29", freeBSDLifecycleSource},
		"12.1": {"2021-01-31", freeBSDLifecycleSource},
		"12.2": {"2022-03-31", freeBSDLifecycleSource},
		"12.3": {"2023-03-31", freeBSDLifecycleSource},
		"12.4": {"2023-12-31", freeBSDLifecycleSource},
		"13.0": {"2022-08-31", freeBSDLifecycleSource},
		"13.1": {"2023-07-31", freeBSDLifecycleSource},
		"13.2": {"2024-06-30", freeBSDLifecycleSource},
		"13.3": {"2024-12-31", freeBSDLifecycleSource},
		"13.4": {"2025-06-30", freeBSDLifecycleSource},
		"13.5": {"2026-04-30", freeBSDLifecycleSource},
		"14.0": {"2024-09-30", freeBSDLifecycleSource},
		"14.1": {"2025-03-31", freeBSDLifecycleSource},
		"14.2": {"2025-09-30", freeBSDLifecycleSource},
		"14.3": {"2026-06-30", freeBSDLifecycleSource},
	},
	"centos:centos_stream": {
		"8": {"2024-05-31", "https://www.centos.org/centos-stream/"},
	},
	"cisco:ios_xe": {
		// These software bulletins explicitly exclude Aironet/Catalyst APs.
		// Enrichment requires positive router/switch evidence for this verdict.
		"17.3": {"2023-09-30", iosXELifecycleSource + "ios-xe-17-3-x-eol.html"},
		"17.6": {"2024-09-30", iosXELifecycleSource + "ios-xe-17-6-x-eol.html"},
		"17.9": {"2026-09-30", iosXELifecycleSource + "ios-xe-17-9-x-eol.html"},
	},
}

func init() {
	// Product names carry the Windows release; the CPE version can be '*'.
	for product, rule := range map[string]lifecycleRule{
		"windows_server_2003":    {"2015-07-14", windowsLifecycleSource + "windows-server-2003-r2"},
		"windows_server_2003_r2": {"2015-07-14", windowsLifecycleSource + "windows-server-2003-r2"},
		"windows_server_2008":    {"2020-01-14", windowsLifecycleSource + "windows-server-2008"},
		"windows_server_2008_r2": {"2020-01-14", windowsLifecycleSource + "windows-server-2008-r2"},
		"windows_server_2012":    {"2023-10-10", windowsLifecycleSource + "windows-server-2012"},
		"windows_server_2012_r2": {"2023-10-10", windowsLifecycleSource + "windows-server-2012-r2"},
		"windows_server_2016":    {"2027-01-12", windowsLifecycleSource + "windows-server-2016"},
		"windows_server_2019":    {"2029-01-09", windowsLifecycleSource + "windows-server-2019"},
		"windows_server_2022":    {"2031-10-14", windowsLifecycleSource + "windows-server-2022"},
	} {
		lifecycleDates["microsoft:"+product] = map[string]lifecycleRule{product: rule}
	}
}
