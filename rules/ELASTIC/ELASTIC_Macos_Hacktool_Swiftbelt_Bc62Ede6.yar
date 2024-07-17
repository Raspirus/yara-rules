
rule ELASTIC_Macos_Hacktool_Swiftbelt_Bc62Ede6 : FILE MEMORY
{
	meta:
		description = "Detects Macos Hacktool Swiftbelt (MacOS.Hacktool.Swiftbelt)"
		author = "Elastic Security"
		id = "bc62ede6-e6f1-4c9e-bff2-ef55a5d12ba1"
		date = "2021-10-12"
		modified = "2021-10-25"
		reference = "https://www.elastic.co/security-labs/inital-research-of-jokerspy"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Hacktool_Swiftbelt.yar#L1-L44"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "452c832a17436f61ad5f32ee1c97db05575160105ed1dcd0d3c6db9fb5a9aea1"
		logic_hash = "51481baa6ddb09cf8463d989637319cb26b23fef625cc1a44c96d438c77362ca"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "98d14dba562ad68c8ecc00780ab7ee2ecbe912cd00603fff0eb887df1cd12fdb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$dbg1 = "SwiftBelt/Sources/SwiftBelt"
		$dbg2 = "[-] Firefox places.sqlite database not found for user"
		$dbg3 = "[-] No security products found"
		$dbg4 = "SSH/AWS/gcloud Credentials Search:"
		$dbg5 = "[-] Could not open the Slack Cookies database"
		$sec1 = "[+] Malwarebytes A/V found on this host"
		$sec2 = "[+] Cisco AMP for endpoints found"
		$sec3 = "[+] SentinelOne agent running"
		$sec4 = "[+] Crowdstrike Falcon agent found"
		$sec5 = "[+] FireEye HX agent installed"
		$sec6 = "[+] Little snitch firewall found"
		$sec7 = "[+] ESET A/V installed"
		$sec8 = "[+] Carbon Black OSX Sensor installed"
		$sec9 = "/Library/Little Snitch"
		$sec10 = "/Library/FireEye/xagt"
		$sec11 = "/Library/CS/falcond"
		$sec12 = "/Library/Logs/PaloAltoNetworks/GlobalProtect"
		$sec13 = "/Library/Application Support/Malwarebytes"
		$sec14 = "/usr/local/bin/osqueryi"
		$sec15 = "/Library/Sophos Anti-Virus"
		$sec16 = "/Library/Objective-See/Lulu"
		$sec17 = "com.eset.remoteadministrator.agent"
		$sec18 = "/Applications/CarbonBlack/CbOsxSensorService"
		$sec19 = "/Applications/BlockBlock Helper.app"
		$sec20 = "/Applications/KextViewr.app"

	condition:
		6 of them
}