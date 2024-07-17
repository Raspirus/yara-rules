
rule ELASTIC_Windows_Trojan_Metastealer_F94E2464 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Metastealer (Windows.Trojan.MetaStealer)"
		author = "Elastic Security"
		id = "f94e2464-b41a-46fd-89c1-335aa8c14425"
		date = "2024-03-27"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_MetaStealer.yar#L1-L34"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "14ca15c0751207103c38f1a2f8fdc73e5dd3d58772f6e5641e54e0c790ecd132"
		logic_hash = "bf374bda2ca7c7bcec1ff092bbc9c3fd95c33faa78a6ea105a7b12b8e80a2e23"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fb35feaf8e2d0994d022da1c8e872dc8b05b04e25ab6fed2ed1997267edfccd9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$string1 = "AvailableLanguages" fullword
		$string2 = "GetGraphicCards" fullword
		$string3 = "GetVs" fullword
		$string4 = "GetSerialNumber" fullword
		$string5 = "net.tcp://" wide
		$string6 = "AntivirusProduct|AntiSpyWareProduct|FirewallProduct" wide
		$string7 = "wallet.dat" wide
		$string8 = "[A-Za-z\\d]{24}\\.[\\w-]{6}\\.[\\w-]{27}" wide
		$string9 = "Software\\Valve\\Steam" wide
		$string10 = "{0}\\FileZilla\\recentservers.xml" wide
		$string11 = "{0}\\FileZilla\\sitemanager.xml" wide
		$string12 = "([a-zA-Z0-9]{1000,1500})" wide
		$string13 = "\\qemu-ga.exe" wide
		$string14 = "metaData" wide
		$string15 = "%DSK_23%" wide
		$string16 = "CollectMemory" fullword

	condition:
		all of them
}