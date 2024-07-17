rule ELASTIC_Windows_Ransomware_Ryuk_88Daaf8E : BETA FILE MEMORY
{
	meta:
		description = "Identifies RYUK ransomware"
		author = "Elastic Security"
		id = "88daaf8e-0bfe-46c4-9a75-2527d0e10538"
		date = "2020-04-30"
		modified = "2021-08-23"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Ryuk.yar#L139-L158"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "6fc463976c0fb9c3e4f25d854545d07800c63730826f3974298f0077d272cff0"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "b1f218a9bc6bf5f3ec108a471de954988e7692de208e68d7d4ee205194cbbb40"
		threat_name = "Windows.Ransomware.Ryuk"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$f1 = { 48 8B CF E8 AB 25 00 00 85 C0 74 35 }

	condition:
		1 of ($f*)
}