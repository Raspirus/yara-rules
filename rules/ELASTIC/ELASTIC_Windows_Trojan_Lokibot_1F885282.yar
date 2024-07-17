
rule ELASTIC_Windows_Trojan_Lokibot_1F885282 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Lokibot (Windows.Trojan.Lokibot)"
		author = "Elastic Security"
		id = "1f885282-b60e-491e-ae1b-d26825e5aadb"
		date = "2021-06-22"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Lokibot.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "916eded682d11cbdf4bc872a8c1bcaae4d4e038ac0f869f59cc0a83867076409"
		logic_hash = "c76941a83e18f11ed5af701e89616d324ddba613a95069997ea8f1830f328307"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a7519bb0751a6c928af7548eaed2459e0ed26128350262d1278f74f2ad91331b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "MAC=%02X%02X%02XINSTALL=%08X%08Xk" fullword

	condition:
		all of them
}