
rule ELASTIC_Windows_Generic_Threat_9C7D2333 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "9c7d2333-f2c4-4d90-95ce-d817da5cb2a3"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1484-L1502"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "85219f1402c88ab1e69aa99fe4bed75b2ad1918f4e95c448cdc6a4b9d2f9a5d4"
		logic_hash = "561290ebf3ca2a01914f514d63121be930e7a8c06cfc90ff4b8f0c7cef3408fe"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3f003cc34b797887b5bbfeb729441d7fdb537d4516f13b215e1f6eceb5a8afaf"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 81 EC 64 09 00 00 57 C6 85 00 F8 FF FF 00 B9 FF 00 00 00 33 C0 8D BD 01 F8 FF FF F3 AB 66 AB AA C6 85 00 FC FF FF 00 B9 FF 00 00 00 33 C0 8D BD 01 FC FF FF F3 AB 66 AB AA C7 85 AC F6 }

	condition:
		all of them
}