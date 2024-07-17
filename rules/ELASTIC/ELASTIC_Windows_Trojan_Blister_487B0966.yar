
rule ELASTIC_Windows_Trojan_Blister_487B0966 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Blister (Windows.Trojan.Blister)"
		author = "Elastic Security"
		id = "487b0966-fb24-4c41-84cc-f3a389461ddc"
		date = "2023-09-11"
		modified = "2023-09-20"
		reference = "https://www.elastic.co/security-labs/elastic-security-uncovers-blister-malware-campaign"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Blister.yar#L68-L89"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5fc79a4499bafa3a881778ef51ce29ef015ee58a587e3614702e69da304395db"
		logic_hash = "521409d03335205507cc6894e0de3ca627eb966a95a2f8e7b931e552ad78bbb7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7111f2f9746e056f6ac5e08d904f71628a548b4ab2c1181dec0a38f0f8387878"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$b_loader0 = { 65 48 8B 04 25 60 00 00 00 44 8B D3 41 BE ?? ?? ?? ?? 48 8B 50 18 48 83 C2 ?? 48 8B 0A }
		$b_loader1 = { 0F B7 C0 4D 8D 49 02 41 33 C0 44 69 C0 ?? ?? ?? ?? 41 8B C0 C1 E8 0F 44 33 C0 41 0F B7 01 66 85 C0 }
		$b_loader2 = { 66 45 03 DC 49 83 C2 04 41 0F B7 C3 49 83 C0 02 3B C6 }

	condition:
		2 of them
}