
rule ELASTIC_Windows_Trojan_Cobaltstrike_8751Cdf9 : FILE MEMORY
{
	meta:
		description = "Identifies Cobalt Strike wininet reverse shellcode along with XOR implementation by Cobalt Strike."
		author = "Elastic Security"
		id = "8751cdf9-4038-42ba-a6eb-f8ac579a4fbb"
		date = "2021-03-25"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L808-L827"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "64fae95fd89ad46a50a00c943cf98a997a0842a83be64b3728b25151867b75a8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0988386ef4ba54dd90b0cf6d6a600b38db434e00e569d69d081919cdd3ea4d3f"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 99
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
		$a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }

	condition:
		all of them
}