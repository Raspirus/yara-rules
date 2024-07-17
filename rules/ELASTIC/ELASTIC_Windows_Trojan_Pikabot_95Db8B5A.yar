
rule ELASTIC_Windows_Trojan_Pikabot_95Db8B5A : FILE MEMORY
{
	meta:
		description = "Related to Pikabot loader"
		author = "Elastic Security"
		id = "95db8b5a-f97d-42bd-a114-e35e031784e2"
		date = "2024-02-15"
		modified = "2024-02-21"
		reference = "https://www.elastic.co/security-labs/pikabot-i-choose-you"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_PikaBot.yar#L80-L103"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "74073ceae1b26b953b7644d56a2ec92993b83802a30ce82c6921df5448ebab06"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f9463fa18fc5975aeabf076490bd8fe79c62c822126c5320f90870a9b4032f60"
		threat_name = "Windows.Trojan.PikaBot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$syscall_ZwQueryInfoProcess = { 68 9B 8B 16 88 E8 73 FF FF FF }
		$syscall_ZwCreateUserProcess = { 68 B2 CE 2E CF E8 5F FF FF FF }
		$load_sycall = { 8F 05 ?? ?? ?? ?? 83 C0 04 50 8F 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 A3 ?? ?? ?? ?? 31 C0 64 8B 0D C0 00 00 00 85 C9 }
		$payload_chunking = { 8A 84 35 ?? ?? ?? ?? 8A 95 ?? ?? ?? ?? 88 84 1D ?? ?? ?? ?? 88 94 35 ?? ?? ?? ?? 02 94 1D ?? ?? ?? ?? }
		$loader_rc4_decrypt_chunk = { F7 FF 8A 84 15 ?? ?? ?? ?? 89 D1 8A 94 1D ?? ?? ?? ?? 88 94 0D ?? ?? ?? ?? 8B 55 08 88 84 1D ?? ?? ?? ?? 02 84 0D ?? ?? ?? ?? 0F B6 C0 8A 84 05 ?? ?? ?? ?? 32 04 32 }

	condition:
		2 of them
}