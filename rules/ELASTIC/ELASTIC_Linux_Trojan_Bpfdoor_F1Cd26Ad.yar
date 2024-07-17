rule ELASTIC_Linux_Trojan_Bpfdoor_F1Cd26Ad : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Bpfdoor (Linux.Trojan.BPFDoor)"
		author = "Elastic Security"
		id = "f1cd26ad-dffb-421f-88f1-a812769d70ff"
		date = "2023-05-11"
		modified = "2023-05-16"
		reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_BPFDoor.yar#L154-L175"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7"
		logic_hash = "ad3e130d5a1203c55b5c8d369c7d9989f66f76c9bd57e2314a30f4c931e4b98d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fb70740218e4b06c3f34cef2d3b02e67172900e067723408bcd41d4d6ca7c399"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$magic_bytes_check = { 0F C8 0F CA 3D 9F CD 30 44 ?? ?? ?? ?? ?? ?? 81 FA 66 27 14 5E }
		$seq_binary = { 48 C1 E6 08 48 C1 E0 14 48 01 F0 48 01 C8 89 E9 48 C1 E8 20 29 C1 D1 E9 01 C8 C1 E8 0B 83 C0 01 89 C6 C1 E6 0C }
		$signals_setup = { BE 01 00 00 00 BF 02 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 01 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 03 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 0D 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 16 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 15 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 11 00 00 00 ?? ?? ?? ?? ?? BF 0A 00 00 00 }

	condition:
		($magic_bytes_check and $seq_binary) or $signals_setup
}