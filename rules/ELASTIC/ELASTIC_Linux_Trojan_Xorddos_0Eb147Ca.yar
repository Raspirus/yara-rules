rule ELASTIC_Linux_Trojan_Xorddos_0Eb147Ca : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "0eb147ca-ec6d-4a6d-b807-4de8c1eff875"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L59-L77"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "45f25d2ffa2fc2566ed0eab6bdaf6989006315bbbbc591288be39b65abf2410b"
		logic_hash = "b20479af0767e5e8579489b5298648b9cc84b3e0778f58d8dc9deb252d0f4806"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6a1667f585a7bee05d5aece397a22e376562d2b264d3f287874e5a1843e67955"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 83 45 F0 01 8B 45 F0 89 45 E8 8B 45 E8 83 C4 18 5F 5D C3 55 }

	condition:
		all of them
}