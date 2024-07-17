
rule ELASTIC_Linux_Trojan_Ddostf_Dc47A873 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ddostf (Linux.Trojan.Ddostf)"
		author = "Elastic Security"
		id = "dc47a873-65a0-430d-a598-95be7134f207"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ddostf.yar#L60-L78"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1015b9aef1f749dfc31eb33528c4a4169035b6d73542e068b617965d3e948ef2"
		logic_hash = "2f5bd9e012fd778388074cf29b56c7cd59391840f994835d087b7b661445d316"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f103490a9dedc0197f50ca2b412cf18d2749c8d6025fd557f1686bc38f32db52"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 05 88 10 8B 45 08 0F B6 10 83 E2 0F 83 CA 40 88 10 8B 45 08 C6 40 }

	condition:
		all of them
}