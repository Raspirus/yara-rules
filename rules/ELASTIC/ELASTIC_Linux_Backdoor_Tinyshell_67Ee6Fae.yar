
rule ELASTIC_Linux_Backdoor_Tinyshell_67Ee6Fae : FILE MEMORY
{
	meta:
		description = "Detects Linux Backdoor Tinyshell (Linux.Backdoor.Tinyshell)"
		author = "Elastic Security"
		id = "67ee6fae-304b-47f5-93b6-4086a864d433"
		date = "2021-10-12"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Backdoor_Tinyshell.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9d2e25ec0208a55fba97ac70b23d3d3753e9b906b4546d1b14d8c92f8d8eb03d"
		logic_hash = "200d4267e21b8934deecc48273294f2e34464fcb412e39f3f5a006278631b9f1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f71ce364fb607ee6f4422864674ae3d053453b488c139679aa485466893c563d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "Usage: %s [ -c [ connect_back_host ] ] [ -s secret ] [ -p port ]" fullword
		$a2 = "s:p:c::" fullword
		$b1 = "Usage: %s [ -s secret ] [ -p port ] [command]" fullword
		$b2 = "<hostname|cb> get <source-file> <dest-dir>" fullword

	condition:
		( all of ($a*)) or ( all of ($b*))
}