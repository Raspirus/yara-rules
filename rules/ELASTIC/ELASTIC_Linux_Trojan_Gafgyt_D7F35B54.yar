
rule ELASTIC_Linux_Trojan_Gafgyt_D7F35B54 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "d7f35b54-82a8-4ef0-8c8c-30a6734223e1"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1407-L1425"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
		logic_hash = "d827e21c09b8dce65db293aa57b39f49f034537bb708471989ad64e653c479be"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d01db0f6a169d82d921c76801738108a2f0ef4ef65ea2e104fb80188a3bb73b8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FD 48 FD 45 FD 48 FD FD FD FD FD FD FD FD FD 48 FD 45 FD 66 }

	condition:
		all of them
}