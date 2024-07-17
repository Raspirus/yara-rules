rule ELASTIC_Linux_Hacktool_Flooder_25C48456 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "25c48456-2f83-41a8-ba37-b557014d1d86"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L300-L318"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "eba6f3e4f7b53e22522d82bdbdf5271c3fc701cbe07e9ecb7b4c0b85adc9d6b4"
		logic_hash = "4ed4b901fccaed834b9908fb447da1521bf31f283ae55b6d8f6090814cf8fcd2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0c79f8eaacd2aa1fa60d5bfb7b567a9fc3e65068be1516ca723cb1394bb564ce"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 F8 48 83 6D E0 01 48 83 7D E0 00 75 DD 48 8B 45 F0 C9 C3 55 48 }

	condition:
		all of them
}