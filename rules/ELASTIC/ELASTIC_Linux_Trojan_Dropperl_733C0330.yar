rule ELASTIC_Linux_Trojan_Dropperl_733C0330 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Dropperl (Linux.Trojan.Dropperl)"
		author = "Elastic Security"
		id = "733c0330-3163-48f3-a780-49be80a3387f"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Dropperl.yar#L101-L119"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b303f241a2687dba8d7b4987b7a46b5569bd2272e2da3e0c5e597b342d4561b6"
		logic_hash = "37bf7777e26e556f09b8cb0e7e3c8425226a6412c3bed0d95fdab7229b6f4815"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ee233c875dd3879b4973953a1f2074cd77abf86382019eeb72da069e1fd03e1c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E8 A0 FB FF FF 83 7D DC 00 79 0A B8 ?? ?? 60 00 }

	condition:
		all of them
}