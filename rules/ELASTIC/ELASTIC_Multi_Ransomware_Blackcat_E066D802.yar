rule ELASTIC_Multi_Ransomware_Blackcat_E066D802 : FILE MEMORY
{
	meta:
		description = "Detects Multi Ransomware Blackcat (Multi.Ransomware.BlackCat)"
		author = "Elastic Security"
		id = "e066d802-b803-4e35-9b53-ae1823662483"
		date = "2023-07-27"
		modified = "2023-09-20"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Multi_Ransomware_BlackCat.yar#L93-L113"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "00360830bf5886288f23784b8df82804bf6f22258e410740db481df8a7701525"
		logic_hash = "00fbb8013faf26c35b6cd8a72ebc246444c37c5ec7a0df2295830e96c01c8720"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "05037af3395b682d1831443757376064c873815ac4b6d1c09116715570f51f5d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "multi"

	strings:
		$a1 = "esxcli vm process kill --type=force --world-id=Killing"
		$a2 = "vim-cmd vmsvc/snapshot.removeall $i"
		$a3 = "File already has encrypted extension"

	condition:
		2 of them
}