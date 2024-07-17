rule ELASTIC_Windows_Ransomware_Lockfile_74185716 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Lockfile (Windows.Ransomware.Lockfile)"
		author = "Elastic Security"
		id = "74185716-e79d-4d63-b6ae-9480f24dcd4f"
		date = "2021-08-31"
		modified = "2022-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Lockfile.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bf315c9c064b887ee3276e1342d43637d8c0e067260946db45942f39b970d7ce"
		logic_hash = "e922c2fc9dd52dd0238847a9d48691bea90d028cf680fc3a1a0dbdfef1d8dce3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "849a0fb5a2e08b2d32db839a7fdbde03a184a48726678e65e7f8452b354a3ca8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "LOCKFILE-README"
		$a2 = "wmic process where \"name  like '%virtualbox%'\" call terminate"
		$a3 = "</computername>"
		$a4 = ".lockfile"

	condition:
		all of them
}