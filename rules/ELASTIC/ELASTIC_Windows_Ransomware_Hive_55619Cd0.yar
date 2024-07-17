rule ELASTIC_Windows_Ransomware_Hive_55619Cd0 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Hive (Windows.Ransomware.Hive)"
		author = "Elastic Security"
		id = "55619cd0-6013-45e2-b15e-0dceff9571ab"
		date = "2021-08-26"
		modified = "2022-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Hive.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "50ad0e6e9dc72d10579c20bb436f09eeaa7bfdbcb5747a2590af667823e85609"
		logic_hash = "51e2b03a9f9b92819bbf05ecbb33a23662a40e7d51f9812aa8243c4506057f1f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "04df3169c50fbab4e2b495de5500c62ddf5e76aa8b4a7fc8435f39526f69c52b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "google.com/encryptor.(*App).KillProcesses" ascii fullword
		$a2 = "- Do not shutdown or reboot your computers, unmount external storages." ascii fullword
		$a3 = "hive"

	condition:
		all of them
}