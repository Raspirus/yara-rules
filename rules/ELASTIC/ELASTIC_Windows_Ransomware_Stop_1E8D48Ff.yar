rule ELASTIC_Windows_Ransomware_Stop_1E8D48Ff : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Stop (Windows.Ransomware.Stop)"
		author = "Elastic Security"
		id = "1e8d48ff-e0ab-478d-8268-a11f2e87ab79"
		date = "2021-06-10"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Stop.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "821b27488f296e15542b13ac162db4a354cbf4386b6cd40a550c4a71f4d628f3"
		logic_hash = "d743feae072a5f3e1b008354352bef48218bb041bc8a5ba39526815ab9cd2690"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "715888e3e13aaa33f2fd73beef2c260af13e9726cb4b43d349333e3259bf64eb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = "E:\\Doc\\My work (C++)\\_Git\\Encryption\\Release\\encrypt_win_api.pdb" ascii fullword
		$b = { 68 FF FF FF 50 FF D3 8D 85 78 FF FF FF 50 FF D3 8D 85 58 FF }

	condition:
		any of them
}