
rule ELASTIC_Windows_Ransomware_Conti_89F3F6Fa : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Conti (Windows.Ransomware.Conti)"
		author = "Elastic Security"
		id = "89f3f6fa-492c-40e3-a4aa-a526004197b2"
		date = "2021-08-05"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Conti.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "eae876886f19ba384f55778634a35a1d975414e83f22f6111e3e792f706301fe"
		logic_hash = "4c1834e45d5e42f466249b75a89561ce1e88b9e3c07070e2833d4897fbed22ee"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a82331eba3cbd52deb4bed5e11035ac1e519ec27931507f582f2985865c0fb1a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { F7 FE 88 57 FF 83 EB 01 75 DA 8B 45 FC 5F 5B 40 5E 8B E5 5D C3 8D }

	condition:
		all of them
}