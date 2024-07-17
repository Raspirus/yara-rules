
rule ELASTIC_Windows_Vulndriver_Procid_86605Fa9 : FILE
{
	meta:
		description = "Detects Windows Vulndriver Procid (Windows.VulnDriver.ProcId)"
		author = "Elastic Security"
		id = "86605fa9-bf1a-4c2c-87f5-cb656ebe4cf3"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_ProcId.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b03f26009de2e8eabfcf6152f49b02a55c5e5d0f73e01d48f5a745f93ce93a29"
		logic_hash = "882cdbd267d812e77e68e7080f1fca0ca3d7e75ab84c583c3ec148894b1cf644"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "6d8d926efd98d6eaa1d06d39fb5babf70abf6f0e639fb74f29f65836a79e4743"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\piddrv64.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}