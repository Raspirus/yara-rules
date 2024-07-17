rule ELASTIC_Windows_Vulndriver_Gvci_F5A35359 : FILE
{
	meta:
		description = "Detects Windows Vulndriver Gvci (Windows.VulnDriver.Gvci)"
		author = "Elastic Security"
		id = "f5a35359-ee16-444a-aafd-c4ef162e46d4"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Gvci.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "42f0b036687cbd7717c9efed6991c00d4e3e7b032dc965a2556c02177dfdad0f"
		logic_hash = "beb0c324358a016e708dae30a222373113a7eab8e3d90dfa1bbde6c2f7874362"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "590e6b10c8bd1c299eb4ecd1368ac05d8811147c7ce3976de5e86d1a6d8bc14f"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\GVCIDrv64.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}