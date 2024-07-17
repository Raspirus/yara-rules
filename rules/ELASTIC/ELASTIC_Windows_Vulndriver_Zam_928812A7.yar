
rule ELASTIC_Windows_Vulndriver_Zam_928812A7 : FILE
{
	meta:
		description = "Detects Windows Vulndriver Zam (Windows.VulnDriver.Zam)"
		author = "Elastic Security"
		id = "928812a7-ac7c-47cf-9111-11470b661d46"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Zam.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91"
		logic_hash = "82ca874d60d8a0ee04aca39f59415f22797e7e0337314c88dd8ebad1a823d200"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "8e5db0d4fee806538929680e7d3521b111b0e09fcc3eba3c191f6787375999cc"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$pdb_64 = "AntiMalware\\bin\\zam64.pdb"
		$pdb_32 = "AntiMalware\\bin\\zam32.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and any of ($pdb_*)
}