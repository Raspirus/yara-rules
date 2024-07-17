
rule ELASTIC_Windows_Vulndriver_Echodrv_D17Ff31C : FILE
{
	meta:
		description = "Detects Windows Vulndriver Echodrv (Windows.VulnDriver.EchoDrv)"
		author = "Elastic Security"
		id = "d17ff31c-59d1-4bea-be25-c6f7fe2b8c7b"
		date = "2023-10-31"
		modified = "2023-11-03"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_EchoDrv.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ea3c5569405ed02ec24298534a983bcb5de113c18bc3fd01a4dd0b5839cd17b9"
		logic_hash = "0b2eb3c5da8703749ee63662495d6e8738ccdc353f3ac3df48e25a77312c0da0"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "dcf828c8db88580faeaa78f4bcda5a01ff4e710cb3e1e0912a99665831a070b4"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "D:\\WACATACC\\Projects\\Programs\\Echo\\x64\\Release\\echo-driver.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and int16 ( uint32(0x3C)+0x18)==0x020b and $str1
}