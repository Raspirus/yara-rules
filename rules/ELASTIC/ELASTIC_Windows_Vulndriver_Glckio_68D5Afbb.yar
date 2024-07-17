rule ELASTIC_Windows_Vulndriver_Glckio_68D5Afbb : FILE
{
	meta:
		description = "Detects Windows Vulndriver Glckio (Windows.VulnDriver.GlckIo)"
		author = "Elastic Security"
		id = "68d5afbb-a90e-404a-8e77-4b0f9d72934c"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_GlckIo.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5ae23f1fcf3fb735fcf1fa27f27e610d9945d668a149c7b7b0c84ffd6409d99a"
		logic_hash = "0b5f0d408a5c4089ef496c5f8241a34d0468cc3d21e89e41dc105a0df0855d38"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "98b25bf15be40dcd9cedbce6d50551faa968ac0e8259c1df0181ecb36afc69dd"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "[GLKIO2] Cannot resolve ZwQueryInformationProcess"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and int16 ( uint32(0x3C)+0x18)==0x020b and $str1
}