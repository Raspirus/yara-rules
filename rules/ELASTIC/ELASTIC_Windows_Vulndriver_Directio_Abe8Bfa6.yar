rule ELASTIC_Windows_Vulndriver_Directio_Abe8Bfa6 : FILE
{
	meta:
		description = "Detects Windows Vulndriver Directio (Windows.VulnDriver.DirectIo)"
		author = "Elastic Security"
		id = "abe8bfa6-0b51-4224-a7fc-4249e34ac0a2"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_DirectIo.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d84e3e250a86227c64a96f6d5ac2b447674ba93d399160850acb2339da43eae5"
		logic_hash = "8548e64e091c0e9e53316662d3dd91eca605c260f391d752ad40253f225571ed"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "f572092a61c4b7f107c397deb6eb9e04d56a0c74ba0a17cc218e33d17e909f18"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\DirectIo64.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}