rule ELASTIC_Windows_Vulndriver_Asio_5F9F29Be : FILE
{
	meta:
		description = "Detects Windows Vulndriver Asio (Windows.VulnDriver.AsIo)"
		author = "Elastic Security"
		id = "5f9f29be-9dbb-4d0f-84f5-7027c1413c2c"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_AsIo.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "52a90fd1546c068b92add52c29fbb8a87d472a57e609146bbcb34862f9dcec15"
		logic_hash = "a901d81737c7e6d00e87f0eec758dd063eade59d9883e85e04a33bb18f2f99de"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "82967badefb37a3964de583cb65f423afe46abc299d361c7a9cd407b146fd897"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\AsIO.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}