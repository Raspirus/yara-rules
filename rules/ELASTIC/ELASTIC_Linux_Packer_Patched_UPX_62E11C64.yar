rule ELASTIC_Linux_Packer_Patched_UPX_62E11C64 : FILE
{
	meta:
		description = "Detects Linux Packer Patched_Upx (Linux.Packer.Patched_UPX)"
		author = "Elastic Security"
		id = "62e11c64-fc7d-4a0a-9d72-ad53ec3987ff"
		date = "2021-06-08"
		modified = "2021-07-28"
		reference = "https://cujo.com/upx-anti-unpacking-techniques-in-iot-malware/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Packer_Patched_UPX.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "02f81a1e1edcb9032a1d7256a002b11e1e864b2e9989f5d24ea1c9b507895669"
		logic_hash = "cb576fdd59c255234a96397460b81cbb2deeb38befaed101749b7bb515624028"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "3297b5c63e70c557e71b739428b453039b142e1e04c2ab15eea4627d023b686d"
		severity = 60
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 55 50 58 21 [4] 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		all of them and $a in (0..255)
}