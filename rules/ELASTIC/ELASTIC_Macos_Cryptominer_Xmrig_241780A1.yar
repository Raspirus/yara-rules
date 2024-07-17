
rule ELASTIC_Macos_Cryptominer_Xmrig_241780A1 : FILE MEMORY
{
	meta:
		description = "Detects Macos Cryptominer Xmrig (MacOS.Cryptominer.Xmrig)"
		author = "Elastic Security"
		id = "241780a1-ad50-4ded-b85a-26339ae5a632"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Cryptominer_Xmrig.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2e94fa6ac4045292bf04070a372a03df804fa96c3b0cb4ac637eeeb67531a32f"
		logic_hash = "9e091f6881a96abdc6592db385eb9026806befdda6bda4489470b4e16e1d4d87"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "be9c56f18e0f0bdc8c46544039b9cb0bbba595c1912d089b2bcc7a7768ac04a8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = "mining.set_target" ascii fullword
		$a2 = "XMRIG_HOSTNAME" ascii fullword
		$a3 = "Usage: xmrig [OPTIONS]" ascii fullword
		$a4 = "XMRIG_VERSION" ascii fullword

	condition:
		all of them
}