import "pe"


rule SIGNATURE_BASE_MAL_WIPER_Isaacwiper_Mar22_1 : FILE
{
	meta:
		description = "Detects IsaacWiper malware"
		author = "Florian Roth (Nextron Systems)"
		id = "97d8d8dd-db65-5156-8f97-56c620cf2d56"
		date = "2022-03-03"
		modified = "2023-12-05"
		reference = "https://www.welivesecurity.com/2022/03/01/isaacwiper-hermeticwizard-wiper-worm-targeting-ukraine/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ua_isaacwiper.yar#L3-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6fe7d1536db5fc30c9b4a171be66993fc69e6a1d96dae00be4170bdb4a53afb8"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
		hash2 = "7bcd4ec18fc4a56db30e0aaebd44e2988f98f7b5d8c14f6689f650b4f11e16c0"

	strings:
		$s1 = "C:\\ProgramData\\log.txt" wide fullword
		$s2 = "Cleaner.dll" ascii fullword
		$s3 = "-- system logical drive: " wide fullword
		$s4 = "-- FAILED" wide fullword
		$op1 = { 8b f1 80 3d b0 66 03 10 00 0f 85 96 00 00 00 33 c0 40 b9 a8 66 03 10 87 01 33 db }
		$op2 = { 8b 40 04 2b c2 c1 f8 02 3b c8 74 34 68 a2 c8 01 10 2b c1 6a 04 }
		$op3 = { 8d 4d f4 ff 75 08 e8 12 ff ff ff 68 88 39 03 10 8d 45 f4 50 e8 2d 1d 00 00 cc }

	condition:
		uint16(0)==0x5a4d and filesize <700KB and (pe.imphash()=="a4b162717c197e11b76a4d9bc58ea25d" or 3 of them )
}