import "pe"


rule SIGNATURE_BASE_BKDR_Snarasite_Oct17 : FILE
{
	meta:
		description = "Auto-generated rule"
		author = "Florian Roth (Nextron Systems)"
		id = "3a5d156a-529b-52ae-9b6a-d454895eb1fb"
		date = "2017-10-07"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_snarasite.yar#L3-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "79f49bce6de996d20b64476feb73987fdcd7555963ea1a596648d8702fbd2898"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "36ba92cba23971ca9d16a0b4f45c853fd5b3108076464d5f2027b0f56054fd62"

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and (pe.imphash()=="322bef04e1e1ac48875036e38fb5c23c" or pe.imphash()=="15088754757513c92fa36ba5590e907b")
}