rule SIGNATURE_BASE_MAL_Emotet_JS_Dropper_Oct19_1 : FILE
{
	meta:
		description = "Detects Emotet JS dropper"
		author = "Florian Roth (Nextron Systems)"
		id = "34605452-8f3d-540a-b66f-4f68d9187003"
		date = "2019-10-03"
		modified = "2023-12-05"
		reference = "https://app.any.run/tasks/aaa75105-dc85-48ca-9732-085b2ceeb6eb/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_emotet.yar#L2-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "563077f3bc8ee18a887eecb9f0591c693e5543a9875eebad2186745154af1ade"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "38295d728522426672b9497f63b72066e811f5b53a14fb4c4ffc23d4efbbca4a"
		hash2 = "9bc004a53816a5b46bfb08e819ac1cf32c3bdc556a87a58cbada416c10423573"

	strings:
		$xc1 = { FF FE 76 00 61 00 72 00 20 00 61 00 3D 00 5B 00
               27 00 }

	condition:
		uint32(0)==0x0076feff and filesize <=700KB and $xc1 at 0
}