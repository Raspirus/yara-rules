
rule SIGNATURE_BASE_MAL_Gozicrypter_Dec20_1 : FILE
{
	meta:
		description = "Detects crypter associated with several Gozi samples"
		author = "James Quinn"
		id = "d4a48612-fa6f-5f03-8d27-5f6b79b2a070"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "YaraExchange"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_gozi_crypter.yar#L2-L13"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "51fdfbb59b8f52cc2ff89d994c0f89d2c2895c346b098879c68b4ccb880783c1"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$s1 = { 89 05 ?? ?? ?? ?? 81 2d ?? ?? ?? ?? 01 00 00 00 81 3D ?? ?? ?? ?? 00 00 00 00 }

	condition:
		uint16(0)==0x5A4D and any of them and filesize <1000KB
}