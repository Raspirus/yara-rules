rule SIGNATURE_BASE_MAL_Burningumbrella_Sample_13 : FILE
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		author = "Florian Roth (Nextron Systems)"
		id = "38c73425-bbdd-5b74-8ad4-5e0052039dd8"
		date = "2018-05-04"
		modified = "2023-12-05"
		reference = "https://401trg.pw/burning-umbrella/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L203-L215"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8cc611685a822e0484146a08f4ebc2fa8dd260dc8627929333060696d8dc35ce"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d31374adc0b96a8a8b56438bbbc313061fd305ecee32a12738dd965910c8890f"
		hash2 = "c74a8e6c88f8501fb066ae07753efe8d267afb006f555811083c51c7f546cb67"

	condition:
		uint16(0)==0x5a4d and filesize <100KB and pe.imphash()=="75f201aa8b18e1c4f826b2fe0963b84f"
}