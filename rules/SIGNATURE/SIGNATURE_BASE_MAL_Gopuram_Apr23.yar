
rule SIGNATURE_BASE_MAL_Gopuram_Apr23 : FILE
{
	meta:
		description = "Detects Lazarus Gopuram malware"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e0bb43b0-542b-5c8e-bcba-0326f80efaa0"
		date = "2023-04-04"
		modified = "2023-12-05"
		reference = "https://securelist.com/gopuram-backdoor-deployed-through-3cx-supply-chain-attack/109344/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lazarus_gopuram.yar#L1-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "beb775af5196f30e0ee021790a4978ca7a7ac2a7cf970a5a620ffeb89cc60b2c"
		hash = "97b95b4a5461f950e712b82783930cb2a152ec0288c00a977983ca7788342df7"
		logic_hash = "58d978bd09a656f2a10a4d5d2585e51efe5cfb6b6648a4b3c2ce8c4f5d2256d4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"

	strings:
		$path = "%s.TxR.0.regtrans-ms"

	condition:
		uint16(0)==0x5A4D and $path and filesize <10MB
}