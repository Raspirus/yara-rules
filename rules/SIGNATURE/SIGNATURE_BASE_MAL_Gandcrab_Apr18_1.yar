import "pe"


rule SIGNATURE_BASE_MAL_Gandcrab_Apr18_1 : FILE
{
	meta:
		description = "Detects GandCrab malware"
		author = "Florian Roth (Nextron Systems)"
		id = "ef7983cd-a7b3-5ce2-8cff-1bcf35bc6140"
		date = "2018-04-23"
		modified = "2023-12-05"
		reference = "https://twitter.com/MarceloRivero/status/988455516094550017"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_mal_grandcrab.yar#L3-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "70fc8deb91126a7404095aaa512e9b7542fe8605f83a037a10f8ccff76c27d4f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6fafe7bb56fd2696f2243fc305fe0c38f550dffcfc5fca04f70398880570ffff"

	condition:
		uint16(0)==0x5a4d and filesize <800KB and pe.imphash()=="7936b0e9491fd747bf2675a7ec8af8ba"
}