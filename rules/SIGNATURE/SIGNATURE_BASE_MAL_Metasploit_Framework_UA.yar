rule SIGNATURE_BASE_MAL_Metasploit_Framework_UA : FILE
{
	meta:
		description = "Detects User Agent used in Metasploit Framework"
		author = "Florian Roth (Nextron Systems)"
		id = "e5a18456-3a07-5b58-ad95-086152298a1f"
		date = "2018-08-16"
		modified = "2023-12-05"
		reference = "https://github.com/rapid7/metasploit-framework/commit/12a6d67be48527f5d3987e40cac2a0cbb4ab6ce7"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_metasploit_payloads.yar#L325-L339"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "986fea99735b93aed9dbf72582c009e11a1e7ba19b256902f93312474ef34b4a"
		score = 65
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1743e1bd4176ffb62a1a0503a0d76033752f8bd34f6f09db85c2979c04bbdd29"

	strings:
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 1 of them
}