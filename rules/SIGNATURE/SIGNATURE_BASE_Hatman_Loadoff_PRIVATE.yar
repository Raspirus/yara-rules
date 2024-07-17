
private rule SIGNATURE_BASE_Hatman_Loadoff_PRIVATE : HATMAN
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "Florian Roth"
		id = "1ad2f77b-4360-512d-ac06-9933ac2cdc67"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hatman.yar#L74-L82"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "70d33c40b919d1852eded8c4afa96978c8b4503f95fb4a48e1d8b89864b77d38"
		score = 75
		quality = 85
		tags = "HATMAN"

	strings:
		$loadoff_be = { 80 60 00 04  48 00 ?? ??  70 60 ff ff  28 00 00 00
                        40 82 ?? ??  28 03 00 00  41 82 ?? ??              }
		$loadoff_le = { 04 00 60 80  ?? ?? 00 48  ff ff 60 70  00 00 00 28
                        ?? ?? 82 40  00 00 03 28  ?? ?? 82 41              }

	condition:
		$loadoff_be or $loadoff_le
}