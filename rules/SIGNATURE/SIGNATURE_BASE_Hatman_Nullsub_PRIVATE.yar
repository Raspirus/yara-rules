private rule SIGNATURE_BASE_Hatman_Nullsub_PRIVATE : HATMAN
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "Florian Roth"
		id = "1b0e708d-6e4c-5688-9fc6-c31a4fb3c4a8"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hatman.yar#L45-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7e7a7494e68450a03aeddfaa1fd0a3fb3cff06684d5bb0c4615571e698293fe3"
		score = 75
		quality = 85
		tags = "HATMAN"

	strings:
		$nullsub = { ff ff 60 38  02 00 00 44  20 00 80 4e }

	condition:
		$nullsub
}