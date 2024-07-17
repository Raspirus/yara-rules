rule SIGNATURE_BASE_SUSP_RAR_With_PDF_Script_Obfuscation : FILE
{
	meta:
		description = "Detects RAR file with suspicious .pdf extension prefix to trick users"
		author = "Florian Roth (Nextron Systems)"
		id = "a3d2f5e9-3052-551b-8b2c-abcdd1ac2e48"
		date = "2019-04-06"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_suspicious_strings.yar#L269-L285"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "05e9fd7620a70a490548d4562c80497bcf888e493b8e1188e0a0e0c274e2a7e5"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "b629b46b009a1c2306178e289ad0a3d9689d4b45c3d16804599f23c90c6bca5b"

	strings:
		$s1 = ".pdf.vbe" ascii
		$s2 = ".pdf.vbs" ascii
		$s3 = ".pdf.ps1" ascii
		$s4 = ".pdf.bat" ascii
		$s5 = ".pdf.exe" ascii

	condition:
		uint32(0)==0x21726152 and 1 of them
}