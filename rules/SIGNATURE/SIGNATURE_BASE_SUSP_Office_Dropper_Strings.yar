rule SIGNATURE_BASE_SUSP_Office_Dropper_Strings : FILE
{
	meta:
		description = "Detects Office droppers that include a notice to enable active content"
		author = "Florian Roth (Nextron Systems)"
		id = "6560fdf7-46e8-5c16-8263-a36f1dec7868"
		date = "2018-09-13"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_susp_office_dropper.yar#L1-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3a66a86eb99a3e7cd02e3444714c6c88b423cd0ea1e6210bf91da01cf804105f"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "_VBA_PROJECT" wide
		$s1 = "click enable editing" fullword ascii
		$s2 = "click enable content" fullword ascii
		$s3 = "\"Enable Editing\"" fullword ascii
		$s4 = "\"Enable Content\"" fullword ascii

	condition:
		uint16(0)==0xcfd0 and filesize <500KB and $a1 and 1 of ($s*)
}