rule SIGNATURE_BASE_SUSP_ENV_Folder_Root_File_Jan23_1 : SCRIPT FILE
{
	meta:
		description = "Detects suspicious file path pointing to the root of a folder easily accessible via environment variables"
		author = "Florian Roth (Nextron Systems)"
		id = "6067d822-5c1b-5b86-863c-fdcfa37da665"
		date = "2023-01-11"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_susp_indicators.yar#L3-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5355ae567e6255e22f566bae9fe50f4995bafba07c261461d37d5b8ba200d33a"
		score = 70
		quality = 83
		tags = "SCRIPT, FILE"

	strings:
		$xr1 = /%([Aa]pp[Dd]ata|APPDATA)%\\[A-Za-z0-9_\-]{1,20}\.[a-zA-Z0-9]{1,4}[^\\]/ wide ascii
		$xr2 = /%([Pp]ublic|PUBLIC)%\\[A-Za-z0-9_\-]{1,20}\.[a-zA-Z0-9]{1,4}[^\\]/ wide ascii
		$xr4 = /%([Pp]rogram[Dd]ata|PROGRAMDATA)%\\[A-Za-z0-9_\-]{1,20}\.[a-zA-Z0-9]{1,4}[^\\]/ wide ascii
		$fp1 = "perl -MCPAN " ascii
		$fp2 = "CCleaner" ascii

	condition:
		filesize <20MB and 1 of ($x*) and not 1 of ($fp*) and not pe.number_of_signatures>0
}