
rule SIGNATURE_BASE_MAL_Fortinet_COATHANGER_Beacon : COATHANGER FILE
{
	meta:
		description = "Detects COATHANGER beaconing code"
		author = "NLD MIVD - JSCU"
		id = "0c84e6e4-afae-5150-82e2-8de528cd11fc"
		date = "2024-02-06"
		modified = "2024-04-24"
		reference = "https://www.ncsc.nl/documenten/publicaties/2024/februari/6/mivd-aivd-advisory-coathanger-tlp-clear"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_fortinet_coathanger_feb24.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e44496e62de8c885d5bd941819a97f4c0dd90ce2d0cfe9d042ab9590cc354ddb"
		score = 75
		quality = 85
		tags = "COATHANGER, FILE"
		malware = "COATHANGER"

	strings:
		$chunk_1 = { 48 B8 47 45 54 20 2F 20 48 54 48 89 45 B0 48 B8 54 50 2F 32 0A 48 6F 73 48 89 45 B8 48 B8 74 3A 20 77 77 77 2E 67 48 89 45 C0 48 B8 6F 6F 67 6C 65 2E 63 6F }

	condition:
		uint32(0)==0x464c457f and filesize <5MB and any of them
}