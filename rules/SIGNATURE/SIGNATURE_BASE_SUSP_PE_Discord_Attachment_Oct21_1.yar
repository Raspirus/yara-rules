
rule SIGNATURE_BASE_SUSP_PE_Discord_Attachment_Oct21_1 : FILE
{
	meta:
		description = "Detects suspicious executable with reference to a Discord attachment (often used for malware hosting on a legitimate FQDN)"
		author = "Florian Roth (Nextron Systems)"
		id = "7c217350-4a35-505d-950d-1bc989c14bc2"
		date = "2021-10-12"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_suspicious_strings.yar#L407-L421"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4d84ec50738f4c7aca8e77c3aabdcd77f3071733a2245a58283f070f2b220599"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "https://cdn.discordapp.com/attachments/" ascii wide

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and 1 of them
}