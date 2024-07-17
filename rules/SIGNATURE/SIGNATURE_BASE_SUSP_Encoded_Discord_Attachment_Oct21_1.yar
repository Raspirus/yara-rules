rule SIGNATURE_BASE_SUSP_Encoded_Discord_Attachment_Oct21_1 : FILE
{
	meta:
		description = "Detects suspicious encoded URL to a Discord attachment (often used for malware hosting on a legitimate FQDN)"
		author = "Florian Roth (Nextron Systems)"
		id = "06c086f4-8b79-5506-9e3f-b5d099106157"
		date = "2021-10-12"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_suspicious_strings.yar#L423-L448"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1ea5a83e91b5c5b4b8a1d507c365bc1583394c97a28b7d7a576f085854676769"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$enc_b01 = "Y2RuLmRpc2NvcmRhcHAuY29tL2F0dGFjaG1lbnRz" ascii wide
		$enc_b02 = "Nkbi5kaXNjb3JkYXBwLmNvbS9hdHRhY2htZW50c" ascii wide
		$enc_b03 = "jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobWVudH" ascii wide
		$enc_b04 = "AGMAZABuAC4AZABpAHMAYwBvAHIAZABhAHAAcAAuAGMAbwBtAC8AYQB0AHQAYQBjAGgAbQBlAG4AdABz" ascii wide
		$enc_b05 = "BjAGQAbgAuAGQAaQBzAGMAbwByAGQAYQBwAHAALgBjAG8AbQAvAGEAdAB0AGEAYwBoAG0AZQBuAHQAc" ascii wide
		$enc_b06 = "AYwBkAG4ALgBkAGkAcwBjAG8AcgBkAGEAcABwAC4AYwBvAG0ALwBhAHQAdABhAGMAaABtAGUAbgB0AH" ascii wide
		$enc_h01 = "63646E2E646973636F72646170702E636F6D2F6174746163686D656E7473" ascii wide
		$enc_h02 = "63646e2e646973636f72646170702e636f6d2f6174746163686d656e7473" ascii wide
		$enc_r01 = "stnemhcatta/moc.ppadrocsid.ndc" ascii wide

	condition:
		filesize <5000KB and 1 of them
}