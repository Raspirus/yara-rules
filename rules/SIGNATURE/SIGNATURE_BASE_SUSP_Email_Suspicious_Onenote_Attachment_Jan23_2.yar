rule SIGNATURE_BASE_SUSP_Email_Suspicious_Onenote_Attachment_Jan23_2 : FILE
{
	meta:
		description = "Detects suspicious OneNote attachment that has a file name often used in phishing attacks"
		author = "Florian Roth (Nextron Systems)"
		id = "f8c58c73-2404-5ce6-8e8f-99b0dad84ad0"
		date = "2023-01-27"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_onenote_phish.yar#L41-L61"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "eb6f992ce186022f04613af3bf4df629b00d85eac151f8bbd4b8ef96e6892eab"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$hc1 = { 2E 6F 6E 65 22 0D 0A 0D 0A 35 46 4A 63 65 }
		$x01 = " attachment; filename=\"Invoice" nocase
		$x02 = " attachment; filename=\"ORDER" nocase
		$x03 = " attachment; filename=\"PURCHASE" nocase
		$x04 = " attachment; filename=\"SHIP" nocase

	condition:
		filesize <5MB and $hc1 and 1 of ($x*)
}