rule SIGNATURE_BASE_MAL_Emotet_BKA_Cleanup_Apr21 : FILE
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "press inquiries <info@bka.de>, technical contact <info@mha.bka.de>"
		id = "10d93918-8a5e-54a3-81c6-f6ff68562e13"
		date = "2021-03-23"
		modified = "2023-12-05"
		reference = "https://www.bka.de/DE/IhreSicherheit/RichtigesVerhalten/StraftatenImInternet/FAQ/FAQ_node.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_emotet.yar#L54-L70"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "533adaed96d015ea2dcd54d5aaf9e71b5b70430ed5733a98618925cf978a6515"
		score = 75
		quality = 85
		tags = "FILE"
		descripton = "This rule targets a modified emotet binary deployed by the Bundeskriminalamt on the 26th of January 2021."
		note = "The binary will replace the original emotet by copying it to a quarantine. It also contains a routine to perform a self-deinstallation on the 25th of April 2021. The three-month timeframe between rollout and self-deinstallation was chosen primarily for evidence purposes as well as to allow remediation."
		sharing = "TLP:WHITE"

	strings:
		$key = { c3 da da 19 63 45 2c 86 77 3b e9 fd 24 64 fb b8 07 fe 12 d0 2a 48 13 38 48 68 e8 ae 91 3c ed 82 }

	condition:
		filesize >300KB and filesize <700KB and uint16(0)==0x5A4D and $key
}