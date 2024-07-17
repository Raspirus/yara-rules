
rule SIGNATURE_BASE_M_Hunting_Credtheft_WARPWIRE_1 : FILE
{
	meta:
		description = "This rule detects WARPWIRE, a credential stealer written in JavaScript that is embedded into a legitimate Pulse Secure file."
		author = "Mandiant"
		id = "9a6a8783-b531-560d-998d-8aa7c90158a8"
		date = "2024-01-11"
		modified = "2024-04-24"
		reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_report_ivanti_mandiant_jan24.yar#L102-L120"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "d0c7a334a4d9dcd3c6335ae13bee59ea"
		logic_hash = "8029df5998166ab3db3319b0dd765ef3356b4b44dc16d2d418015a0f7ffac97e"
		score = 75
		quality = 77
		tags = "FILE"

	strings:
		$s1 = {76 61 72 20 77 64 61 74 61 20 3d 20 64 6f 63 75 6d 65 6e 74 2e 66 72 6d 4c 6f 67 69 6e 2e 75 73 65 72 6e 61 6d 65 2e 76 61 6c 75 65 3b}
		$s2 = {76 61 72 20 73 64 61 74 61 20 3d 20 64 6f 63 75 6d 65 6e 74 2e 66 72 6d 4c 6f 67 69 6e 2e 70 61 73 73 77 6f 72 64 2e 76 61 6c 75 65 3b}
		$s3 = {2b 77 64 61 74 61 2b 27 26 27 2b 73 64 61 74 61 3b}
		$s4 = {76 61 72 20 78 68 72 20 3d 20 6e 65 77 20 58 4d 4c 48 74 74 70 52 65 71 75 65 73 74}
		$s5 = "Remember the last selected auth realm for 30 days" ascii

	condition:
		filesize <8KB and all of them
}