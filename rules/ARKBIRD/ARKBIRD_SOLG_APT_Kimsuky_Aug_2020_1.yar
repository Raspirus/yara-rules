
rule ARKBIRD_SOLG_APT_Kimsuky_Aug_2020_1 : FILE
{
	meta:
		description = "Detect Gold Dragon used by Kimsuky APT group"
		author = "Arkbird_SOLG"
		id = "dd79aa3b-0bbc-5fdd-808e-c2dee6d89804"
		date = "2020-08-31"
		modified = "2020-09-14"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-09-14/Kimsuky/APT_Kimsuky_Aug_2020_1.yar#L1-L23"
		license_url = "N/A"
		logic_hash = "4644ea81535c867a36a882bb270cea784ae135e7acc7078823be0579b1746932"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "4ff2a67b094bcc56df1aec016191465be4e7de348360fd307d1929dc9cbab39f"
		hash2 = "97935fb0b5545a44e136ee07df38e9ad4f151c81f5753de4b59a92265ac14448"

	strings:
		$s1 = "/c systeminfo >> %s" fullword ascii
		$s2 = "/c dir %s\\ >> %s" fullword ascii
		$s3 = ".?AVGen3@@" fullword ascii
		$s4 = { 48 6f 73 74 3a 20 25 73 0d 0a 52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 25 73 25 73 0d 0a 25 73 0d 0a 25 73 }
		$s5 = "%s?filename=%s" fullword ascii
		$s6 = "Content-Disposition: form-data; name=\"userfile\"; filename=\"" fullword ascii
		$s7 = "Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywhpFxMBe19cSjFnG" fullword ascii
		$s8 = "Content-Disposition: form-data; name=\"MAX_FILE_SIZE\"" fullword ascii
		$s9 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; .NET CLR 1.1.4322)" fullword ascii
		$s10 = "\\Microsoft\\HNC" fullword ascii
		$s11 = "Mozilla/5.0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize >150KB and 8 of them
}