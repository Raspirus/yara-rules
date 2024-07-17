
rule ELCEEF_HTML_Smuggling_B : T1027 FILE
{
	meta:
		description = "Generic detection for HTML smuggling (T1027.006)"
		author = "marcin@ulikowski.pl"
		id = "640d70c2-f1fc-5e32-a720-ebc92839ec40"
		date = "2022-12-02"
		modified = "2023-04-16"
		reference = "https://github.com/elceef/yara-rulz"
		source_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/rules/HTML_Smuggling.yara#L33-L60"
		license_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/LICENSE"
		logic_hash = "3c42e6f715bd5476aea4d47e9f6431747ddf7c7c8098840560201e2c21723eeb"
		score = 75
		quality = 75
		tags = "T1027, FILE"
		hash1 = "63955db0ccd6c0613912afb862635bde0fa925847f27adc8a0d65c994a7e05ea"

	strings:
		$objecturl = { ( 2e | 22 | 27 ) 63 72 65 61 74 65 4f 62 6a 65 63 74 55 52 4c ( 28 | 22 | 27 ) }
		$atob = "atob("
		$blob = "new Blob("
		$file = "new File(["
		$array = "new Uint8Array("
		$ole2 = "0M8R4KGxGuEA"
		$pe32 = "TVqQAAMAAAAE"
		$iso = "AAAABQ0QwMDE"
		$udf = "AAAAQkVBMDEB"
		$zip = { 55 45 73 44 42 ( 41 | 42 | 43 | 44 ) ( 6f | 30 | 4d | 51 ) ( 41 | 44 ) ( 41 | 43 ) }
		$jsxor = { 2e 63 68 61 72 43 6f 64 65 41 74 28 [1-10] 29 ( 5e | 20 5e ) }

	condition:
		filesize <5MB and $atob and #objecturl==1 and #file==1 and #blob==1 and #array==1 and (#ole2+#pe32+#iso+#udf+#zip+#jsxor)==1
}