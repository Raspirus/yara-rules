rule ELCEEF_HTML_Smuggling_A : T1027 FILE
{
	meta:
		description = "Generic detection for HTML smuggling (T1027.006)"
		author = "marcin@ulikowski.pl"
		id = "b711318f-81d2-5d0b-968f-04ae18fdea5b"
		date = "2021-05-13"
		modified = "2023-04-16"
		reference = "https://github.com/elceef/yara-rulz"
		source_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/rules/HTML_Smuggling.yara#L1-L31"
		license_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/LICENSE"
		logic_hash = "bc076e9f3d4c6d2aa5a3602436408e5b2ac3140ca9f7cc776c44835cba211951"
		score = 75
		quality = 75
		tags = "T1027, FILE"
		hash1 = "279d5ef8f80aba530aaac8afd049fa171704fc703d9cfe337b56639732e8ce11"

	strings:
		$mssave = { ( 2e | 22 | 27 ) 6d 73 53 61 76 65 }
		$element = { ( 2e | 22 | 27 ) 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 ( 28 | 22 | 27 ) }
		$objecturl = { ( 2e | 22 | 27 ) 63 72 65 61 74 65 4f 62 6a 65 63 74 55 52 4c ( 28 | 22 | 27 ) }
		$download = { ( 2e | 22 | 27 ) 64 6f 77 6e 6c 6f 61 64 ( 3d | 22 | 27 ) }
		$click = { ( 2e | 22 | 27 ) 63 6c 69 63 6b ( 3d | 22 | 27 ) }
		$atob = { 61 74 6f 62 ( 28 | 22 | 27 ) }
		$blob = "new Blob("
		$array = "new Uint8Array("
		$ole2 = "0M8R4KGxGuEA"
		$pe32 = "TVqQAAMAAAAE"
		$iso = "AAAABQ0QwMDE"
		$udf = "AAAAQkVBMDEB"
		$zip = { 55 45 73 44 42 ( 41 | 42 | 43 | 44 ) ( 6f | 30 | 4d | 51 ) ( 41 | 44 ) ( 41 | 43 ) }
		$jsxor = { 2e 63 68 61 72 43 6f 64 65 41 74 28 [1-10] 29 ( 5e | 20 5e ) }

	condition:
		filesize <5MB and ($mssave or (#element==1 and #objecturl==1 and #download==1 and #click==1)) and $blob and $array and $atob and (#ole2+#pe32+#iso+#udf+#zip+#jsxor)==1
}