
rule SIGNATURE_BASE_APT_MAL_URL_Cloudatlas_Oct20_2 : FILE
{
	meta:
		description = "Detects unknown maldoc dropper noticed in October 2020 - file morgue6visible5bunny6culvert7ambo5nun1illuminate4.url"
		author = "Florian Roth (Nextron Systems)"
		id = "91f6362f-1793-58a3-a750-04ec9812b9df"
		date = "2020-10-13"
		modified = "2023-12-05"
		reference = "https://twitter.com/jfslowik/status/1316050637092651009"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_cloudatlas.yar#L18-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8bb60c262a34babbe8839f5d39d1c972eeb41ea77eaae02cc877d908c7033f13"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "a6a58b614a9f5ffa1d90b5d42e15521f52e2295f02c1c0e5cd9cbfe933303bee"

	strings:
		$hc1 = { 5B 49 6E 74 65 72 6E 65 74 53 68 6F 72 74 63 75
               74 5D 0D 0A 55 52 4C 3D 68 74 74 70 73 3A 2F 2F
               6D 73 6F 66 66 69 63 65 75 70 64 61 74 65 2E 6F
               72 67 }

	condition:
		uint16(0)==0x495b and filesize <200 and $hc1 at 0
}