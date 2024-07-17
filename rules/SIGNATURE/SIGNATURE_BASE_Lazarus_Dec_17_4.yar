
rule SIGNATURE_BASE_Lazarus_Dec_17_4 : FILE
{
	meta:
		description = "Detects Lazarus malware from incident in Dec 2017ithumb.js"
		author = "Florian Roth (Nextron Systems)"
		id = "fbdc6287-c177-53b5-83dd-979936f65192"
		date = "2017-12-20"
		modified = "2023-12-05"
		reference = "https://goo.gl/8U6fY2"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lazarus_dec17.yar#L53-L67"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "70801347699d339cb47cad03ec3f694b09a976e32b70052a97fade09fcac679d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8ff100ca86cb62117f1290e71d5f9c0519661d6c955d9fcfb71f0bbdf75b51b3"
		hash2 = "7975c09dd436fededd38acee9769ad367bfe07c769770bd152f33a10ed36529e"

	strings:
		$s1 = "var _0xf5ed=[\"\\x57\\x53\\x63\\x72\\x69\\x70\\x74\\x2E\\x53\\x68\\x65\\x6C\\x6C\"," ascii

	condition:
		filesize <9KB and 1 of them
}