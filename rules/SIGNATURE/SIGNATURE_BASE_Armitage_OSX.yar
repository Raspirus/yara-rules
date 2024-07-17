
rule SIGNATURE_BASE_Armitage_OSX : FILE
{
	meta:
		description = "Detects Armitage component"
		author = "Florian Roth (Nextron Systems)"
		id = "e886e866-c163-56fb-9631-c586e9f23f9e"
		date = "2017-12-24"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_armitage.yar#L52-L68"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "25c94b9715fdc10d0e04eea7d5b9974e60f3e248f51b80de80542b169996fc7a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2680d9900a057d553fcb28d84cdc41c3fc18fd224a88a32ee14c9c1b501a86af"
		hash2 = "b7b506f38d0553cd2beb4111c7ef383c821f04cee5169fed2ef5d869c9fbfab3"

	strings:
		$x1 = "resources/covertvpn-injector.exe" fullword ascii
		$s10 = "resources/browserpivot.x64.dll" fullword ascii
		$s17 = "resources/msfrpcd_new.bat" fullword ascii

	condition:
		filesize <6000KB and 1 of them
}