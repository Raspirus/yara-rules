rule SIGNATURE_BASE_Lazarus_Dec_17_1 : FILE
{
	meta:
		description = "Detects Lazarus malware from incident in Dec 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "f195ebf0-d7af-58e8-a544-769a0c8b628b"
		date = "2017-12-20"
		modified = "2023-12-05"
		reference = "https://goo.gl/8U6fY2"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lazarus_dec17.yar#L12-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "50ff8418cf342147a81ef3a418e5e61d42f0e5764982e43b51d4dd3a983a548e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d5f9a81df5061c69be9c0ed55fba7d796e1a8ebab7c609ae437c574bd7b30b48"

	strings:
		$s1 = "::DataSpace/Storage/MSCompressed/Transform/" ascii
		$s2 = "HHA Version 4." ascii
		$s3 = { 74 45 58 74 53 6F 66 74 77 61 72 65 00 41 64 6F
              62 65 20 49 6D 61 67 65 52 65 61 64 79 71 }
		$s4 = "bUEeYE" fullword ascii

	condition:
		uint16(0)==0x5449 and filesize <4000KB and all of them
}