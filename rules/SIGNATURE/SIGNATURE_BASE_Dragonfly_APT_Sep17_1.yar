import "pe"


rule SIGNATURE_BASE_Dragonfly_APT_Sep17_1 : FILE
{
	meta:
		description = "Detects malware from DrqgonFly APT report"
		author = "Florian Roth (Nextron Systems)"
		id = "d219a54e-cb76-5c56-b64c-5019e811eeb1"
		date = "2017-09-12"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_dragonfly.yar#L29-L44"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c885fb690b7e047203529f0c4a6dd60dea822ce60a47e42b52d3216bc26da62e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fc54d8afd2ce5cb6cc53c46783bf91d0dd19de604308d536827320826bc36ed9"

	strings:
		$s1 = "\\Update\\Temp\\ufiles.txt" wide
		$s2 = "%02d.%02d.%04d %02d:%02d" fullword wide
		$s3 = "*pass*.*" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}