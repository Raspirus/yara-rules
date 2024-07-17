rule SIGNATURE_BASE_APT_Sandworm_Keywords_May20_1 : CVE_2019_10149 FILE
{
	meta:
		description = "Detects commands used by Sandworm group to exploit critical vulernability CVE-2019-10149 in Exim"
		author = "Florian Roth (Nextron Systems)"
		id = "e0d4e90e-5547-5487-8d0c-a141d88fff7c"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sandworm_exim_expl.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9f9a81ff0c576f05ac063eaca7a5882dbdb09c9a0778610cca2864636a00efce"
		score = 75
		quality = 85
		tags = "CVE-2019-10149, FILE"

	strings:
		$x1 = "MAIL FROM:<$(run("
		$x2 = "exec\\x20\\x2Fusr\\x2Fbin\\x2Fwget\\x20\\x2DO\\x20\\x2D\\x20http"

	condition:
		filesize <8000KB and 1 of them
}