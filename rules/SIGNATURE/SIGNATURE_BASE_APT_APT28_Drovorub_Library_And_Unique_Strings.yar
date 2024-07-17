rule SIGNATURE_BASE_APT_APT28_Drovorub_Library_And_Unique_Strings : FILE
{
	meta:
		description = "Rule to detect Drovorub-server, Drovorub-agent, and Drovorub-client"
		author = "NSA / FBI"
		id = "8e010356-09c7-5897-9cbe-051cd0800502"
		date = "2020-08-13"
		modified = "2023-12-05"
		reference = "https://www.nsa.gov/news-features/press-room/Article/2311407/nsa-and-fbi-expose-russian-previously-undisclosed-malware-drovorub-in-cybersecu/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt28_drovorub.yar#L23-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "adb0d4cb6d589213e6a125d3cc20fcea8164b697bdd24d897ce75e7c7f06120a"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "Poco" ascii wide
		$s2 = "Json" ascii wide
		$s3 = "OpenSSL" ascii wide
		$a1 = "clientid" ascii wide
		$a2 = "-----BEGIN" ascii wide
		$a3 = "-----END" ascii wide
		$a4 = "tunnel" ascii wide

	condition:
		( filesize >1MB and filesize <10MB and ( uint32(0)==0x464c457f)) and (#s1>20 and #s2>15 and #s3>15 and all of ($a*))
}