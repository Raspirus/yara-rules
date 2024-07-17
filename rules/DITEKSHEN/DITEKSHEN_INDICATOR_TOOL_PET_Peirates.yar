rule DITEKSHEN_INDICATOR_TOOL_PET_Peirates : FILE
{
	meta:
		description = "Detects Kubernetes penetration tool Peirates"
		author = "ditekSHen"
		id = "74ce83ed-0d93-5cb0-97e8-6885ae83b336"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L677-L694"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "321f06af098283638f99d027dc3c95a25a72192a25c7afa5081a7dbff8c3acb7"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "DeprecatedServiceAccount" fullword ascii
		$s2 = "LivenessProbe" fullword ascii
		$s3 = "\\t\\tkubectl expose rs nginx --port=80 --target-port=8000" ascii
		$s4 = "\\t\\tkubectl run hazelcast --image=hazelcast --port=5701" ascii
		$s5 = "COMPREPLY[$i]=${COMPREPLY[$i]#\"$colon_word\"}" ascii
		$s6 = "%*polymorphichelpers.HistoryViewerFunc" ascii
		$s7 = "ListenAndServeTLS" ascii
		$s8 = "DownwardAPI" ascii
		$s9 = "; plural=(n%10==1 && n%100!=11 ? 0 : n != 0 ? 1 : 2);proto:" ascii
		$s10 = "name: attack-" ascii

	condition:
		uint16(0)==0x457f and 9 of them
}