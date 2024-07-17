import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Goclr : FILE
{
	meta:
		description = "Detects binaries utilizing Go-CLR for hosting the CLR in a Go process and using it to execute a DLL from disk or an assembly from memory"
		author = "ditekSHen"
		id = "21766cad-17dd-525a-9ebe-cd90e892cff1"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L800-L814"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "a2a79793b1f530bcf9f79983f29a655f270cf0147606690b19eaeb82d4bd1f0d"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "github.com/ropnop/go-clr.(*IC" ascii
		$s2 = "EnumKeyExWRegEnumValueWRegOpenKeyExWRtlCopyMemoryRtlGetVersionShellExecuteWStartServiceW" ascii
		$c1 = "ICorRuntimeHost" ascii wide
		$c2 = "CLRCreateInstance" ascii wide
		$c3 = "ICLRRuntimeInfo" ascii wide
		$c4 = "ICLRMetaHost" ascii wide
		$go = "Go build ID:" ascii wide

	condition:
		uint16(0)==0x5a4d and all of ($s*) or (2 of ($c*) and $go)
}