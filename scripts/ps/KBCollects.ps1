
function Escape-JSONString($str)
{
    if ($str -eq $null)
    {
        return ""
    }
    $str = $str.ToString().Replace('"', '\"').Replace('\', '\\').Replace("`n", '\n').Replace("`r", '\r').Replace("`t", '\t')
    return $str;
}
function ConvertTo-JSON($maxDepth = 1, $forceArray = $false)
{
    begin {
        $data = @()
    }
    process{
        $data += $_
    }

    end{

        if ($data.length -eq 1 -and $forceArray -eq $false)
        {
            $value = $data[0]
        }
        else
        {
            $value = $data
        }

        if ($value -eq $null)
        {
            return "null"
        }



        $dataType = $value.GetType().Name

        switch -regex ($dataType)
        {
            'String'  {
                return  "`"{0}`"" -f (Escape-JSONString $value)
            }
            '(System\.)?DateTime'  {
                return  "`"{0:yyyy-MM-dd}T{0:HH:mm:ss}`"" -f $value
            }
            'Int32|Double' {
                return  "$value"
            }
            'Boolean' {
                return  "$value".ToLower()
            }
            '(System\.)?Object\[\]' {
                # array

                if ($maxDepth -le 0)
                {
                    return "`"$value`""
                }

                $jsonResult = ''
                foreach ($elem in $value)
                {
                    #if ($elem -eq $null) {continue}
                    if ($jsonResult.Length -gt 0)
                    {
                        $jsonResult += ', '
                    }
                    $jsonResult += ($elem | ConvertTo-JSON -maxDepth ($maxDepth - 1))
                }
                return "[" + $jsonResult + "]"
            }
            '(System\.)?Hashtable' {
                # hashtable
                $jsonResult = ''
                foreach ($key in $value.Keys)
                {
                    if ($jsonResult.Length -gt 0)
                    {
                        $jsonResult += ', '
                    }
                    $jsonResult +=
                    @"
    "{0}": {1}
"@ -f $key, ($value[$key] | ConvertTo-JSON -maxDepth ($maxDepth - 1))
                }
                return "{" + $jsonResult + "}"
            }
            default {
                #object
                if ($maxDepth -le 0)
                {
                    return  "`"{0}`"" -f (Escape-JSONString $value)
                }

                return "{" +
                        (($value | Get-Member -MemberType *property | % {
                            @"
    "{0}": {1}
"@ -f $_.Name, ($value.($_.Name) | ConvertTo-JSON -maxDepth ($maxDepth - 1))

                        }) -join ', ') + "}"
            }
        }
    }
}


function Get-CollectKB(){
    # 1. 搜集所有的KB补丁
    $KBArray = @()
    $KBArray = Get-HotFix|ForEach-Object {$_.HotFixId}
    return $KBArray
}
function Get-BasicInfo(){


    $basicInfo = @{}
    $basicInfo.windowsProductName = (Get-WmiObject -class Win32_OperatingSystem).Caption
    $basicInfo.windowsVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId

    return $basicInfo
    
}
$basicInfo = Get-BasicInfo
$KBList = Get-CollectKB
$basicInfo.KBList = $KBList
$basicInfo | ConvertTo-JSON


