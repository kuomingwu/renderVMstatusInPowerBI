<#######Create by Mo Wu#######>
function getRegion(){
    param(
        [String] $location
    )

    $region = (ConvertFrom-Json –InputObject '[{"id":"1","RegionID":"1","name":"North Central US","location_name":"northcentralus","lat":"41.8819","lng":"-87.6278","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"4","RegionID":"4","name":"Southeast Asia","location_name":"southeastasia","lat":"1.283","lng":"103.833","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"7","RegionID":"8","name":"East US","location_name":"eastus","lat":"37.3719","lng":"-79.8164","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"10","RegionID":"14","name":"Japan West","location_name":"japanwest","lat":"34.6939","lng":"135.502","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"13","RegionID":"18","name":"Central US","location_name":"centralus","lat":"41.5908","lng":"-93.6208","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"16","RegionID":"24","name":"Central India","location_name":"centralindia","lat":"18.5822","lng":"73.9197","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"19","RegionID":"27","name":"Canada Central","location_name":"canadacentral","lat":"43.653","lng":"-79.383","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"22","RegionID":"30","name":"West Central US","location_name":"westcentralus","lat":"40.89","lng":"-110.234","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"2","RegionID":"2","name":"South Central US","location_name":"southcentralus","lat":"29.4167","lng":"-98.5","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"5","RegionID":"6","name":"West Europe","location_name":"westeurope","lat":"52.3667","lng":"4.9","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"8","RegionID":"9","name":"West US","location_name":"westus","lat":"37.783","lng":"-122.417","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"11","RegionID":"15","name":"Brazil South","location_name":"brazilsouth","lat":"-23.55","lng":"-46.633","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"14","RegionID":"19","name":"Australia East","location_name":"australiaeast","lat":"-33.86","lng":"151.209","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"17","RegionID":"25","name":"South India","location_name":"southindia","lat":"12.9822","lng":"80.1636","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"20","RegionID":"28","name":"Canada East","location_name":"canadaeast","lat":"46.817","lng":"-71.217","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"23","RegionID":"33","name":"UK South","location_name":"uksouth","lat":"50.941","lng":"-0.799","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"3","RegionID":"3","name":"North Europe","location_name":"northeurope","lat":"53.3478","lng":"-6.2597","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"6","RegionID":"7","name":"East Asia","location_name":"eastasia","lat":"22.267","lng":"114.188","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"9","RegionID":"13","name":"Japan East","location_name":"japaneast","lat":"35.68","lng":"139.77","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"12","RegionID":"17","name":"East US 2","location_name":"eastus2","lat":"36.6681","lng":"-78.3889","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"15","RegionID":"20","name":"Australia Southeast","location_name":"australiasoutheast","lat":"-37.8136","lng":"144.963","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"18","RegionID":"26","name":"West India","location_name":"westindia","lat":"19.088","lng":"72.868","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"21","RegionID":"29","name":"West US 2","location_name":"westus2","lat":"47.233","lng":"-119.852","dtype":"normal","timestamp":"1499099464","status":"Green"},{"id":"24","RegionID":"34","name":"UK West","location_name":"ukwest","lat":"53.427","lng":"-3.084","dtype":"normal","timestamp":"1499099464","status":"Green"}]') | Where-Object {$_.location_name -eq $location}


    return $region

}


function postData(){
    param(
        [String] $enpoint,
        [String] $method,
        [Object] $Headers
    )
    return Invoke-RestMethod -Uri $enpoint -Headers $Headers -ContentType "application/json" -Method $method
}
function getVMInfoFromId(){
    param(
        [String] $resourceId
    )

    $r =  $resourceId.Split("/")
    return @{
        'subscription'= $r[2]
        'resourceGroup'= $r[4]
        'vmname' = $r[8]
    }

}

<######SAStoken Class by Mo######>

class moModuleSastoken{
    [String] $uri
    [String] $sasKeyName
    [String] $sasKeyValue


    [String] sha256withHMAC($message , $secret){
    
        $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
        $hmacsha.key = [Text.Encoding]::ASCII.GetBytes($secret)
        $signature = $hmacsha.ComputeHash([Text.Encoding]::ASCII.GetBytes($message))
        $signature = [Convert]::ToBase64String($signature)   
    
        return  $signature
    
    
    }

    [String] encodeBase64($Text){
    
        $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
        $EncodedText =[Convert]::ToBase64String($Bytes)
        return $EncodedText
    
    
    }


    [String] createSAStokenBySha256(){
    
        

        $targetUri = ([uri]::EscapeDataString($this.uri.ToLower())).ToLower();

        $expires = [int][double]::Parse((Get-Date -UFormat %s)) ;      

        $expiresInMins = 60; 
        $week = 60*60*24*7;
        $expires = $expires + $week; 
        $toSign = $targetUri+"`n"+$expires; 

        $signature = [uri]::EscapeDataString($this.sha256withHMAC($toSign , $this.sasKeyValue)) ; 


        $token = "SharedAccessSignature sr="+$targetUri+"&sig="+$signature+"&se="+$expires+"&skn="+$this.sasKeyName; 


        return $token
    
    }

    moModuleSastoken([String]$uri , [String]$sasKeyName , [String]$sasKeyValue){
        $this.uri = $uri
        $this.sasKeyName = $sasKeyName
        $this.sasKeyValue = $sasKeyValue
        
    }


}


#get token
$TENANTID="***************************"
$APPID="***************************"
$PASSWORD="***************************" #key
$_username = "***************************"
$_password = "***************************"
##$result=Invoke-RestMethod -Uri https://login.microsoftonline.com/$TENANTID/oauth2/token?api-version=1.0 -Method Post -Body @{"grant_type" = "client_credentials"; "resource" = "https://management.core.windows.net/"; "client_id" = "$APPID"; "client_secret" = "$PASSWORD" ; }
$result=Invoke-RestMethod -Uri https://login.microsoftonline.com/$TENANTID/oauth2/token?api-version=1.0 -Method Post -Body @{"grant_type" = "password"; "resource" = "https://management.core.windows.net/"; "client_id" = "$APPID"; "client_secret" = "$PASSWORD" ; "username"="$_username" ; "password"="$_password"}





$token=$result.access_token

##set Header
$Headers=@{
    'authorization'="Bearer $token"
    'host'="management.azure.com"
}
$endpoint = @{
    'getAllSubscription' = "https://management.azure.com/subscriptions?api-version=2016-06-01"
    
}

##start...get all subscirption

$allSub = postData -enpoint $endpoint.getAllSubscription -method GET -Headers $Headers


$postEventHubData = @()

For($i = 0 ; $i -lt $allSub.value.Length ; $i++){

    $sub = $allSub.value[$i];
    $subId = $sub.subscriptionId
    ##get all RG from sub...
    
    $listSubEndpoint = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Compute/virtualmachines?api-version=2016-04-30-preview"
    $VMs = postData -enpoint $listSubEndpoint -method GET -Headers $Headers
    ##$debug_vm = $VMs.value
    For($j = 0 ; $j -lt $VMs.value.length ; $j++){
        $vm = $VMs.value[$j]
        
        $resourceInfo = getVMInfoFromId -resourceId $vm.id
        $s = $resourceInfo.subscription
        $v = $resourceInfo.vmname
        $rg = $resourceInfo.resourceGroup
        $location = getRegion -location $vm.location
        ##get vm detail info
        $vmDetailEndpoint = "https://management.azure.com/subscriptions/$s/resourceGroups/$rg/providers/Microsoft.Compute/virtualMachines/$v/InstanceView?api-version=2016-04-30-preview"
    
        $VMdetail = postData -enpoint $vmDetailEndpoint -method GET -Headers $Headers
        $VMdetail
        $code = $VMdetail.statuses[1].code
        $displayStatus = $VMdetail.statuses[1].displayStatus
        
        <##
        {
            resourceName : [
                {
                    code
                    displayStatus
                    vmname
                    rg
                
                }
                
            ]
        
        }
        ##>
        $vmstatus = @{
            "code"=$code
            "displayStatus" = $displayStatus
            "vmname" = $v
            "rg" = $rg
            "lat" = $location.lat
            "lng" = $location.lng
            "location" = $location.location_name
        }
        $vmstatus
        $postEventHubData += $vmstatus
       
        
    
    }



}



###############post data to event hub#############

#sastoken


$uri="https://moautoeventhub.servicebus.windows.net/moautodemo/messages" #example
$sasKeyName = "**************"
$sasKeyValue = "**************"
$mo = [moModuleSastoken]::new($uri , $sasKeyName , $sasKeyValue);
$SAStoken = $mo.createSAStokenBySha256();

Write-Output $SAStoken


#eventhub
$eventhubNameSpace = "moautoeventhub"
$eventhub = "moautodemo"
$eventhubEndpoint = "https://$eventhubNameSpace.servicebus.windows.net/$eventhub/messages"
$eventHeader = @{
    'Authorization'=$SAStoken

}

$postEventHubData_json = $postEventHubData | ConvertTo-Json

$eventPost = Invoke-RestMethod -Uri "https://moautoeventhub.servicebus.windows.net/moautodemo/messages" -Headers $eventHeader -Method Post -Body $postEventHubData_json
$eventPost