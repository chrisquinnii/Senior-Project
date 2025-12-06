$eip = New-EC2Address -Domain vpc
$eipAllocationId = $eip.AllocationId
Write-host "Created Elastic IP Address"

$default_subnet = "<subnet-idnumber goes here>"
$subnetId = Read-Host -Prompt "Enter the subnet ID the NAT Gateway goes in (MUST BE A PUBLIC SUBNET :D)"
if (-not $subnetid) {$subnetid = $default_subnet}

$natGateway = New-EC2NatGateway -SubnetId $subnetId -AllocationId $eipAllocationId
$natGatewayId = $natGateway.NatGateway.NatGatewayId

Write-Host "Creating NAT Gateway"
do {
Start-Sleep -Seconds 10
$status = (Get-EC2NatGateway -NatGatewayId $natGateway.NatGateway.NatGatewayId).State
Write-Host "Current status: $status"
} while ($status -ne "available")

Write-Host "NAT Gateway Available:" 
Write-Host $natGateway.NatGateway.NatGatewayId

$routeTableId = "rtb-idnumber" #Route Table that is associated with the devices that need to access the internet
New-EC2Route -RouteTableId $routeTableId -DestinationCidrBlock "0.0.0.0/0" -NatGatewayId $natGateway.NatGateway.NatGatewayId
Write-Host "Created Route Table entry for NAT Gateway"

$cleanup = Read-Host "When you are ready to delete these resources, please type DELETE"
if ($cleanup -eq "DELETE"){
    Write-host "Deleting Nat Gateway..."
    Remove-EC2NatGateway -NatGatewayId $natGateway.NatGateway.NatGatewayId -Force

    Write-host "Releasing Elastic IP...(Waiting on NAT Gateway Destruction)"
    Start-Sleep -Seconds 140
    Remove-EC2Address -AllocationId $eip.AllocationId -Force

    Write-host "Removing Route Table Entry..."
    Remove-EC2Route -RouteTableId $routeTableId -DestinationCidrBlock "0.0.0.0/0" -ProfileName "default"

    Write-Host "Resources deleted successfully."
} else {
    Write-Host "Resources left running. Delete them manually later please."
}
