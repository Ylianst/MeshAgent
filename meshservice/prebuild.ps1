#Write-Host "Input: $($args[0]) Output: $($args[1])"

#
# Read ILibDuktape_Commit.h into file_data
#
$file_data = Get-Content $($args[0]);

$hash = $null;
$hashdate = $null;
$current = $null;
$updated = $null;

#
# Parse out the GIT Commit Hash and GIT Commit Date, so we can update the resource
#
$tokens = $file_data -split '`n';
for($a=0;$a -lt $tokens.length;++$a)
{
   if($tokens[$a].IndexOf('SOURCE_COMMIT_HASH') -gt 0)
   {
      $hash_tok = $tokens[$a] -split '"';
      $hash = $hash_tok[1];
   }
   if($tokens[$a].IndexOf('SOURCE_COMMIT_DATE') -gt 0)
   {
      $hash_tok = $tokens[$a] -split '"';
      $hashdate = $hash_tok[1];
   }
}

#
# Parse the resource file
#
$rc_data = Get-Content $($args[1]);
$i = $rc_data -split '`n';

for($x=0;$x -lt $i.length;++$x)
{
   $z = $i[$x] -split '"';
   if($z[1] -eq "ProductVersion")
   {
      #
	  # Update the ProductVersion
	  #
      $current = $z[3];
      $z[3] = "Commit: " +  $hash;
	  $updated = $z[3];
   }
   if($z[1] -eq "FileVersion")
   {
      #
	  # Update File Version
	  #
      $z[3] = $hashdate;
   }
   $i[$x] = $z -Join '"';
}


#
# Only update MeshService.rc if the values were actually updated
#
if($current -ne $updated)
{
   Write-Host "Updated MeshService.rc";
   $result = $i -Join [Environment]::NewLine
   $result > $($args[1]);
}
else
{
   Write-Host "MeshService.rc is already up to date";
}







