<?php
/*
Copyright (C) 2014 Politecnico di Torino, Italy
TORSEC group -- http://security.polito.it
*/

//CONNECT TO DATABASE
include("includes/dbconnect.php");

//PROCESS PAGE INPUT URL PARAMETER
include("includes/pagenumber.php");

include("includes/users_permissions_functions.php");

$username = "" ;
$user_regex = ".*" ;

// If the login credentials are set
if( isset( $_SERVER['PHP_AUTH_USER'] ) && isset( $_SERVER['PHP_AUTH_PW'] ) )
{
    // Escaping special chars on the username to prevent SQL Injection attacks
    $username = mysql_real_escape_string( $_SERVER['PHP_AUTH_USER'] ) ;
    $user_regex = GetUsersPermissionsValue( $username , "Host" , "Read_Attest" , "Username" ) ;
}

//PROCESS SORT INPUT URL PARAMETER -- THESE MUST BE IN AGREEMENT WITH TABLE COLUMNS
switch($_GET["sort"])
{
case "hostnameasc":
$order = " ORDER BY ar.host_name ASC, ar.id DESC";
$sort = "sort=hostnameasc";
break;
case "hostnamedesc":
$order = " ORDER BY ar.host_name DESC, ar.id DESC";
$sort = "sort=hostnamedesc";
break;
case "requesttimeasc":
$order = " ORDER BY ar.request_time ASC, ar.id DESC";
$sort = "sort=requesttimeasc";
break;
case "requesttimedesc":
$order = " ORDER BY ar.request_time DESC, ar.id DESC";
$sort = "sort=requesttimedesc";
break;
case "reportasc":
$order = " ORDER BY ar.audit_log_id ASC, ar.id DESC";
$sort = "sort=reportasc";
break;
case "reportdesc":
$order = " ORDER BY ar.audit_log_id DESC, ar.id DESC";
$sort = "sort=reportdesc";
break;
case "requesthostasc":
$order = " ORDER BY ar.request_host ASC, ar.id DESC";
$sort = "sort=requesthostasc";
break;
case "requesthostdesc":
$order = " ORDER BY ar.request_host DESC, ar.id DESC";
$sort = "sort=requesthostdesc";
break;
case "validatetimeasc":
$order = " ORDER BY ar.validate_time ASC, ar.id DESC";
$sort = "sort=validatetimeasc";
break;
case "validatetimedesc":
$order = " ORDER BY ar.validate_time DESC, ar.id DESC";
$sort = "sort=validatetimedesc";
break;
case "userasc":
$order = " ORDER BY u.USERNAME ASC, ar.id DESC";
$sort = "sort=userasc";
break;
case "userdesc":
$order = " ORDER BY u.USERNAME DESC, ar.id DESC";
$sort = "sort=userdesc";
break;
case "attestrequestasc":
$order = " ORDER BY ar.id ASC";
$sort = "sort=attestrequestasc";
break;
case "attestrequestdesc":
default:
$order = " ORDER BY ar.id DESC";
$sort = "sort=attestrequestdesc";
break;
}
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html lang="en-US" xml:lang="en-US" xmlns="http://www.w3.org/1999/xhtml">
<head>
<?php
//INCLUDE STYLESHEETS
include("includes/styles.php");
?>
<title>HIS Reports</title>
</head>
<body>
<?php
//INCLUDE CLASSIFICATION MARKINGS
include("includes/classification.php");
?>
<div id="wrapper">
<?php
//INCLUDE THE HEADER
include("includes/header.php");

//INCLUDE THE NAVIGATION BAR
include("includes/navigation.php");
?>
<div id="content">
<div class="rightcol">
<h1>Attestation Requests</h1>
<?php
//NEED A COUNT OF TOTAL RECORDS FOR THE PAGINATION SCRIPT
$count = 0 ;
if( $username )
{
    $count = mysql_fetch_row(mysql_query("SELECT COUNT(id) FROM attest_request at , users u WHERE at.id_users=u.ID and u.USERNAME REGEXP BINARY '".$$user_regex."'"));
}
else
{
    $count = mysql_fetch_row(mysql_query("SELECT COUNT(id) FROM attest_request"));
}

//NEED A FILE LINK FOR THE PAGINATION SCRIPT
$link = "attestation_requests.php";

//INVOKE PAGINATION
include("includes/paginate.php");
?>
<table>
<?php
//DISPLAY TABLE HEADERS WITH SORT OPTIONS
echo "<tr>\n";
if($sort == "sort=attestrequestdesc") { echo "<th><a href=\"attestation_requests.php?" . $page . "&sort=attestrequestasc\">Attest Request <img src=\"images/fatcow/16/bullet_arrow_down.png\" alt=\"ascending icon\" /></a></th>";}
else { if($sort == "sort=attestrequestasc") { echo "<th><a href=\"attestation_requests.php?" . $page . "&sort=attestrequestdesc\">Attest Request <img src=\"images/fatcow/16/bullet_arrow_up.png\" alt=\"descending icon\" /></a></th>";}
else { echo "<th><a href=\"attestation_requests.php?" . $page . "&sort=attestrequestdesc\">Attest Request</a></th>";}}
if($sort == "sort=hostnamedesc") { echo "<th colspan=\"2\"><a href=\"attestation_requests.php?" . $page . "&sort=hostnameasc\">Host Name <img src=\"images/fatcow/16/bullet_arrow_down.png\" alt=\"ascending icon\" /></a></th>";}
else { if($sort == "sort=hostnameasc") { echo "<th colspan=\"2\"><a href=\"attestation_requests.php?" . $page . "&sort=hostnamedesc\">Host Name <img src=\"images/fatcow/16/bullet_arrow_up.png\" alt=\"descending icon\" /></a></th>";}
else { echo "<th colspan=\"2\"><a href=\"attestation_requests.php?" . $page . "&sort=hostnamedesc\">Host Name</a></th>";}}
if($sort == "sort=requesttimedesc") { echo "<th><a href=\"attestation_requests.php?" . $page . "&sort=requesttimeasc\">Request Time <img src=\"images/fatcow/16/bullet_arrow_down.png\" alt=\"ascending icon\" /></a></th>";}
else { if($sort == "sort=requesttimeasc") { echo "<th><a href=\"attestation_requests.php?" . $page . "&sort=requesttimedesc\">Request Time <img src=\"images/fatcow/16/bullet_arrow_up.png\" alt=\"descending icon\" /></a></th>";}
else { echo "<th><a href=\"attestation_requests.php?" . $page . "&sort=requesttimedesc\">Request Time</a></th>";}}
if($sort == "sort=reportdesc") { echo "<th colspan=\"2\"><a href=\"attestation_requests.php?" . $page . "&sort=reportasc\">Report <img src=\"images/fatcow/16/bullet_arrow_down.png\" alt=\"ascending icon\" /></a></th>";}
else { if($sort == "sort=reportasc") { echo "<th colspan=\"2\"><a href=\"attestation_requests.php?" . $page . "&sort=reportdesc\">Report <img src=\"images/fatcow/16/bullet_arrow_up.png\" alt=\"descending icon\" /></a></th>";}
else { echo "<th colspan=\"2\"><a href=\"attestation_requests.php?" . $page . "&sort=reportdesc\">Report</a></th>";}}
if($sort == "sort=requesthostdesc") { echo "<th><a href=\"attestation_requests.php?" . $page . "&sort=requesthostasc\">Request Host <img src=\"images/fatcow/16/bullet_arrow_down.png\" alt=\"ascending icon\" /></a></th>";}
else { if($sort == "sort=requesthostasc") { echo "<th><a href=\"attestation_requests.php?" . $page . "&sort=requesthostdesc\">Request Host <img src=\"images/fatcow/16/bullet_arrow_up.png\" alt=\"descending icon\" /></a></th>";}
else { echo "<th><a href=\"attestation_requests.php?" . $page . "&sort=requesthostdesc\">Request Host</a></th>";}}
echo "<th>Count </th>" ;
if($sort == "sort=validatetimedesc") { echo "<th><a href=\"attestation_requests.php?" . $page . "&sort=validatetimeasc\">Validate Time <img src=\"images/fatcow/16/bullet_arrow_down.png\" alt=\"ascending icon\" /></a></th>";}
else { if($sort == "sort=validatetimeasc") { echo "<th><a href=\"attestation_requests.php?" . $page . "&sort=validatetimedesc\">Validate Time <img src=\"images/fatcow/16/bullet_arrow_up.png\" alt=\"descending icon\" /></a></th>";}
else { echo "<th><a href=\"attestation_requests.php?" . $page . "&sort=validatetimedesc\">Validate Time</a></th>";}}
if($sort == "sort=userdesc") { echo "<th colspan=\"2\"><a href=\"attestation_requests.php?" . $page . "&sort=userasc\">User <img src=\"images/fatcow/16/bullet_arrow_down.png\" alt=\"ascending icon\" /></a></th>";}
else { if($sort == "sort=userasc") { echo "<th colspan=\"2\"><a href=\"attestation_requests.php?" . $page . "&sort=userdesc\">User <img src=\"images/fatcow/16/bullet_arrow_up.png\" alt=\"descending icon\" /></a></th>";}
else { echo "<th colspan=\"2\"><a href=\"attestation_requests.php?" . $page . "&sort=userdesc\">User</a></th>";}}
echo "</tr>\n";

//QUERY DATABASE FOR TABLE CONTENTS
$result = mysql_query("SELECT ar.id, ar.host_name, ar.request_time, ar.audit_log_id, ar.request_host, ar.count , ar.validate_time , u.USERNAME FROM attest_request ar , USERS u WHERE ar.id_users = u.ID AND u.USERNAME REGEXP BINARY '".$user_regex."' ". $order . " LIMIT " . (($limit - 1) * 100) . ",100");

//DISPLAY QUERY RESULTS IN TABLE
if(!mysql_num_rows($result))
{
echo "<tr><td colspan=\"14\">No Results</td></tr>";
}
else
{
while($row = mysql_fetch_array($result))
{
echo "<tr>
<td>" . $row["id"] . "</td>
<td><a href=\"machine.php?name=" . $row["host_name"] . "\"><img src=\"images/fatcow/16/terminal.png\" /></a></td>
<td>" . $row["host_name"] . "</td>
<td>" . $row["request_time"] . "</td>
<td><a href=\"reports.php?filter=single&id_single=" . $row["audit_log_id"] . "\"><img src=\"images/fatcow/16/zoom.png\" /></a></td>
<td>" . $row["audit_log_id"] . "</td>
<td>" . $row["request_host"] . "</td>
<td>" . $row["count"] . "</td>
<td>" . $row["validate_time"] . "</td>
<td><a href=\"user.php?name=" . $row["USERNAME"] . "\"><img src=\"images/fatcow/16/user.png\" /></a></td>
<td>" . $row["USERNAME"] . "</td>
</tr>\n";
}
}
?>
</table>
</div>
</div>
<?php
//INCLUDE THE FOOTER
include("includes/footer.php");
?>
</div>
</body>
</html>
<?php
//CLOSE DATABASE CONNECTION
include("includes/dbclose.php");
?>
