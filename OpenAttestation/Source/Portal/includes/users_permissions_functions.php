<?php
/*
Copyright (C) 2014 Politecnico di Torino, Italy
TORSEC group -- http://security.polito.it
*/

function GetUsersPermissionsValue( $username , $class , $operation , $parname )
{
    $user_regex = ".*" ;

    //QUERY DATABASE TO GET THE USERID
    $result_user_id = mysql_query( "SELECT u.ID FROM USERS u".
                           " where u.Username = '".$username."' and u.DELETED = 0" ) ;

    if( mysql_num_rows( $result_user_id ) )
    {
        $row_user_id = mysql_fetch_array( $result_user_id ) ;
        $user_id = $row_user_id['ID'] ;
        mysql_free_result( $result_user_id ) ;

        //QUERY DATABASE TO GET THE IS_ENFORCED OF READ_ATTEST
        $result_pt = mysql_query( "SELECT pt.ID , pt.IS_ENFORCED FROM PERMISSIONS_TYPES pt".
                               " where pt.CLASS = '".$class."' and pt.OPERATION = '".$operation."' and pt.PAR_NAME = '".$parname."'" ) ;
        if( mysql_num_rows( $result_pt ) )
        {
            $row_pt = mysql_fetch_array( $result_pt ) ;
            $is_enforced = $row_pt['IS_ENFORCED'] ;

            //IF IS_ENFORCED IS TRUE, WE HAVE TO SEARCH FOR THE REGEX VALUE
            if( $is_enforced == 1 )
            {
                $result_user_regex = mysql_query( "SELECT up.VALUE FROM USERS_PERMISSIONS up".
                                       " where up.ID_PERMISSIONS_TYPES = ".$row_pt['ID']." AND up.ID_USERS = ".$user_id ) ;

                if( mysql_num_rows( $result_user_regex ) )
                {
                    $row_user_regex = mysql_fetch_array( $result_user_regex ) ;
                    $user_regex = $row_user_regex['VALUE'] ;
                    mysql_free_result( $result_user_regex ) ;
                }
                else
                {
                    // ALWAYS UNMATCHABLE
                    $user_regex = "" ;
                }
            }
            mysql_free_result( $result_pt ) ;
        }
    }
    else
    {
        // ALWAYS UNMATCHABLE
        $user_regex = "" ;
    }

    return $user_regex ;
}
?>