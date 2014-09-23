/*
Copyright (C) 2014 Politecnico di Torino, Italy
TORSEC group -- http://security.polito.it
*/

package gov.niarl.hisAppraiser.hibernate.dao;

import java.util.ArrayList;
import java.util.List;
import java.util.Collections;
import java.lang.StringBuilder;
import org.hibernate.Query;
import org.hibernate.Session;
import gov.niarl.hisAppraiser.hibernate.domain.User;
import gov.niarl.hisAppraiser.hibernate.util.HibernateUtilHis;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class serves as a central location for updates and queries against 
 * the USERS table
 * @author intel
 * @version OpenAttestation
 *
 */
public class UserDAO
{
    /**
     * Constructor to start a hibernate transaction in case one has not
     * already been started 
     */
    public UserDAO()
    {
    }

    public Long getAuthenticatedUserId( String username , String password )
    {
        Long ret = -1L ;
        try
        {
            HibernateUtilHis.beginTransaction() ;
            Query query = HibernateUtilHis.getSession().createQuery( "select u.ID from User u where u.Username = :username and u.Password = :password and u.Deleted = 0" ) ;
            query.setString( "username" , username ) ;
            query.setString( "password" , password ) ;

            List list = query.list() ;
            if( list.size() > 0 )
            {
                // The ID of the User will be returned
                ret = (Long)list.get( 0 ) ;
            }

            HibernateUtilHis.commitTransaction() ;
            return ret ;
        }
        catch( Exception e )
        {
            HibernateUtilHis.rollbackTransaction() ;
            e.printStackTrace() ;
            throw new RuntimeException( e ) ;
        }
        finally
        {
            HibernateUtilHis.closeSession() ;
        }
    }
}
