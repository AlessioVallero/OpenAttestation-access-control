/*
Copyright (C) 2014 Politecnico di Torino, Italy
TORSEC group -- http://security.polito.it
*/

package com.intel.openAttestation.manifest.hibernate.dao;

import java.util.ArrayList;
import java.util.List;
import java.util.Collections;
import java.lang.StringBuilder;
import org.hibernate.Query;
import org.hibernate.Session;
import com.intel.openAttestation.manifest.hibernate.domain.User;
import com.intel.openAttestation.manifest.hibernate.util.HibernateUtilHis;
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

    public void addUserEntry( User UserEntry )
    {
        try
        {
            HibernateUtilHis.beginTransaction() ;
            Session session = HibernateUtilHis.getSession() ;
            // Insert of the new User
            UserEntry.setDeleted( false ) ;
            session.save( UserEntry ) ;
            HibernateUtilHis.commitTransaction() ;
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

    public void editUserEntry( User userEntry )
    {
        try
        {
            HibernateUtilHis.beginTransaction() ;
            Session session = HibernateUtilHis.getSession() ;

            Query query = session.createQuery( "from User u where u.Username = :username and u.Deleted = 0" ) ;
            query.setString( "username" , userEntry.getUsername() ) ;
            List list = query.list() ;
            if( list.size() < 1 )
            {
                HibernateUtilHis.rollbackTransaction() ;
                throw new Exception( "Object not found" ) ;
            }
            User userOld = (User)list.get( 0 ) ;
            // Set the new password
            userOld.setPassword( userEntry.getPassword() ) ;

            HibernateUtilHis.commitTransaction() ;
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

    public void deleteUserEntry( String Username )
    {
        try
        {
            HibernateUtilHis.beginTransaction() ;
            Session session = HibernateUtilHis.getSession() ;

            Query query = session.createQuery( "from User u where u.Username = :username and u.Deleted = 0" ) ;
            query.setString( "username" , Username ) ;
            List list = query.list() ;
            if( list.size() < 1 )
            {
                HibernateUtilHis.rollbackTransaction() ;
                throw new Exception( "Object not found" ) ;
            }
            User userOld = (User)list.get( 0 ) ;
            // Set Deleted to true
            userOld.setDeleted( true ) ;

            HibernateUtilHis.commitTransaction() ;
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

    public boolean isUserExisted( String Username )
    {
        boolean flag = false ;
        try
        {
            HibernateUtilHis.beginTransaction() ;
            Query query = HibernateUtilHis.getSession().createQuery( "from User u where u.Username = :value and u.Deleted = 0" ) ;
            query.setString( "value" , Username ) ;
            List list = query.list() ;

            // If the User was found, the return value is true, false otherwise
            if( list.size() < 1 )
            {
                flag =  false ;
            }
            else
            {
                flag = true ;
            }

            HibernateUtilHis.commitTransaction() ;
            return flag ;
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
