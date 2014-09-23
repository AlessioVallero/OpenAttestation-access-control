/*
Copyright (C) 2014 Politecnico di Torino, Italy
TORSEC group -- http://security.polito.it
*/

package com.intel.openAttestation.manifest.hibernate.dao;

import java.util.ArrayList;
import java.util.List;
import java.util.Collections;
import org.hibernate.Query;
import org.hibernate.Session;
import com.intel.openAttestation.manifest.hibernate.domain.User;
import com.intel.openAttestation.manifest.hibernate.domain.UserPermissions;
import com.intel.openAttestation.manifest.hibernate.domain.PermissionType;
import com.intel.openAttestation.manifest.hibernate.util.HibernateUtilHis;
import java.lang.StringBuilder;

/**
 * This class serves as a central location for updates and queries against 
 * the USERS - PERMISSIONS_TYPES - USERS_PERMISSIONS tables
 * @author intel
 * @version OpenAttestation
 *
 */
public class UserPermissionDAO
{
    /**
     * Constructor to start a hibernate transaction in case one has not
     * already been started 
     */
    public UserPermissionDAO()
    {
    }

    public void addUserPermissionEntry( Long userID , Long permissionTypeID , String value )
    {
        try
        {
            HibernateUtilHis.beginTransaction() ;
            Session session = HibernateUtilHis.getSession() ;

            // Insert the User Permission
            UserPermissions userpermissions = new UserPermissions() ;
            userpermissions.setIDUsers( userID ) ;
            userpermissions.setIDPermissionsTypes( permissionTypeID ) ;
            userpermissions.setValue( value ) ;
            session.save( userpermissions ) ;

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

    public void editUserPermissionEntry( Long userID , Long permissionTypeID , String value )
    {
        try
        {
            HibernateUtilHis.beginTransaction() ;
            Session session = HibernateUtilHis.getSession() ;
            // Delete old related permissions
            Query query = session.createQuery( "from UserPermissions up where up.IDUsers = :idusers and up.IDPermissionsTypes = :permissionTypeID" ) ;
            query.setLong( "idusers" , userID ) ;
            query.setLong( "permissionTypeID" , permissionTypeID ) ;
            List list = query.list() ;
            // Searching for the User
            if( list.size() < 1 )
            {
                HibernateUtilHis.rollbackTransaction() ;
                throw new Exception( "Object not found" ) ;
            }

            UserPermissions userpermissions = (UserPermissions)list.get( 0 ) ;
            userpermissions.setValue( value ) ;

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

    public void deleteUserPermissionEntry( Long userID , Long permissionTypeID )
    {
        try
        {
            HibernateUtilHis.beginTransaction() ;
            Session session = HibernateUtilHis.getSession() ;
            // Delete old related permissions
            Query query = session.createQuery( "from UserPermissions up where up.IDUsers = :idusers and up.IDPermissionsTypes = :permissionTypeID" ) ;
            query.setLong( "idusers" , userID ) ;
            query.setLong( "permissionTypeID" , permissionTypeID ) ;
            List list = query.list() ;
            if( list.size() < 1 )
            {
                HibernateUtilHis.rollbackTransaction() ;
                throw new Exception( "Object not found" ) ;
            }
            UserPermissions UserPermissionsEntry = (UserPermissions)list.get( 0 ) ;
            // Delete the UserPermissions from DB
            session.delete( UserPermissionsEntry ) ;

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

    // Return a User's ID from a User's Username
    public Long getUserIDFromUsername( String Username )
    {
        Long ret = -1L ;

        try
        {
            HibernateUtilHis.beginTransaction() ;
            Query query = HibernateUtilHis.getSession().createQuery( "select u.ID from User u where u.Username = :value and u.Deleted = 0" ) ;
            query.setString( "value" , Username ) ;
            List list = query.list() ;

            if( list.size() > 0 )
            {
                ret = (Long)list.get( 0 ) ;
                HibernateUtilHis.commitTransaction() ;
            }
            else
            {
                HibernateUtilHis.rollbackTransaction() ;
                HibernateUtilHis.closeSession() ;
            }

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

    // Return a PermissionType's ID from all PermissionType's data
    public Long getPermissionTypeIDFromPermissionTypeData( String classpar , String operation , String parName )
    {
        Long ret = -1L ;

        try
        {
            HibernateUtilHis.beginTransaction() ;
            Query query = HibernateUtilHis.getSession().createQuery( "select pt.ID from PermissionType pt where pt.ClassValue = :class and pt.Operation = :operation and pt.ParName = :parName" ) ;
            query.setString( "class" , classpar ) ;
            query.setString( "operation" , operation ) ;
            query.setString( "parName" , parName ) ;

            List list = query.list() ;

            if( list.size() > 0 )
            {
                ret = (Long)list.get( 0 ) ;
                HibernateUtilHis.commitTransaction() ;
            }
            else
            {
                HibernateUtilHis.rollbackTransaction() ;
                HibernateUtilHis.closeSession() ;
            }

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

    public boolean userPermissionsExists( Long userID , Long permissionTypeID )
    {
        boolean flag = false ;
        try
        {
            HibernateUtilHis.beginTransaction() ;

            Query query = HibernateUtilHis.getSession().createQuery( "from UserPermissions up where up.IDUsers = :iduser and up.IDPermissionsTypes = :idpermissiontype" ) ;
            query.setLong( "iduser" , userID ) ;
            query.setLong( "idpermissiontype" , permissionTypeID ) ;

            List list = query.list() ;

            // If a User's permission was found, the return value is true, false otherwise
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
