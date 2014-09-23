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
import com.intel.openAttestation.manifest.hibernate.domain.PermissionType;
import com.intel.openAttestation.manifest.hibernate.util.HibernateUtilHis;
import java.lang.StringBuilder;

/**
 * This class serves as a central location for updates and queries against 
 * the PERMISSIONS_TYPES tables
 * @author intel
 * @version OpenAttestation
 *
 */
public class PermissionTypeDAO
{
    /**
     * Constructor to start a hibernate transaction in case one has not
     * already been started 
     */
    public PermissionTypeDAO()
    {
    }

    public void editPermissionTypeEntry( PermissionType permissionType )
    {
        try
        {
            HibernateUtilHis.beginTransaction() ;
            Session session = HibernateUtilHis.getSession() ;

            Query query = session.createQuery( "from PermissionType pt where pt.ClassValue = :classValue and pt.Operation = :operationValue and pt.ParName = :parnameValue" ) ;
            query.setString( "classValue" , permissionType.getClassValue() ) ;
            query.setString( "operationValue" , permissionType.getOperation() ) ;
            query.setString( "parnameValue" , permissionType.getParName() ) ;
            List list = query.list() ;
            if( list.size() < 1 )
            {
                HibernateUtilHis.rollbackTransaction() ;
                throw new Exception( "Object not found" ) ;
            }
            PermissionType permissionTypeOld = (PermissionType)list.get( 0 ) ;
            // Set the new IsEnforced
            permissionTypeOld.setIsEnforced( permissionType.getIsEnforced() ) ;

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

    public boolean permissionTypeExists( PermissionType permissionType )
    {
        return permissionTypeExists( permissionType.getClassValue() , permissionType.getOperation() , permissionType.getParName() ) ;
    }

    public boolean permissionTypeExists( String classValue , String operationValue , String parnameValue )
    {
        boolean flag = false ;
        try
        {
            HibernateUtilHis.beginTransaction() ;

            Query query = HibernateUtilHis.getSession().createQuery( "from PermissionType pt where pt.ClassValue = :classValue and pt.Operation = :operationValue and pt.ParName = :parnameValue" ) ;
            query.setString( "classValue" , classValue ) ;
            query.setString( "operationValue" , operationValue ) ;
            query.setString( "parnameValue" , parnameValue ) ;

            List list = query.list() ;

            // If the permission type was found, the return value is true, false otherwise
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
