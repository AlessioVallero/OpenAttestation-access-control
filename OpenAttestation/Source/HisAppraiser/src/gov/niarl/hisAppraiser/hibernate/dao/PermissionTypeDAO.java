/*
Copyright (C) 2014 Politecnico di Torino, Italy
TORSEC group -- http://security.polito.it
*/

package gov.niarl.hisAppraiser.hibernate.dao;

import java.util.ArrayList;
import java.util.List;
import java.util.Collections;
import org.hibernate.Query;
import org.hibernate.Session;
import gov.niarl.hisAppraiser.hibernate.domain.User;
import gov.niarl.hisAppraiser.hibernate.domain.PermissionType;
import gov.niarl.hisAppraiser.hibernate.util.HibernateUtilHis;
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

    public boolean getPermissionTypeEnforcement( String classValue , String operationValue , String parnameValue )
    {
        boolean ret = false ;

        try
        {
            HibernateUtilHis.beginTransaction() ;

            Query query = HibernateUtilHis.getSession().createQuery( "select pt.IsEnforced from PermissionType pt where pt.ClassValue = :classvalue and pt.Operation = :operationvalue and pt.ParName = :parnamevalue" ) ;
            query.setString( "classvalue" , classValue ) ;
            query.setString( "operationvalue" , operationValue ) ;
            query.setString( "parnamevalue" , parnameValue ) ;

            List list = query.list() ;
            if( list.size() > 0 )
            {
                // The IsEnforced value will be returned
                ret = ( (Boolean)list.get( 0 ) ).booleanValue() ;
            }

            HibernateUtilHis.commitTransaction() ;

            return ret ;
        }
        catch( Exception e )
        {
            HibernateUtilHis.rollbackTransaction() ;
            throw new RuntimeException( e ) ;
        }
        finally
        {
            HibernateUtilHis.closeSession() ;
        }
    }
}
