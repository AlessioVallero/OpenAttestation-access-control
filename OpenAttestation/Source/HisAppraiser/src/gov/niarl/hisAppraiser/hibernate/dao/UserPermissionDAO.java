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
import gov.niarl.hisAppraiser.hibernate.domain.UserPermissions;
import gov.niarl.hisAppraiser.hibernate.domain.PermissionType;
import gov.niarl.hisAppraiser.hibernate.util.HibernateUtilHis;
import java.lang.StringBuilder;
import gov.niarl.hisAppraiser.hibernate.util.ParNameContainer;

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

    public boolean doAuthorization( Long userId , String classValue , String operationValue , List<ParNameContainer> parnameValues )
    {
        boolean ret = false ;

        try
        {
            if( parnameValues != null && parnameValues.size() > 0 )
            {
                HibernateUtilHis.beginTransaction() ;

                Query query = HibernateUtilHis.getSession().createSQLQuery( "select pt.PAR_NAME , up.VALUE from USERS_PERMISSIONS up , PERMISSIONS_TYPES pt where up.ID_PERMISSIONS_TYPES = pt.ID and up.ID_USERS = :userid and pt.CLASS = :classvalue and pt.OPERATION = :operationvalue" ) ;
                query.setLong( "userid" , userId ) ;
                query.setString( "classvalue" , classValue ) ;
                query.setString( "operationvalue" , operationValue ) ;

                List list = query.list() ;

                // For each param, we search on the query result for the the corresponding row. If it does not exists, it's an error
                for( int i = 0 ; i < parnameValues.size() ; i++ )
                {
                    ParNameContainer pncToCheck = parnameValues.get( i ) ;

                    int j ;
                    for( j = 0 ; j < list.size() ; j++ )
                    {
                        Object[] rowValues = (Object[])list.get( j ) ;
                        String parNameName = (String)rowValues[0] ;
                        String parNameValue = (String)rowValues[1] ;

                        if( parNameName.equals( pncToCheck.getParNameName() ) )
                        {
                            ret = pncToCheck.getParNameValue().matches( parNameValue ) ;
                            // If the value is not valid, we can exit
                            if( !ret )
                            {
                                HibernateUtilHis.rollbackTransaction() ;
                                HibernateUtilHis.closeSession() ;
                                return ret ;
                            }

                            // The element is found, we can break the searching loop
                            break ;
                        }
                    }

                    // If j = list.size(), then we haven't found the corresponding row, so we exit with false
                    if( j == list.size() )
                    {
                        HibernateUtilHis.rollbackTransaction() ;
                        HibernateUtilHis.closeSession() ;
                        return ret ;
                    }
                }

                HibernateUtilHis.commitTransaction() ;
            }

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
