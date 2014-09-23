/*
Copyright (C) 2014 Politecnico di Torino, Italy
TORSEC group -- http://security.polito.it
*/

package com.intel.openAttestation.manifest.resource;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.hibernate.Session;
import gov.niarl.hisAppraiser.util.HisUtil;
import gov.niarl.hisAppraiser.hibernate.util.AttestUtil;
import gov.niarl.hisAppraiser.hibernate.util.AttestService;

import com.intel.openAttestation.manifest.bean.OpenAttestationResponseFault;
import com.intel.openAttestation.manifest.hibernate.dao.PermissionTypeDAO;
import com.intel.openAttestation.manifest.hibernate.domain.PermissionType;

import java.util.List;

/**
 * RESTful web service interface to work with OEM DB.
 * @author xmei1
 *
 */

@Path("resources/permissions_types")
public class PermissionTypeResource
{
    @PUT
    @Consumes("application/json")
    @Produces("application/json")
    public Response editUserPermission( @Context UriInfo uriInfo , PermissionType permissionType, @Context javax.servlet.http.HttpServletRequest request )
    {
        UriBuilder b = uriInfo.getBaseUriBuilder() ;
        b = b.path( PermissionTypeResource.class ) ;
        Response.Status status = Response.Status.OK ;
        boolean isValidKey = true ;
        AttestUtil.loadProp() ;
        try
        {
            PermissionTypeDAO dao = new PermissionTypeDAO() ;

            HashMap parameters = new HashMap() ;

            // If there isn't Class on the input request, it's an error
            if( permissionType.getClassValue() != null )
            {
                parameters.put( permissionType.getClassValue() , 100 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            // If there isn't Operation on the input request, it's an error
            if( permissionType.getOperation() != null )
            {
                parameters.put( permissionType.getOperation() , 100 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            // If there isn't ParName on the input request, it's an error
            if( permissionType.getParName() != null )
            {
                parameters.put( permissionType.getParName() , 100 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            // If there aren't Values on the input request, it's an error
            if( !isValidKey ||
                permissionType.getClassValue().length() < 1 ||
                permissionType.getOperation().length() < 1 ||
                permissionType.getParName().length() < 1 ||
                !HisUtil.validParas( parameters ) )
            {
                status = Response.Status.INTERNAL_SERVER_ERROR ;
                OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                        OpenAttestationResponseFault.FaultCode.FAULT_500 ) ;
                fault.setError_message( "Edit PermissionType entry failed, please check the length for each parameters" +
                        " and remove all of the unwanted characters belonged to [# & + : \" \']" ) ;
                return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                        .build() ;
            }

            // Authentication
            Long userId = AttestService.ISV_Autherntication_module( request ) ;

            // Read from .properties if we can edit the permission types
            if( AttestUtil.getEditPermissionTypeEnabled() )
            {
                // The permission type must exists
                if( dao.permissionTypeExists( permissionType ) )
                {
                    // Insert the entry related to this permission type
                    dao.editPermissionTypeEntry( permissionType ) ;
                    return Response.status( status ).header( "Location" , b.build() ).type( MediaType.TEXT_PLAIN ).entity( "True" )
                            .build() ;
                }
                else
                {
                    status = Response.Status.BAD_REQUEST ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_1006 ) ;
                    fault.setError_message( "Data Error - This permission does not exists on the database" ) ;        
                    return Response.status( status ).entity( fault ).build() ;
                }
            }
            else
            {
                status = Response.Status.FORBIDDEN ;
                OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                        OpenAttestationResponseFault.FaultCode.FAULT_403);
                fault.setError_message("The access to the Permission Type resource is forbidden");
                return Response.status(status).header("Location", b.build()).entity(fault).build();
            }
        }
        catch( Exception e )
        {
            status = Response.Status.INTERNAL_SERVER_ERROR ;
            OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                    OpenAttestationResponseFault.FaultCode.FAULT_500 ) ;
            fault.setError_message( "Edit Permission Type entry failed." + "Exception:" + e.getMessage() ) ;
            return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                    .build() ;
        }
    }
}
