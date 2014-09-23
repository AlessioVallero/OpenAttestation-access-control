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
import gov.niarl.hisAppraiser.hibernate.util.ParNameContainer;

import com.intel.openAttestation.manifest.bean.OpenAttestationResponseFault;
import com.intel.openAttestation.manifest.hibernate.dao.UserPermissionDAO;
import com.intel.openAttestation.manifest.hibernate.domain.UserPermissions;
import com.intel.openAttestation.manifest.bean.UserPermissionsBean;

import org.apache.commons.codec.digest.DigestUtils;

import org.hibernate.Query;
import java.util.List;

/**
 * RESTful web service interface to work with OEM DB.
 * @author xmei1
 *
 */

@Path("resources/users_permissions")
public class UserPermissionResource
{
    @POST
    @Consumes("application/json")
    @Produces("application/json")
    public Response addUserPermission( @Context UriInfo uriInfo , UserPermissionsBean userPermissions , @Context javax.servlet.http.HttpServletRequest request )
    {
        System.out.println( "Check if the Username exists:" + userPermissions.getUsername() ) ;
        UriBuilder b = uriInfo.getBaseUriBuilder() ;
        b = b.path( UserPermissionResource.class ) ;
        Response.Status status = Response.Status.OK ;
        boolean isValidKey = true ;
        AttestUtil.loadProp() ;
        try
        {
            UserPermissionDAO dao = new UserPermissionDAO() ;

            HashMap parameters = new HashMap() ;
            // If there isn't Username on the input request, it's an error
            if( userPermissions.getUsername() != null )
            {
                parameters.put( userPermissions.getUsername() , 50 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            // If there isn't Class on the input request, it's an error
            if( userPermissions.getClassValue() != null )
            {
                parameters.put( userPermissions.getClassValue() , 100 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            // If there isn't Operation on the input request, it's an error
            if( userPermissions.getOperation() != null )
            {
                parameters.put( userPermissions.getOperation() , 100 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            // If there isn't ParName on the input request, it's an error
            if( userPermissions.getParName() != null )
            {
                parameters.put( userPermissions.getParName() , 100 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            // If there isn't Value on the input request, it's an error
            if( userPermissions.getValue() == null )
            {
                isValidKey = false ;
            }

            // If there aren't Values on the input request, it's an error
            if( !isValidKey ||
                userPermissions.getUsername().length() < 1 ||
                userPermissions.getClassValue().length() < 1 ||
                userPermissions.getOperation().length() < 1 ||
                userPermissions.getParName().length() < 1 ||
                userPermissions.getValue().length() < 1 ||
                !HisUtil.validParas( parameters ) )
            {
                status = Response.Status.INTERNAL_SERVER_ERROR ;
                OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                        OpenAttestationResponseFault.FaultCode.FAULT_500 ) ;
                fault.setError_message( "Add UserPermission entry failed, please check the length for each parameters" +
                        " and remove all of the unwanted characters belonged to [# & + : \" \']" ) ;
                return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                        .build() ;
            }

            // Authentication
            Long userId = AttestService.ISV_Autherntication_module( request ) ;

            boolean isUsernameEnforced = AttestService.ISV_Permission_Type_Enforcement( "UserPermission" , "Add" , "Username" ) ;
            boolean isClassEnforced = AttestService.ISV_Permission_Type_Enforcement( "UserPermission" , "Add" , "Class" ) ;
            boolean isOperationEnforced = AttestService.ISV_Permission_Type_Enforcement( "UserPermission" , "Add" , "Operation" ) ;
            boolean isParNameEnforced = AttestService.ISV_Permission_Type_Enforcement( "UserPermission" , "Add" , "ParName" ) ;
            boolean isValueEnforced = AttestService.ISV_Permission_Type_Enforcement( "UserPermission" , "Add" , "Value" ) ;

            List<ParNameContainer> parnameValues = new ArrayList<ParNameContainer>() ;
            // Check the Username validity, if the Enforcement is enabled
            if( isUsernameEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized add User Permission, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "Username" , userPermissions.getUsername() ) ) ;
            }
            // Check the Class validity, if the Enforcement is enabled
            if( isClassEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized add User Permission, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "Class" , userPermissions.getClassValue() ) ) ;
            }
            // Check the Operation validity, if the Enforcement is enabled
            if( isOperationEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized add User Permission, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "Operation" , userPermissions.getOperation() ) ) ;
            }
            // Check the ParName validity, if the Enforcement is enabled
            if( isParNameEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized add User Permission, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "ParName" , userPermissions.getParName() ) ) ;
            }
            // Check the Value validity, if the Enforcement is enabled
            if( isValueEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized add User Permission, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "Value" , userPermissions.getValue() ) ) ;
            }

            // If no element is enforced, or if they are all in the authorized format, we can proceed
            if( parnameValues.size() < 1 || AttestService.doAuthorization( userId , "UserPermission" , "Add" , parnameValues ) )
            {
                // The Username of the userPermissions we are trying to add must exists to be considered valid
                System.out.println( "Get the UserID from the Username: " + userPermissions.getUsername() ) ;
                Long userIDForPermission = dao.getUserIDFromUsername( userPermissions.getUsername() ) ;
                if( userIDForPermission < 0 )
                {
                    status = Response.Status.BAD_REQUEST ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault( 1006 ) ;
                    fault.setError_message( "Data Error - Username " + userPermissions.getUsername() + " does not exists in the database" ) ;
                    return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                            .build();
                }

                // The Username of the userPermissions we are trying to add must exists to be considered valid
                System.out.println( "Get the PermissionType from the PermissionTypeData: " + userPermissions.getClassValue() + " - " + userPermissions.getOperation() + " - " + userPermissions.getParName() ) ;
                Long permissionTypeID = dao.getPermissionTypeIDFromPermissionTypeData( userPermissions.getClassValue() , userPermissions.getOperation() , userPermissions.getParName() ) ;
                if( permissionTypeID < 0 )
                {
                    status = Response.Status.BAD_REQUEST ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault( 1006 ) ;
                    fault.setError_message( "Data Error - PermissionType " + userPermissions.getClassValue() + " - " + userPermissions.getOperation() + " - " + userPermissions.getParName() + " does not exists in the database" ) ;
                    return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                            .build();
                }

                // All the permissions we are trying to add must not exists to be considered a valid situation
                System.out.println( "Check if the Permission exists" ) ;
                if( dao.userPermissionsExists( userIDForPermission , permissionTypeID ) )
                {
                    status = Response.Status.BAD_REQUEST ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault( 1006 ) ;
                    fault.setError_message( "Data Error - Permission " + userPermissions.getUsername() + " - " + userPermissions.getClassValue() + " - " + userPermissions.getOperation() + " - " + userPermissions.getParName() + " already exists in the database" ) ;
                    return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                            .build();
                }

                // Insert the entry related to this user permission
                dao.addUserPermissionEntry( userIDForPermission , permissionTypeID , userPermissions.getValue() ) ;
                return Response.status( status ).header( "Location" , b.build() ).type( MediaType.TEXT_PLAIN ).entity( "True" )
                        .build() ;
            }
            else
            {
                status = Response.Status.FORBIDDEN ;
                OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                        OpenAttestationResponseFault.FaultCode.FAULT_403);
                fault.setError_message("The passed values are not in an authorized format");
                return Response.status(status).header("Location", b.build()).entity(fault).build();
            }
        }
        catch( Exception e )
        {
            status = Response.Status.INTERNAL_SERVER_ERROR ;
            OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                    OpenAttestationResponseFault.FaultCode.FAULT_500 ) ;
            fault.setError_message( "Add Permission entry failed." + "Exception:" + e.getMessage() ) ;
            return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                    .build() ;
        }
    }

    @PUT
    @Consumes("application/json")
    @Produces("application/json")
    public Response editUserPermission( @Context UriInfo uriInfo , UserPermissionsBean userPermissions, @Context javax.servlet.http.HttpServletRequest request )
    {
        System.out.println( "Check if the Username exists:" + userPermissions.getUsername() ) ;
        UriBuilder b = uriInfo.getBaseUriBuilder() ;
        b = b.path( UserPermissionResource.class ) ;
        Response.Status status = Response.Status.OK ;
        boolean isValidKey = true ;
        AttestUtil.loadProp() ;
        try
        {
            UserPermissionDAO dao = new UserPermissionDAO() ;

            HashMap parameters = new HashMap() ;
            // If there isn't Username on the input request, it's an error
            if( userPermissions.getUsername() != null )
            {
                parameters.put( userPermissions.getUsername() , 50 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            // If there isn't Class on the input request, it's an error
            if( userPermissions.getClassValue() != null )
            {
                parameters.put( userPermissions.getClassValue() , 100 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            // If there isn't Operation on the input request, it's an error
            if( userPermissions.getOperation() != null )
            {
                parameters.put( userPermissions.getOperation() , 100 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            // If there isn't ParName on the input request, it's an error
            if( userPermissions.getParName() != null )
            {
                parameters.put( userPermissions.getParName() , 100 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            // If there isn't Value on the input request, it's an error
            if( userPermissions.getValue() == null )
            {
                isValidKey = false ;
            }

            // If there aren't Values on the input request, it's an error
            if( !isValidKey ||
                userPermissions.getUsername().length() < 1 ||
                userPermissions.getClassValue().length() < 1 ||
                userPermissions.getOperation().length() < 1 ||
                userPermissions.getParName().length() < 1 ||
                userPermissions.getValue().length() < 1 ||
                !HisUtil.validParas( parameters ) )
            {
                status = Response.Status.INTERNAL_SERVER_ERROR ;
                OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                        OpenAttestationResponseFault.FaultCode.FAULT_500 ) ;
                fault.setError_message( "Add UserPermission entry failed, please check the length for each parameters" +
                        " and remove all of the unwanted characters belonged to [# & + : \" \']" ) ;
                return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                        .build() ;
            }

            // Authentication
            Long userId = AttestService.ISV_Autherntication_module( request ) ;

            boolean isUsernameEnforced = AttestService.ISV_Permission_Type_Enforcement( "UserPermission" , "Edit" , "Username" ) ;
            boolean isClassEnforced = AttestService.ISV_Permission_Type_Enforcement( "UserPermission" , "Edit" , "Class" ) ;
            boolean isOperationEnforced = AttestService.ISV_Permission_Type_Enforcement( "UserPermission" , "Edit" , "Operation" ) ;
            boolean isParNameEnforced = AttestService.ISV_Permission_Type_Enforcement( "UserPermission" , "Edit" , "ParName" ) ;
            boolean isValueEnforced = AttestService.ISV_Permission_Type_Enforcement( "UserPermission" , "Edit" , "Value" ) ;

            List<ParNameContainer> parnameValues = new ArrayList<ParNameContainer>() ;
            // Check the Username validity, if the Enforcement is enabled
            if( isUsernameEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized edit User Permission, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "Username" , userPermissions.getUsername() ) ) ;
            }
            // Check the Class validity, if the Enforcement is enabled
            if( isClassEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized edit User Permission, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "Class" , userPermissions.getClassValue() ) ) ;
            }
            // Check the Operation validity, if the Enforcement is enabled
            if( isOperationEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized edit User Permission, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "Operation" , userPermissions.getOperation() ) ) ;
            }
            // Check the ParName validity, if the Enforcement is enabled
            if( isParNameEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized edit User Permission, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "ParName" , userPermissions.getParName() ) ) ;
            }
            // Check the Value validity, if the Enforcement is enabled
            if( isValueEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized edit User Permission, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "Value" , userPermissions.getValue() ) ) ;
            }

            // If no element is enforced, or if they are all in the authorized format, we can proceed
            if( parnameValues.size() < 1 || AttestService.doAuthorization( userId , "UserPermission" , "Edit" , parnameValues ) )
            {
                // The Username of the userPermissions we are trying to add must exists to be considered valid
                System.out.println( "Get the UserID from the Username: " + userPermissions.getUsername() ) ;
                Long userIDForPermission = dao.getUserIDFromUsername( userPermissions.getUsername() ) ;
                if( userIDForPermission < 0 )
                {
                    status = Response.Status.BAD_REQUEST ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault( 1006 ) ;
                    fault.setError_message( "Data Error - Username " + userPermissions.getUsername() + " does not exists in the database" ) ;
                    return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                            .build();
                }

                // The PermissionTypeData of the permission we are trying to add must exists to be considered valid
                System.out.println( "Get the PermissionType from the PermissionTypeData: " + userPermissions.getClassValue() + " - " + userPermissions.getOperation() + " - " + userPermissions.getParName() ) ;
                Long permissionTypeID = dao.getPermissionTypeIDFromPermissionTypeData( userPermissions.getClassValue() , userPermissions.getOperation() , userPermissions.getParName() ) ;
                if( permissionTypeID < 0 )
                {
                    status = Response.Status.BAD_REQUEST ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault( 1006 ) ;
                    fault.setError_message( "Data Error - PermissionType " + userPermissions.getClassValue() + " - " + userPermissions.getOperation() + " - " + userPermissions.getParName() + " does not exists in the database" ) ;
                    return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                            .build();
                }

                // The permissions we are trying to edit must exists
                System.out.println( "Check if the Permission exists" ) ;
                if( dao.userPermissionsExists( userIDForPermission , permissionTypeID ) )
                {
                    // Editing User Permission
                    dao.editUserPermissionEntry( userIDForPermission , permissionTypeID , userPermissions.getValue() ) ;
                    return Response.status( status ).type( MediaType.TEXT_PLAIN ).entity( "True" )
                            .build() ;
                }
                else
                {
                    status = Response.Status.BAD_REQUEST ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_1006 ) ;
                    fault.setError_message( "Data Error - This permission for " + userPermissions.getUsername() + " does not exist in the database" ) ;        
                    return Response.status( status ).entity( fault )
                            .build() ;
                }
            }
            else
            {
                status = Response.Status.FORBIDDEN ;
                OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                        OpenAttestationResponseFault.FaultCode.FAULT_403);
                fault.setError_message("The passed values are not in an authorized format");
                return Response.status(status).header("Location", b.build()).entity(fault).build();
            }
        }
        catch( Exception e )
        {
            status = Response.Status.INTERNAL_SERVER_ERROR ;
            OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                    OpenAttestationResponseFault.FaultCode.FAULT_500 ) ;
            fault.setError_message( "Edit Permission entry failed." + "Exception:" + e.getMessage() ) ;
            return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                    .build() ;
        }
    }
    
    @DELETE
    @Produces("application/json")
    public Response delUserPermission( @QueryParam("Username") String Username , @QueryParam("Class") String Class , @QueryParam("Operation") String Operation , @QueryParam("ParName") String ParName , @Context UriInfo uriInfo , @Context javax.servlet.http.HttpServletRequest request )
    {
        UriBuilder b = uriInfo.getBaseUriBuilder() ;
        b = b.path( UserPermissionResource.class ) ;
        Response.Status status = Response.Status.OK ;
        boolean isValidKey = true ;
        AttestUtil.loadProp() ;
        try
        {
            UserPermissionDAO dao = new UserPermissionDAO() ;

            HashMap parameters = new HashMap() ;
            // If there isn't Username on the input request, it's an error
            if( Username != null )
            {
                parameters.put( Username , 50 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            // If there isn't Class on the input request, it's an error
            if( Class != null )
            {
                parameters.put( Class , 100 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            // If there isn't Operation on the input request, it's an error
            if( Operation != null )
            {
                parameters.put( Operation , 100 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            // If there isn't ParName on the input request, it's an error
            if( ParName != null )
            {
                parameters.put( ParName , 100 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            if( !isValidKey || Username.length() < 1 || Class.length() < 1 || Operation.length() < 1 || ParName.length() < 1 || !HisUtil.validParas( parameters ) )
            {
                status = Response.Status.INTERNAL_SERVER_ERROR ;
                OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                        OpenAttestationResponseFault.FaultCode.FAULT_500 ) ;
                fault.setError_message( "Delete Permission entry failed, please check the length for each parameters" +
                        " and remove all of the unwanted characters belonged to [# & + : \" \']" ) ;
                return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                        .build() ;
            }

            // Authentication
            Long userId = AttestService.ISV_Autherntication_module( request ) ;

            boolean isUsernameEnforced = AttestService.ISV_Permission_Type_Enforcement( "UserPermission" , "Delete" , "Username" ) ;
            boolean isClassEnforced = AttestService.ISV_Permission_Type_Enforcement( "UserPermission" , "Delete" , "Class" ) ;
            boolean isOperationEnforced = AttestService.ISV_Permission_Type_Enforcement( "UserPermission" , "Delete" , "Operation" ) ;
            boolean isParNameEnforced = AttestService.ISV_Permission_Type_Enforcement( "UserPermission" , "Delete" , "ParName" ) ;

            List<ParNameContainer> parnameValues = new ArrayList<ParNameContainer>() ;
            // Check the Username validity, if the Enforcement is enabled
            if( isUsernameEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized delete User Permission, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "Username" , Username ) ) ;
            }
            // Check the Class validity, if the Enforcement is enabled
            if( isClassEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized delete User Permission, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "Class" , Class ) ) ;
            }
            // Check the Operation validity, if the Enforcement is enabled
            if( isOperationEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized delete User Permission, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "Operation" , Operation ) ) ;
            }
            // Check the ParName validity, if the Enforcement is enabled
            if( isParNameEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized delete User Permission, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "ParName" , ParName ) ) ;
            }

            // If no element is enforced, or if they are all in the authorized format, we can proceed
            if( parnameValues.size() < 1 || AttestService.doAuthorization( userId , "UserPermission" , "Delete" , parnameValues ) )
            {
                // The Username of the userPermissions we are trying to add must exists to be considered valid
                System.out.println( "Get the UserID from the Username: " + Username ) ;
                Long userIDForPermission = dao.getUserIDFromUsername( Username ) ;
                if( userIDForPermission < 0 )
                {
                    status = Response.Status.BAD_REQUEST ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault( 1006 ) ;
                    fault.setError_message( "Data Error - Username " + Username + " does not exists in the database" ) ;
                    return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                            .build();
                }

                // The PermissionTypeData of the permission we are trying to add must exists to be considered valid
                System.out.println( "Get the PermissionType from the PermissionTypeData: " + Class + " - " + Operation + " - " + ParName ) ;
                Long permissionTypeID = dao.getPermissionTypeIDFromPermissionTypeData( Class , Operation , ParName ) ;
                if( permissionTypeID < 0 )
                {
                    status = Response.Status.BAD_REQUEST ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault( 1006 ) ;
                    fault.setError_message( "Data Error - PermissionType " + Class + " - " + Operation + " - " + ParName + " does not exists in the database" ) ;
                    return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                            .build();
                }

                // The permissions we are trying to delete must exists
                System.out.println( "Check if the Permission exists" ) ;
                if( dao.userPermissionsExists( userIDForPermission , permissionTypeID ) )
                {
                    // Deleting User Permission
                    dao.deleteUserPermissionEntry( userIDForPermission , permissionTypeID ) ;
                    return Response.status( status ).type( MediaType.TEXT_PLAIN ).entity( "True" )
                            .build() ;
                }

                status = Response.Status.BAD_REQUEST ;
                OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                        OpenAttestationResponseFault.FaultCode.FAULT_1006 ) ;
                fault.setError_message( "Data Error - This permission for " + Username + " does not exist in the database" ) ;        
                return Response.status( status ).entity( fault )
                        .build() ;
            }
            else
            {
                status = Response.Status.FORBIDDEN ;
                OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                        OpenAttestationResponseFault.FaultCode.FAULT_403);
                fault.setError_message("The passed values are not in an authorized format");
                return Response.status(status).header("Location", b.build()).entity(fault).build();
            }
        }
        catch( Exception e )
        {
            status = Response.Status.INTERNAL_SERVER_ERROR ;
            OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                    OpenAttestationResponseFault.FaultCode.FAULT_500 ) ;
            fault.setError_message( "Delete Permission entry failed." + "Exception:" + e.getMessage() ) ; 
            return Response.status( status ).entity( fault )
                    .build() ;
        }
    }
}
