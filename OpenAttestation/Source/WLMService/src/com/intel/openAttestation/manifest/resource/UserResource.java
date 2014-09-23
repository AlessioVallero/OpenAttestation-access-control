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
import com.intel.openAttestation.manifest.hibernate.dao.UserDAO;
import com.intel.openAttestation.manifest.hibernate.domain.User;
import com.intel.openAttestation.manifest.resource.UserResource;

import org.apache.commons.codec.digest.DigestUtils;

import org.hibernate.Query;
import java.util.List;

/**
 * RESTful web service interface to work with OEM DB.
 * @author xmei1
 *
 */

@Path("resources/users")
public class UserResource
{
    @POST
    @Consumes("application/json")
    @Produces("application/json")
    public Response addUser( @Context UriInfo uriInfo , User user , @Context javax.servlet.http.HttpServletRequest request )
    {
        UriBuilder b = uriInfo.getBaseUriBuilder() ;
        b = b.path( UserResource.class ) ;
        Response.Status status = Response.Status.OK ;
        boolean isValidKey = true ;
        AttestUtil.loadProp() ;
        try
        {
            UserDAO dao = new UserDAO() ;

            HashMap parameters = new HashMap() ;
            // If there isn't Username on the input request, it's an error
            if( user.getUsername() != null )
            {
                parameters.put( user.getUsername() , 50 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            // If there isn't Password on the input request, it's an error
            if( user.getPassword() == null )
            {
                isValidKey = false ;
            }

            if( !isValidKey || user.getUsername().length() < 1 || user.getPassword().length() < 1 || !HisUtil.validParas( parameters ) )
            {
                status = Response.Status.INTERNAL_SERVER_ERROR ;
                OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                        OpenAttestationResponseFault.FaultCode.FAULT_500 ) ;
                fault.setError_message( "Add User entry failed, please check the length for each parameters" +
                        " and remove all of the unwanted characters belonged to [# & + : \" \']" ) ;
                return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                        .build() ;
            }

            // Authentication
            Long userId = AttestService.ISV_Autherntication_module( request ) ;

            boolean isUsernameEnforced = AttestService.ISV_Permission_Type_Enforcement( "User" , "Add" , "Username" ) ;
            boolean isPasswordEnforced = AttestService.ISV_Permission_Type_Enforcement( "User" , "Add" , "Password" ) ;

            List<ParNameContainer> parnameValues = new ArrayList<ParNameContainer>() ;
            // Check the Username validity, if the Enforcement is enabled
            if( isUsernameEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized add User, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "Username" , user.getUsername() ) ) ;
            }
            // Check the Password validity, if the Enforcement is enabled
            if( isPasswordEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized add User, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "Password" , user.getPassword() ) ) ;
            }

            // If no element is enforced, or if they are all in the authorized format, we can proceed
            if( parnameValues.size() < 1 || AttestService.doAuthorization( userId , "User" , "Add" , parnameValues ) )
            {
                // The Username of the user we are trying to add must not exists to be considered valid
                System.out.println( "Check if the User Username exists:" + user.getUsername() ) ;
                if( dao.isUserExisted( user.getUsername() ) )
                {
                    status = Response.Status.BAD_REQUEST ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault( 1006 ) ;
                    fault.setError_message( "Data Error - User " + user.getUsername( )+ " already exists in the database" ) ;
                    return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                            .build();
                }

                // The password is stored with a SHA-1 hashing
                user.setPassword( AttestService.getHash( user.getPassword() , "SHA-1" ) ) ;
                // Insert an entry into USERS
                dao.addUserEntry( user ) ;

                return Response.status( status ).header( "Location" , b.build() ).type( MediaType.TEXT_PLAIN ).entity( "True" )
                        .build() ;
            }
            else
            {
                status = Response.Status.FORBIDDEN ;
                OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                        OpenAttestationResponseFault.FaultCode.FAULT_403);
                fault.setError_message("The couple Username/Password is not in an authorized format");
                return Response.status(status).header("Location", b.build()).entity(fault).build();
            }
        }
        catch( Exception e )
        {
            status = Response.Status.INTERNAL_SERVER_ERROR ;
            OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                    OpenAttestationResponseFault.FaultCode.FAULT_500 ) ;
            fault.setError_message( "Add User entry failed." + "Exception:" + e.getMessage() ) ;
            return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                    .build() ;
        }
    }

    @PUT
    @Consumes("application/json")
    @Produces("application/json")
    public Response editUser( @Context UriInfo uriInfo , User user, @Context javax.servlet.http.HttpServletRequest request )
    {
        UriBuilder b = uriInfo.getBaseUriBuilder() ;
        b = b.path( UserResource.class ) ;
        Response.Status status = Response.Status.OK ;
        boolean isValidKey = true ;
        AttestUtil.loadProp() ;
        try
        {
            UserDAO dao = new UserDAO() ;

            HashMap parameters = new HashMap() ;
            // If there isn't Username on the input request, it's an error
            if( user.getUsername() != null )
            {
                parameters.put( user.getUsername() , 50 ) ;
            }
            else
            {
                isValidKey = false ;
            }

            // If there isn't Password on the input request, it's an error
            if( user.getPassword() == null )
            {
                isValidKey = false ;
            }

            if( !isValidKey || user.getUsername().length() < 1 || user.getPassword().length() < 1 || !HisUtil.validParas( parameters ) )
            {
                status = Response.Status.INTERNAL_SERVER_ERROR ;
                OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                        OpenAttestationResponseFault.FaultCode.FAULT_500 ) ;
                fault.setError_message( "Edit User entry failed, please check the length for each parameters" +
                        " and remove all of the unwanted characters belonged to [# & + : \" \']" ) ;
                return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                        .build() ;
            }

            // Authentication
            Long userId = AttestService.ISV_Autherntication_module( request ) ;

            boolean isUsernameEnforced = AttestService.ISV_Permission_Type_Enforcement( "User" , "Edit" , "Username" ) ;
            boolean isPasswordEnforced = AttestService.ISV_Permission_Type_Enforcement( "User" , "Edit" , "Password" ) ;

            List<ParNameContainer> parnameValues = new ArrayList<ParNameContainer>() ;
            // Check the Username validity, if the Enforcement is enabled
            if( isUsernameEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized edit User, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "Username" , user.getUsername() ) ) ;
            }
            // Check the Password validity, if the Enforcement is enabled
            if( isPasswordEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized edit User, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "Password" , user.getPassword() ) ) ;
            }

            // If no element is enforced, or if they are all in the authorized format, we can proceed
            if( parnameValues.size() < 1 || AttestService.doAuthorization( userId , "User" , "Edit" , parnameValues ) )
            {
                // The Username of the user we are trying to add must exists
                System.out.println( "Check if the User Username exists:" + user.getUsername() ) ;
                if( !dao.isUserExisted( user.getUsername() ) )
                {
                    status = Response.Status.BAD_REQUEST ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault( 1006 ) ;
                    fault.setError_message( "Data Error - User " + user.getUsername( )+ " does not exists in the database" ) ;
                    return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                            .build();
                }

                // The password is stored with a SHA-1 hashing
                user.setPassword( AttestService.getHash( user.getPassword() , "SHA-1" ) ) ;
                // Edit an USERS entry
                dao.editUserEntry( user ) ;

                return Response.status( status ).header( "Location" , b.build() ).type( MediaType.TEXT_PLAIN ).entity( "True" )
                        .build() ;
            }
            else
            {
                status = Response.Status.FORBIDDEN ;
                OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                        OpenAttestationResponseFault.FaultCode.FAULT_403);
                fault.setError_message("The couple Username/Password is not in an authorized format");
                return Response.status(status).header("Location", b.build()).entity(fault).build();
            }
        }
        catch( Exception e )
        {
            status = Response.Status.INTERNAL_SERVER_ERROR ;
            OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                    OpenAttestationResponseFault.FaultCode.FAULT_500 ) ;
            fault.setError_message( "Add User entry failed." + "Exception:" + e.getMessage() ) ;
            return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                    .build() ;
        }
    }
    
    @DELETE
    @Produces("application/json")
    public Response deluserEntry( @QueryParam("Username") String Username , @Context UriInfo uriInfo , @Context javax.servlet.http.HttpServletRequest request )
    {
        UriBuilder b = uriInfo.getBaseUriBuilder() ;
        b = b.path( UserResource.class ) ;
        Response.Status status = Response.Status.OK ;
        boolean isValidKey = true ;
        AttestUtil.loadProp() ;
        try
        {
            UserDAO dao = new UserDAO() ;

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

            if( !isValidKey || Username.length() < 1 || !HisUtil.validParas( parameters ) )
            {
                status = Response.Status.INTERNAL_SERVER_ERROR ;
                OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                        OpenAttestationResponseFault.FaultCode.FAULT_500 ) ;
                fault.setError_message( "Delete User entry failed, please check the length for each parameters" +
                        " and remove all of the unwanted characters belonged to [# & + : \" \']" ) ;
                return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                        .build() ;
            }

            // Authentication
            Long userId = AttestService.ISV_Autherntication_module( request ) ;

            boolean isUsernameEnforced = AttestService.ISV_Permission_Type_Enforcement( "User" , "Delete" , "Username" ) ;

            List<ParNameContainer> parnameValues = new ArrayList<ParNameContainer>() ;
            // Check the Username validity, if the Enforcement is enabled
            if( isUsernameEnforced )
            {
                if( userId < 0 )
                {
                    status = Response.Status.UNAUTHORIZED ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                            OpenAttestationResponseFault.FaultCode.FAULT_401);
                    fault.setError_message("Unauthorized delete User, please make sure that the authentication informations are correct");
                    return Response.status(status).header("Location", b.build()).entity(fault).build();
                }

                parnameValues.add( new ParNameContainer( "Username" , Username ) ) ;
            }

            // If no element is enforced, or if they are all in the authorized format, we can proceed
            if( parnameValues.size() < 1 || AttestService.doAuthorization( userId , "User" , "Delete" , parnameValues ) )
            {
                // The Username we are trying to delete must exists on the database
                if( dao.isUserExisted( Username ) )
                {
                    // Deleting User
                    dao.deleteUserEntry( Username ) ;
                    return Response.status( status ).type( MediaType.TEXT_PLAIN ).entity( "True" )
                            .build() ;
                }
                else
                {
                    status = Response.Status.BAD_REQUEST ;
                    OpenAttestationResponseFault fault = new OpenAttestationResponseFault( 1006 ) ;
                    fault.setError_message( "Data Error - User " + Username + " does not exists in the database" ) ;
                    return Response.status( status ).header( "Location" , b.build() ).entity( fault )
                            .build();
                }
            }
            else
            {
                status = Response.Status.FORBIDDEN ;
                OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                        OpenAttestationResponseFault.FaultCode.FAULT_403);
                fault.setError_message("The Username is not in an authorized format");
                return Response.status(status).header("Location", b.build()).entity(fault).build();
            }
        }
        catch( Exception e )
        {
            status = Response.Status.INTERNAL_SERVER_ERROR ;
            OpenAttestationResponseFault fault = new OpenAttestationResponseFault(
                    OpenAttestationResponseFault.FaultCode.FAULT_500 ) ;
            fault.setError_message( "Delete User entry failed." + "Exception:" + e.getMessage() ) ; 
            return Response.status( status ).entity( fault )
                    .build() ;
        }
    }
}
