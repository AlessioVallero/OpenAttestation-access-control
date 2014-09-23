/*
Copyright (c) 2012, Intel Corporation
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of Intel Corporation nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package gov.niarl.hisAppraiser.hibernate.util;
import gov.niarl.hisAppraiser.hibernate.dao.AttestDao;
import gov.niarl.hisAppraiser.hibernate.domain.AttestRequest;
import gov.niarl.hisAppraiser.hibernate.domain.AuditLog;
import gov.niarl.hisAppraiser.hibernate.domain.PCRManifest;
import gov.niarl.hisAppraiser.hibernate.domain.PcrWhiteList;
import gov.niarl.hisAppraiser.hibernate.util.ResultConverter.AttestResult;
import gov.niarl.hisAppraiser.hibernate.dao.UserDAO;
import gov.niarl.hisAppraiser.hibernate.dao.UserPermissionDAO;
import gov.niarl.hisAppraiser.hibernate.dao.PermissionTypeDAO;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import javax.ws.rs.core.GenericEntity;

import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class AttestService {
	
	
	/**
	 * validate PCR value of a request. Here is 4 cases, that is timeout, unknown, trusted and untrusted.
	 * case1 (timeout): attest's time is greater than default timeout of attesting from OpenAttestation.properties. In generally, it is usually set as 60 seconds;
	 * case2 (unknown): machine is not enrolled in attest server.  Just check whether active machineCert is existed.
	 * case3 (trusted): all hosts has attested and their pcrs has matched with PCRManifest table;
	 * case4 (untrusted): all hosts has attested, but their pcrs cannot match with PCRManifest table.  
	 * @param attestRequest of intending to validate. 
	 * @return 
	 */
	public static AttestRequest validatePCRReport(AttestRequest attestRequest,String machineNameInput){
		attestRequest.getAuditLog();
		List<PcrWhiteList> whiteList = new ArrayList<PcrWhiteList>();
		AttestDao dao = new AttestDao();
		boolean flag = true;
		whiteList = dao.getPcrValue(machineNameInput);
		
		System.out.println(attestRequest.getId() +":" +attestRequest.getAuditLog().getId());
		
		 if(attestRequest.getAuditLog()!= null && attestRequest.getIsConsumedByPollingWS()){
			 
			AuditLog auditLog = attestRequest.getAuditLog();
			HashMap<Integer,String> pcrs = new HashMap<Integer, String>();
			pcrs = generatePcrsByAuditId(auditLog);
			
			if (whiteList!=null && whiteList.size() != 0){
				for(int i=0; i<whiteList.size(); i++){
					int pcrNumber = Integer.valueOf(whiteList.get(i).getPcrName()).intValue();
						if(!whiteList.get(i).getPcrDigest().equalsIgnoreCase(pcrs.get(pcrNumber))){
							flag = false;
							break;
						}
				}
			} else {
				flag = false;
			}
			
			if (!flag){
				attestRequest.setResult(ResultConverter.getIntFromResult(AttestResult.UN_TRUSTED));
			}
			else
				attestRequest.setResult(ResultConverter.getIntFromResult(AttestResult.TRUSTED));
			attestRequest.setValidateTime(new Date());
		}
		 return attestRequest;
	}
	
	/*
	 * compare request's PCR with PCRManifest in DB. 
	 * @Param needs to compare request. 
	 *        At first convert request string from AttestRequest to List<Manifest>.
	 *        A request may contain several pcrs, so needs parse a List of PCRmanifest.  
	 * @Return null string if PCR not exists, else not null string 
	 * with different pcrs' number and separating them with '|' like this '2|20'     
	 */
	public static String compareManifestPCR(List<PCRManifest> manifestPcrs){
		GenericEntity<List<PCRManifest>> entity = new GenericEntity<List<PCRManifest>>(manifestPcrs) {}; 
		AttestUtil.loadProp();
		//manifestPcrs.
		WebResource resource = AttestUtil.getClient(AttestUtil.getManifestWebServicesUrl());
	    ClientResponse res = resource.path("/Validate").type("application/json").
  	              accept("application/json").post(ClientResponse.class,entity);
	    return res.getEntity(String.class);
	}

	
	/**
	 * generate a hashMap of pcrs for a given auditlog. The hashMap key is pcr's number and value is pcr's value.  
	 * @param auditlog of interest
	 * @return contain key-values of pcrs like {<'1','11111111111'>,<'2','111111111111111111111'>,...}   
	 */
	public static HashMap<Integer,String> generatePcrsByAuditId(AuditLog auditlog){
		HashMap<Integer,String> pcrs = new HashMap<Integer, String>();
		pcrs.put(0, auditlog.getPcr0());
		pcrs.put(1, auditlog.getPcr1());
		pcrs.put(2, auditlog.getPcr2());
		pcrs.put(3, auditlog.getPcr3());
		pcrs.put(4, auditlog.getPcr4());
		pcrs.put(5, auditlog.getPcr5());
		pcrs.put(6, auditlog.getPcr6());
		pcrs.put(7, auditlog.getPcr7());
		pcrs.put(8, auditlog.getPcr8());
		pcrs.put(9, auditlog.getPcr9());
		pcrs.put(10, auditlog.getPcr10());
		pcrs.put(11, auditlog.getPcr11());
		pcrs.put(12, auditlog.getPcr12());
		pcrs.put(13, auditlog.getPcr13());
		pcrs.put(14, auditlog.getPcr14());
		pcrs.put(15, auditlog.getPcr15());
		pcrs.put(16, auditlog.getPcr16());
		pcrs.put(17, auditlog.getPcr17());
		pcrs.put(18, auditlog.getPcr18());
		pcrs.put(19, auditlog.getPcr19());
		pcrs.put(20, auditlog.getPcr20());
		pcrs.put(21, auditlog.getPcr21());
		pcrs.put(22, auditlog.getPcr22());
		pcrs.put(23, auditlog.getPcr23());
		return pcrs;
	}

    /**
     * authentication
     * @param username
     * @param password
     * @return the user's id
     */
    public static Long ISV_Autherntication_module( javax.servlet.http.HttpServletRequest request )
    {
        Long ret = -1L ;
        try
        {
            if( request != null )
            {
                String auth_blob = request.getHeader( "Auth-blob" ) ;
                if( auth_blob == null || auth_blob.isEmpty() )
                {

                }
                else
                {
                    String[] parts = auth_blob.split( "#" ) ;
                    if( parts != null && parts.length == 2 )
                    {
                        // parts[0] -> Username
                        // parts[1] -> Password
                        if( parts[0] != null && !parts[0].isEmpty() &&
                            parts[1] != null && !parts[1].isEmpty() )
                        {
                            String sPasswordSHA = getHash( parts[1] , "SHA-1" ) ;
                            if( sPasswordSHA != null && !sPasswordSHA.isEmpty() )
                            {
                                UserDAO dao = new UserDAO() ;

                                ret = dao.getAuthenticatedUserId( parts[0] , sPasswordSHA ) ;
                            }
                        }
                    }
                }
            }

            return ret ;
        }
        catch( Exception e )
        {
            throw new RuntimeException( e ) ;
        }
    }

    public static boolean ISV_Permission_Type_Enforcement( String classValue , String operationValue , String parnameValue )
    {
        boolean ret = false ;

        try
        {
            PermissionTypeDAO dao = new PermissionTypeDAO() ;

            ret = dao.getPermissionTypeEnforcement( classValue , operationValue , parnameValue ) ;

            return ret ;
        }
        catch( Exception e )
        {
            throw new RuntimeException( e ) ;
        }
    }

    public static boolean doAuthorization( Long userId , String classValue , String operationValue , List<ParNameContainer> parnameValues )
    {
        boolean ret = false ;

        try
        {
            UserPermissionDAO dao = new UserPermissionDAO() ;

            ret = dao.doAuthorization( userId , classValue , operationValue , parnameValues ) ;

            return ret ;
        }
        catch( Exception e )
        {
            throw new RuntimeException( e ) ;
        }
    }

    public static String getHash( String message , String algorithm )
    {
        try
        {
            // Create the HASH for the input message with the input algorithm
            byte[] buffer = message.getBytes() ;
            MessageDigest md = MessageDigest.getInstance( algorithm ) ;
            md.update( buffer ) ;
            byte[] digest = md.digest() ;
            String hex = "" ;
            for( int i = 0 ; i < digest.length ; i++ )
            {
                int b = digest[i] & 0xff ;
                if( Integer.toHexString( b ).length() == 1 ) hex = hex + "0" ;
                hex  = hex + Integer.toHexString( b ) ;
            }
            return hex ;
        }
        catch( NoSuchAlgorithmException e )
        {
            e.printStackTrace() ;
        }
        return null ;
    }
}
