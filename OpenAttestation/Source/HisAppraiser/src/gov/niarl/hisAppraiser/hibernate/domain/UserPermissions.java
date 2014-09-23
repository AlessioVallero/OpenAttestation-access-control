/*
Copyright (C) 2014 Politecnico di Torino, Italy
TORSEC group -- http://security.polito.it
*/

package gov.niarl.hisAppraiser.hibernate.domain;

import javax.xml.bind.annotation.XmlRootElement;

import javax.xml.bind.annotation.XmlElement;

/**
 * Java class linked to the UsersPermissions table.
 * @author  intel
 * @version OpenAttestation
 *
 */

@XmlRootElement
public class UserPermissions
{
    private Long ID ;
    private Long IDUsers ;
    private Long IDPermissionsTypes ;
    private String Value ;

    public UserPermissions()
    {
    }
    
    public UserPermissions( Long IDUsers , Long IDPermissionsTypes , String Value )
    {
        this.IDUsers = IDUsers ;
        this.IDPermissionsTypes = IDPermissionsTypes ;
        this.Value = Value ;
    }

    public Long getID()
    {
        return ID ;
    }

    public void setID( Long iD )
    {
        ID = iD ;
    }

    public Long getIDUsers()
    {
        return IDUsers ;
    }

    @XmlElement(name = "IDUsers")
    public void setIDUsers( Long iDUsers )
    {
        IDUsers = iDUsers ;
    }

    public Long getIDPermissionsTypes()
    {
        return IDPermissionsTypes ;
    }

    @XmlElement(name = "IDPermissionsTypes")
    public void setIDPermissionsTypes( Long iDPermissionsTypes )
    {
        IDPermissionsTypes = iDPermissionsTypes ;
    }

    public String getValue()
    {
        return Value ;
    }

    @XmlElement(name = "Value")
    public void setValue( String Value )
    {
        this.Value = Value ;
    }
}
