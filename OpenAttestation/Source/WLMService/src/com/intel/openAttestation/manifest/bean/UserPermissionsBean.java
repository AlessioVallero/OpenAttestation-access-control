/*
Copyright (C) 2014 Politecnico di Torino, Italy
TORSEC group -- http://security.polito.it
*/

package com.intel.openAttestation.manifest.bean;

import javax.xml.bind.annotation.XmlRootElement;

import javax.xml.bind.annotation.XmlElement;

/**
 * Java class linked to the UsersPermissions table.
 * @author  intel
 * @version OpenAttestation
 *
 */

@XmlRootElement
public class UserPermissionsBean
{
    String Username ;
    String Class ;
    String Operation ;
    String ParName ;
    private String Value ;
    
    public UserPermissionsBean()
    {
    }
    
    public UserPermissionsBean( String Username , String Class , String Operation , String ParName , String Value )
    {
        this.Username = Username ;
        this.Class = Class ;
        this.Operation = Operation ;
        this.ParName = ParName ;
        this.Value = Value ;
    }

    public String getUsername()
    {
        return Username ;
    }

    @XmlElement(name = "Username")
    public void setUsername( String username )
    {
        Username = username ;
    }

    public String getClassValue()
    {
        return Class ;
    }

    @XmlElement(name = "Class")
    public void setClassValue( String Class )
    {
        this.Class = Class ;
    }

    public String getOperation()
    {
        return Operation ;
    }

    @XmlElement(name = "Operation")
    public void setOperation( String operation )
    {
        Operation = operation ;
    }
    public String getParName()
    {
        return ParName ;
    }

    @XmlElement(name = "ParName")
    public void setParName( String parName )
    {
        ParName = parName ;
    }

    public String getValue()
    {
        return Value ;
    }

    @XmlElement(name="Value")
    public void setValue( String value)
    {
        this.Value = value ;
    }
}
