/*
Copyright (C) 2014 Politecnico di Torino, Italy
TORSEC group -- http://security.polito.it
*/

package com.intel.openAttestation.manifest.hibernate.domain;

import javax.xml.bind.annotation.XmlRootElement;

import javax.xml.bind.annotation.XmlElement;

/**
 * Java class linked to the PermissionsTypes table.
 * @author  intel
 * @version OpenAttestation
 *
 */

@XmlRootElement
public class PermissionType
{
    private Long ID ;
    private String Class ;
    private String Operation ;
    private String ParName ;
    private Boolean IsEnforced ;

    public PermissionType()
    {
    }
    
    public PermissionType( String Class , String Operation , String ParName , boolean IsEnforced )
    {
        this.Class = Class ;
        this.Operation = Operation ;
        this.ParName = ParName ;
        this.IsEnforced = IsEnforced ;
    }

    public Long getID()
    {
        return ID ;
    }

    public void setID( Long iD )
    {
        ID = iD ;
    }

    public String getClassValue()
    {
        return Class ;
    }

    @XmlElement(name = "Class")
    public void setClassValue( String classvalue )
    {
        Class = classvalue ;
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
        this.ParName = parName ;
    }

    public Boolean getIsEnforced()
    {
        return IsEnforced ;
    }

    @XmlElement(name = "IsEnforced")
    public void setIsEnforced( Boolean isEnforced )
    {
        this.IsEnforced = isEnforced ;
    }
}
