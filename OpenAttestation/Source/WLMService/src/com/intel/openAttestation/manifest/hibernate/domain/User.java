/*
Copyright (C) 2014 Politecnico di Torino, Italy
TORSEC group -- http://security.polito.it
*/

package com.intel.openAttestation.manifest.hibernate.domain;

import javax.xml.bind.annotation.XmlRootElement;

import javax.xml.bind.annotation.XmlElement;

import java.util.List;

/**
 * Java class linked to the Users table.
 * @author  intel
 * @version OpenAttestation
 *
 */

@XmlRootElement

public class User
{
    private Long ID ;
    private String Username ;
    private String Password ;
    private Boolean Deleted ;
    
    public User()
    {
    }
    
    public User( String username , String password , Boolean deleted )
    {
        this.Username = username ;
        this.Password = password ;
        this.Deleted = deleted ;
    }

    public Long getID()
    {
        return ID ;
    }
    public void setID( Long iD )
    {
        ID = iD ;
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

    public String getPassword()
    {
        return Password ;
    }

    @XmlElement(name = "Password")
    public void setPassword( String password )
    {
        Password = password ;
    }

    public Boolean getDeleted()
    {
        return Deleted ;
    }

    @XmlElement(name = "Deleted")
    public void setDeleted( Boolean deleted )
    {
        Deleted = deleted ;
    }
}
