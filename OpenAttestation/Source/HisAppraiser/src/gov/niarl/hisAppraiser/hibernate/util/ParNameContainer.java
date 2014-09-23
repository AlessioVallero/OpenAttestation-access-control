/*
Copyright (C) 2014 Politecnico di Torino, Italy
TORSEC group -- http://security.polito.it
*/

package gov.niarl.hisAppraiser.hibernate.util;

public class ParNameContainer
{
    private String ParNameName ;
    private String ParNameValue ;

    public ParNameContainer( String parNameName , String parNameValue )
    {
        ParNameName = parNameName ;
        ParNameValue = parNameValue ;
    }

    public String getParNameName()
    {
        return ParNameName ;
    }

    public String getParNameValue()
    {
        return ParNameValue ;
    }
}
