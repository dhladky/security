package org.sonatype.security.authorization;

public class RoleKey
    implements Comparable<RoleKey>
{

    private String roleId;

    private String source;

    public RoleKey()
    {
        super();
    }

    public RoleKey( String roleId, String source )
    {
        this();
        this.roleId = roleId;
        this.source = source;
    }

    @Override
    public int compareTo( RoleKey o )
    {
        if ( o == null )
        {
            return 1;
        }

        if ( source != null && o.source == null )
        {
            return 1;
        }

        if ( roleId != null && o.roleId == null )
        {
            return 1;
        }

        int result = source.compareTo( o.source );
        if ( result != 0 )
        {
            return result;
        }

        return roleId.compareTo( o.roleId );
    }

    @Override
    public boolean equals( Object obj )
    {
        if ( this == obj )
        {
            return true;
        }
        if ( obj == null )
        {
            return false;
        }
        if ( getClass() != obj.getClass() )
        {
            return false;
        }
        RoleKey other = (RoleKey) obj;
        if ( roleId == null )
        {
            if ( other.roleId != null )
            {
                return false;
            }
        }
        else if ( !roleId.equals( other.roleId ) )
        {
            return false;
        }
        if ( source == null )
        {
            if ( other.source != null )
            {
                return false;
            }
        }
        else if ( !source.equals( other.source ) )
        {
            return false;
        }
        return true;
    }

    public String getRoleId()
    {
        return roleId;
    }

    public String getSource()
    {
        return source;
    }

    @Override
    public int hashCode()
    {
        final int prime = 89;
        int result = 1;
        result = prime * result + ( ( roleId == null ) ? 0 : roleId.hashCode() );
        result = prime * result + ( ( source == null ) ? 0 : source.hashCode() );
        return result;
    }

    public void setRoleId( String roleId )
    {
        this.roleId = roleId;
    }

    public void setSource( String source )
    {
        this.source = source;
    }

}
