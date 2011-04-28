package org.sonatype.security.authorization;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A simple bean that represents a security Role.
 * @author Brian Demers
 *
 */
public class Role implements Comparable<Role>
{
    private RoleKey key;

    public RoleKey getKey()
    {
        return key;
    }

    public void setKey( RoleKey key )
    {
        this.key = key;
    }

    private String name;

    private String description;

    private boolean readOnly;

    private Set<RoleKey> roles;
    
    private Set<String> privileges;
    
    public Role()
    {
        super();
    }
    
    public Role( RoleKey key, String name, String description, boolean readOnly, Set<RoleKey> roles,
                 Set<String> privileges )
    {
        this();
        this.key = key;
        this.name = name;
        this.description = description;
        this.readOnly = readOnly;
        this.roles = roles;
        this.privileges = privileges;
    }



    public String getName()
    {
        return name;
    }

    public void setName( String name )
    {
        this.name = name;
    }

    public Set<RoleKey> getRoles()
    {
        if ( roles == null )
        {
            roles = new LinkedHashSet<RoleKey>();
        }
        return roles;
    }

    public void addRole( RoleKey role )
    {
        getRoles().add( role );
    }
    
    public void setRoles( Set<RoleKey> roles )
    {
        this.roles = roles;
    }

    public Set<String> getPrivileges()
    {
        if ( privileges == null )
        {
            privileges = new LinkedHashSet<String>();
        }
        return privileges;
    }

    public void addPrivilege( String privilege )
    {
        getPrivileges().add( privilege );
    }

    public void setPrivileges( Set<String> privilege )
    {
        this.privileges = privilege;
    }

    public int compareTo( Role o )
    {
        final int before = -1;
        final int equal = 0;
        final int after = 1;

        if ( this == o )
        {
            return equal;
        }

        if ( o == null )
        {
            return after;
        }

        if ( key == null && o.key != null )
        {
            return before;
        }
        else if ( key != null && o.key == null )
        {
            return after;
        }

        // the roleIds are not null
        int result = key.compareTo( o.key );
        if ( result != equal )
        {
            return result;
        }

        // if we are all the way to this point, the RoleIds are equal and this.getSource != null, so just return a
        // compareTo on the source
        return result;
    }

    public String getDescription()
    {
        return description;
    }

    public void setDescription( String description )
    {
        this.description = description;
    }

    public boolean isReadOnly()
    {
        return readOnly;
    }

    public void setReadOnly( boolean readOnly )
    {
        this.readOnly = readOnly;
    }

    @Override
    public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + ( ( description == null ) ? 0 : description.hashCode() );
        result = prime * result + ( ( name == null ) ? 0 : name.hashCode() );
        result = prime * result + ( ( privileges == null ) ? 0 : privileges.hashCode() );
        result = prime * result + ( readOnly ? 1231 : 1237 );
        result = prime * result + ( ( key == null ) ? 0 : key.hashCode() );
        result = prime * result + ( ( roles == null ) ? 0 : roles.hashCode() );
        return result;
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
        Role other = (Role) obj;
        if ( description == null )
        {
            if ( other.description != null )
            {
                return false;
            }
        }
        else if ( !description.equals( other.description ) )
        {
            return false;
        }
        if ( name == null )
        {
            if ( other.name != null )
            {
                return false;
            }
        }
        else if ( !name.equals( other.name ) )
        {
            return false;
        }
        if ( privileges == null )
        {
            if ( other.privileges != null )
            {
                return false;
            }
        }
        else if ( !privileges.equals( other.privileges ) )
        {
            return false;
        }
        if ( readOnly != other.readOnly )
        {
            return false;
        }
        if ( key == null )
        {
            if ( other.key != null )
            {
                return false;
            }
        }
        else if ( !key.equals( other.key ) )
        {
            return false;
        }
        if ( roles == null )
        {
            if ( other.roles != null )
            {
                return false;
            }
        }
        else if ( !roles.equals( other.roles ) )
        {
            return false;
        }

        return true;
    }

    
}
