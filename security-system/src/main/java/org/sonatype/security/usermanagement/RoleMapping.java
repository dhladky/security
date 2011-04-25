package org.sonatype.security.usermanagement;

import java.util.Set;

/**
 * Identifies a role and what source it comes from. Its basically a just a complex key for a role.
 * 
 * @author Brian Demers
 */
public class RoleMapping
{

    private RoleIdentifier roleId;

    private Set<RoleIdentifier> roles;

    private String source;

    /**
     * @param source
     * @param roleId
     */
    public RoleMapping( String source, RoleIdentifier roleId, Set<RoleIdentifier> roles )
    {
        this.source = source;
        this.roleId = roleId;
        this.roles = roles;
    }

    public RoleIdentifier getRoleId()
    {
        return roleId;
    }

    public Set<RoleIdentifier> getRoles()
    {
        return roles;
    }

    public String getSource()
    {
        return source;
    }

    public void setRoleId( RoleIdentifier roleId )
    {
        this.roleId = roleId;
    }

    public void setRoles( Set<RoleIdentifier> roles )
    {
        this.roles = roles;
    }

    public void setSource( String source )
    {
        this.source = source;
    }


    @Override
    public String toString()
    {
        return "source: " + this.source + ", roleId: " + this.roleId;
    }

}
