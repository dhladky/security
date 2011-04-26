package org.sonatype.security.usermanagement;

import java.util.HashSet;
import java.util.Set;

import org.sonatype.security.authorization.RoleKey;

/**
 * A UserSearchCriteria defines searchble fields. Null or empty fields will be ignored.
 * 
 * @author Brian Demers
 */
public class UserSearchCriteria
{
    private String userId;

    private Set<RoleKey> oneOfRoleIds = new HashSet<RoleKey>();

    private String source;

    private String email;

    public UserSearchCriteria()
    {
    }

    public UserSearchCriteria( String userId )
    {
        this.userId = userId;
    }

    public UserSearchCriteria( String userId, Set<RoleKey> oneOfRoleIds, String source )
    {
        this.userId = userId;
        this.oneOfRoleIds = oneOfRoleIds;
        this.source = source;
    }

    public String getUserId()
    {
        return userId;
    }

    public void setUserId( String userId )
    {
        this.userId = userId;
    }

    public Set<RoleKey> getOneOfRoleIds()
    {
        return oneOfRoleIds;
    }

    public void setOneOfRoleIds( Set<RoleKey> oneOfRoleIds )
    {
        this.oneOfRoleIds = oneOfRoleIds;
    }

    public String getSource()
    {
        return source;
    }

    public void setSource( String source )
    {
        this.source = source;
    }

    public String getEmail()
    {
        return email;
    }

    public void setEmail( String email )
    {
        this.email = email;
    }

}
