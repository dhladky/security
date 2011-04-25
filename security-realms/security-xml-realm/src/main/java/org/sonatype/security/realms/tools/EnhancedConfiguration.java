package org.sonatype.security.realms.tools;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import org.sonatype.security.model.CPrivilege;
import org.sonatype.security.model.CRole;
import org.sonatype.security.model.CRoleMapping;
import org.sonatype.security.model.CUser;
import org.sonatype.security.model.CUserRoleMapping;
import org.sonatype.security.model.Configuration;

@SuppressWarnings( "serial" )
public class EnhancedConfiguration
    extends Configuration
{
    private final Configuration delegate;

    public EnhancedConfiguration( final Configuration configuration )
    {
        this.delegate = configuration;

        rebuildId2UsersLookupMap();
        rebuildId2RolesLookupMap();
        rebuildId2PrivilegesLookupMap();
        rebuildId2UserRoleMappingsLookupMap();
        rebuildId2roleMappingsLookupMap();
    }

    // ==

    @Override
    public void addPrivilege( CPrivilege cPrivilege )
    {
        delegate.addPrivilege( cPrivilege );

        id2privileges.put( cPrivilege.getId(), cPrivilege );
    }

    @Override
    public void addRole( CRole cRole )
    {
        delegate.addRole( cRole );

        id2roles.put( cRole.getId(), cRole );
    }

    @Override
    public void addUser( CUser cUser )
    {
        delegate.addUser( cUser );

        id2users.put( cUser.getId(), cUser );
    }

    @Override
    public void addUserRoleMapping( CUserRoleMapping cUserRoleMapping )
    {
        delegate.addUserRoleMapping( cUserRoleMapping );

        id2userRoleMappings.put( getUserRoleMappingKey( cUserRoleMapping.getUserId(), cUserRoleMapping.getSource() ),
            cUserRoleMapping );
    }

    @Override
    public String getModelEncoding()
    {
        return delegate.getModelEncoding();
    }

    @Override
    public List<CPrivilege> getPrivileges()
    {
        // we are intentionally breaking code that will try to _modify_ the list
        // as the old config manager was before we fixed it
        return Collections.unmodifiableList( delegate.getPrivileges() );
    }

    @Override
    public List<CRole> getRoles()
    {
        // we are intentionally breaking code that will try to _modify_ the list
        // as the old config manager was before we fixed it
        return Collections.unmodifiableList( delegate.getRoles() );
    }

    @Override
    public List<CUserRoleMapping> getUserRoleMappings()
    {
        // we are intentionally breaking code that will try to _modify_ the list
        // as the old config manager was before we fixed it
        return Collections.unmodifiableList( delegate.getUserRoleMappings() );
    }

    @Override
    public List<CUser> getUsers()
    {
        // we are intentionally breaking code that will try to _modify_ the list
        // as the old config manager was before we fixed it
        return Collections.unmodifiableList( delegate.getUsers() );
    }

    @Override
    public String getVersion()
    {
        return delegate.getVersion();
    }

    @Override
    public void removePrivilege( CPrivilege cPrivilege )
    {
        id2privileges.remove( cPrivilege.getId() );

        delegate.removePrivilege( cPrivilege );
    }

    @Override
    public void removeRole( CRole cRole )
    {
        id2roles.remove( cRole.getId() );

        delegate.removeRole( cRole );
    }

    @Override
    public void removeUser( CUser cUser )
    {
        id2users.remove( cUser.getId() );

        delegate.removeUser( cUser );
    }

    @Override
    public void removeUserRoleMapping( CUserRoleMapping cUserRoleMapping )
    {
        id2userRoleMappings.remove( getUserRoleMappingKey( cUserRoleMapping.getUserId(), cUserRoleMapping.getSource() ) );

        delegate.removeUserRoleMapping( cUserRoleMapping );
    }

    @Override
    public void setModelEncoding( String modelEncoding )
    {
        delegate.setModelEncoding( modelEncoding );
    }

    @Override
    public void setPrivileges( List<CPrivilege> privileges )
    {
        delegate.setPrivileges( privileges );

        rebuildId2PrivilegesLookupMap();
    }

    @Override
    public void setRoles( List<CRole> roles )
    {
        delegate.setRoles( roles );

        rebuildId2RolesLookupMap();
    }

    @Override
    public void setUserRoleMappings( List<CUserRoleMapping> userRoleMappings )
    {
        delegate.setUserRoleMappings( userRoleMappings );

        rebuildId2UserRoleMappingsLookupMap();
    }

    @Override
    public void setUsers( List<CUser> users )
    {
        delegate.setUsers( users );

        rebuildId2UsersLookupMap();
    }

    @Override
    public void setVersion( String version )
    {
        delegate.setVersion( version );
    }

    @Override
    public String toString()
    {
        return super.toString() + " delegating to " + delegate.toString();
    }

    // ==
    // Enhancements

    public CUser getUserById( final String id )
    {
        return id2users.get( id );
    }

    public boolean removeUserById( final String id )
    {
        CUser user = getUserById( id );

        if ( user != null )
        {
            delegate.removeUser( user );
            return id2users.remove( id ) != null;
        }
        else
        {
            return false;
        }
    }

    public CRole getRoleById( final String id )
    {
        return id2roles.get( id );
    }

    public boolean removeRoleById( final String id )
    {
        CRole role = getRoleById( id );

        if ( role != null )
        {
            delegate.removeRole( role );
            return id2roles.remove( id ) != null;
        }
        else
        {
            return false;
        }
    }

    public CPrivilege getPrivilegeById( final String id )
    {
        return id2privileges.get( id );
    }

    public boolean removePrivilegeById( final String id )
    {
        CPrivilege privilege = getPrivilegeById( id );

        if ( privilege != null )
        {
            delegate.removePrivilege( privilege );
            return id2privileges.remove( id ) != null;
        }
        else
        {
            return false;
        }
    }

    public CUserRoleMapping getUserRoleMappingByUserId( final String id, final String source )
    {
        return id2userRoleMappings.get( getUserRoleMappingKey( id, source ) );
    }

    public boolean removeUserRoleMappingByUserId( final String id, final String source )
    {
        CUserRoleMapping mapping = getUserRoleMappingByUserId( id, source );

        if ( mapping != null )
        {
            delegate.removeUserRoleMapping( mapping );
            return id2userRoleMappings.remove( getUserRoleMappingKey( id, source ) ) != null;
        }
        else
        {
            return false;
        }
    }

    // ==

    private HashMap<String, CUser> id2users = new HashMap<String, CUser>();

    private HashMap<String, CRole> id2roles = new HashMap<String, CRole>();

    private HashMap<String, CPrivilege> id2privileges = new HashMap<String, CPrivilege>();

    private HashMap<String, CUserRoleMapping> id2userRoleMappings = new HashMap<String, CUserRoleMapping>();

    private HashMap<String, CRoleMapping> id2RoleMappings = new HashMap<String, CRoleMapping>();

    protected void rebuildId2UsersLookupMap()
    {
        id2users.clear();

        for ( CUser user : getUsers() )
        {
            id2users.put( user.getId(), user );
        }
    }

    protected void rebuildId2RolesLookupMap()
    {
        id2roles.clear();

        for ( CRole role : getRoles() )
        {
            id2roles.put( role.getId(), role );
        }
    }

    protected void rebuildId2PrivilegesLookupMap()
    {
        id2privileges.clear();

        for ( CPrivilege privilege : getPrivileges() )
        {
            id2privileges.put( privilege.getId(), privilege );
        }
    }

    protected void rebuildId2UserRoleMappingsLookupMap()
    {
        id2userRoleMappings.clear();

        for ( CUserRoleMapping user2role : getUserRoleMappings() )
        {
            id2userRoleMappings.put( getUserRoleMappingKey( user2role.getUserId(), user2role.getSource() ), user2role );
        }
    }

    protected void rebuildId2roleMappingsLookupMap()
    {
        id2RoleMappings.clear();

        for ( CRoleMapping role2role : getRoleMappings() )
        {
            id2RoleMappings.put( getUserRoleMappingKey( role2role.getSourceRoleId(), role2role.getSource() ), role2role );
        }
    }

    // ==

    protected String getUserRoleMappingKey( final String userId, final String source )
    {
        return userId.toLowerCase() + "|" + source;
    }

    @Override
    public void addRoleMapping( CRoleMapping mapping )
    {
        delegate.addRoleMapping( mapping );

        id2RoleMappings.put( getUserRoleMappingKey( mapping.getSourceRoleId(), mapping.getSource() ), mapping );
    }

    public CRoleMapping getRoleMapping( String roleId, String source )
    {
        return id2RoleMappings.get( getUserRoleMappingKey( roleId, source ) );
    }

    public boolean removeRoleMapping( String roleId, String source )
    {
        CRoleMapping mapping = getRoleMapping( roleId, source );

        if ( mapping != null )
        {
            delegate.removeRoleMapping( mapping );
            return id2RoleMappings.remove( getRoleMapping( roleId, source ) ) != null;
        }
        else
        {
            return false;
        }
    }
}
