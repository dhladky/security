package org.sonatype.security.rest.roles.tree;

import org.restlet.data.Request;
import org.sonatype.security.authorization.AuthorizationManager;
import org.sonatype.security.authorization.NoSuchPrivilegeException;
import org.sonatype.security.authorization.NoSuchRoleException;
import org.sonatype.security.authorization.Privilege;
import org.sonatype.security.authorization.Role;
import org.sonatype.security.authorization.RoleKey;
import org.sonatype.security.rest.AbstractSecurityPlexusResource;
import org.sonatype.security.rest.model.RoleTreeResource;
import org.sonatype.security.rest.model.RoleTreeResourceResponse;

public abstract class AbstractRoleTreePlexusResource
    extends AbstractSecurityPlexusResource
{

    public static final String ID_KEY = "id";

    public AbstractRoleTreePlexusResource()
    {
        super();
    }

    protected String getId( Request request )
    {
        return getRequestAttribute( request, ID_KEY );
    }

    protected void handleRole( Role role, AuthorizationManager authzManager, RoleTreeResourceResponse response, RoleTreeResource resource )
    {
        for ( RoleKey roleId : role.getRoles() )
        {
            try
            {
                Role childRole = authzManager.getRole( roleId.getRoleId(), roleId.getSource() );
                RoleTreeResource childResource = new RoleTreeResource();
                childResource.setId( childRole.getKey().getRoleId() );
                childResource.setSource( childRole.getKey().getSource() );
                childResource.setName( childRole.getName() );
                childResource.setType( "role" );
                if ( resource != null )
                {
                    resource.addChildren( childResource );
                }
                else
                {
                    response.addData( childResource );
                }
                handleRole( childRole, authzManager, response, childResource );
            }
            catch ( NoSuchRoleException e )
            {
                getLogger().debug( "handleRole() failed, roleId: " + roleId + " not found" );
            }
        }
    
        for ( String privilegeId : role.getPrivileges() )
        {
            try
            {
                Privilege childPrivilege = authzManager.getPrivilege( privilegeId );
                RoleTreeResource childResource = new RoleTreeResource();
                childResource.setId( childPrivilege.getId() );
                childResource.setName( childPrivilege.getName() );
                childResource.setType( "privilege" );
                childResource.setSource( "default" );
                if ( resource != null )
                {
                    resource.addChildren( childResource );
                }
                else
                {
                    response.addData( childResource );
                }
            }
            catch ( NoSuchPrivilegeException e )
            {
                getLogger().debug( "handleRole() failed, privilegeId: " + privilegeId + " not found" );
            }
        }
    }

}