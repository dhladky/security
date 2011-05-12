package org.sonatype.security.rest.roles.tree;

import javax.enterprise.inject.Typed;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import org.codehaus.enunciate.contract.jaxrs.ResourceMethodSignature;
import org.restlet.Context;
import org.restlet.data.Request;
import org.restlet.data.Response;
import org.restlet.data.Status;
import org.restlet.resource.ResourceException;
import org.restlet.resource.Variant;
import org.sonatype.plexus.rest.resource.PathProtectionDescriptor;
import org.sonatype.plexus.rest.resource.PlexusResource;
import org.sonatype.security.authorization.AuthorizationManager;
import org.sonatype.security.authorization.NoSuchAuthorizationManagerException;
import org.sonatype.security.authorization.NoSuchRoleException;
import org.sonatype.security.authorization.Role;
import org.sonatype.security.authorization.RoleKey;
import org.sonatype.security.rest.model.RoleTreeResource;
import org.sonatype.security.rest.model.RoleTreeResourceResponse;
import org.sonatype.security.usermanagement.User;
import org.sonatype.security.usermanagement.UserNotFoundException;

/**
 * REST resource to retrieve the tree of roles and privileges assigned to a user.
 */
@Singleton
@Typed( value = PlexusResource.class )
@Named( value = "UserRoleTreePlexusResource" )
@Produces( { "application/xml", "application/json" } )
@Consumes( { "application/xml", "application/json" } )
@Path( UserRoleTreePlexusResource.RESOURCE_URI )
public class UserRoleTreePlexusResource
    extends AbstractRoleTreePlexusResource
{

    public static final String RESOURCE_URI = "/role_tree/{" + ID_KEY + "}";

    @Override
    public Object getPayloadInstance()
    {
        return null;
    }

    @Override
    public PathProtectionDescriptor getResourceProtection()
    {
        return new PathProtectionDescriptor( "/role_tree/*", "authcBasic,perms[security:users]" );
    }

    @Override
    public String getResourceUri()
    {
        return RESOURCE_URI;
    }

    /**
     * Retrieves the list of privileges assigned to the user.
     */
    @Override
    @GET
    @ResourceMethodSignature( output = RoleTreeResourceResponse.class )
    public Object get( Context context, Request request, Response response, Variant variant )
        throws ResourceException
    {
        String userId = getId( request );

        try
        {
            RoleTreeResourceResponse responseResource = new RoleTreeResourceResponse();

            AuthorizationManager authzManager = getSecuritySystem().getAuthorizationManager( "default" );

            User user = getSecuritySystem().getUser( userId );

            handleUser( user, authzManager, responseResource );

            return responseResource;
        }
        catch ( UserNotFoundException e )
        {
            throw new ResourceException( Status.CLIENT_ERROR_BAD_REQUEST, "User: " + userId + " could not be found." );
        }
        catch ( NoSuchAuthorizationManagerException e )
        {
            throw new ResourceException( Status.SERVER_ERROR_INTERNAL, "Unable to load default authorization manager" );
        }
    }

    protected void handleUser( User user, AuthorizationManager authzManager, RoleTreeResourceResponse response )
    {
        for ( RoleKey roleKey : user.getRoles() )
        {
            try
            {
                Role role = authzManager.getRole( roleKey.getRoleId(), roleKey.getSource() );

                RoleTreeResource resource = new RoleTreeResource();
                resource.setId( role.getKey().getRoleId() );
                resource.setSource( role.getKey().getSource() );
                resource.setName( role.getName() );
                resource.setType( "role" );
                response.addData( resource );

                handleRole( role, authzManager, response, resource );
            }
            catch ( NoSuchRoleException e )
            {
                getLogger().debug(
                    "Invalid roleId: " + roleKey.getRoleId() + " from source: " + roleKey.getSource() + " not found." );
            }
        }
    }

}
