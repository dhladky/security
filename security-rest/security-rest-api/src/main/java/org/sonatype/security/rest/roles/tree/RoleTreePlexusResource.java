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
import org.sonatype.security.rest.model.RoleTreeResourceResponse;

/**
 * REST resource to retrieve the tree of roles and privileges assigned to a user.
 */
@Singleton
@Typed( value = PlexusResource.class )
@Named( value = "RoleTreePlexusResource" )
@Produces( { "application/xml", "application/json" } )
@Consumes( { "application/xml", "application/json" } )
@Path( RoleTreePlexusResource.RESOURCE_URI )
public class RoleTreePlexusResource
    extends AbstractRoleTreePlexusResource
{
    public static final String SOURCE_KEY = "source";

    public static final String RESOURCE_URI = "/role_tree/{" + ID_KEY + "}/{" + SOURCE_KEY + "}";

    @Override
    public Object getPayloadInstance()
    {
        return null;
    }

    @Override
    public PathProtectionDescriptor getResourceProtection()
    {
        return new PathProtectionDescriptor( "/role_tree/*/*", "authcBasic,perms[security:users]" );
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
        String roleId = getId( request );
        String source = getSource( request );

        try
        {
            RoleTreeResourceResponse responseResource = new RoleTreeResourceResponse();

            AuthorizationManager authzManager = getSecuritySystem().getAuthorizationManager( "default" );

                Role role = authzManager.getRole( roleId, source );

                handleRole( role, authzManager, responseResource, null );


            return responseResource;
        }
        catch ( NoSuchAuthorizationManagerException e )
        {
            throw new ResourceException( Status.SERVER_ERROR_INTERNAL, "Unable to load default authorization manager" );
        }
        catch ( NoSuchRoleException e )
        {
            throw new ResourceException( Status.CLIENT_ERROR_BAD_REQUEST, "Role: " + roleId + " could not be found." );
        }
    }

    protected String getSource( Request request )
    {
        return getRequestAttribute( request, SOURCE_KEY );
    }
}
