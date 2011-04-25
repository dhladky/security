/**
 * Copyright (c) 2008 Sonatype, Inc. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package org.sonatype.security.rest.roles;

import java.util.Set;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;

import org.codehaus.enunciate.contract.jaxrs.ResourceMethodSignature;
import org.restlet.Context;
import org.restlet.data.Request;
import org.restlet.data.Response;
import org.restlet.data.Status;
import org.restlet.resource.ResourceException;
import org.restlet.resource.Variant;
import org.sonatype.configuration.validation.InvalidConfigurationException;
import org.sonatype.plexus.rest.resource.PathProtectionDescriptor;
import org.sonatype.plexus.rest.resource.PlexusResource;
import org.sonatype.security.rest.model.ExternalRoleMappingResource;
import org.sonatype.security.rest.model.ExternalRoleMappingResourceResponse;
import org.sonatype.security.usermanagement.RoleIdentifier;
import org.sonatype.security.usermanagement.RoleMapping;
import org.sonatype.security.usermanagement.UserManager;
import org.sonatype.security.usermanagement.xml.SecurityXmlUserManager;

/**
 * REST resource for listing external role mappings. An external role mapping, maps a role of an external source to one
 * of managed by the system, giving a user all the privileges contained in this system role.
 * 
 * @author bdemers
 */
@Singleton
@Typed( value = PlexusResource.class )
@Named( value = "ExternalRoleMappingPlexusResource" )
@Produces( { "application/xml", "application/json" } )
@Consumes( { "application/xml", "application/json" } )
@Path( ExternalRoleMappingPlexusResource.RESOURCE_URI )
public class ExternalRoleMappingPlexusResource
    extends AbstractRolePlexusResource
{

    public static final String SOURCE_ID_KEY = "sourceId";

    public static final String RESOURCE_URI = "/external_role_map/{" + SOURCE_ID_KEY + "}";

    private SecurityXmlUserManager xmlManager;

    @Inject
    public ExternalRoleMappingPlexusResource( UserManager manager )
    {
        xmlManager = (SecurityXmlUserManager) manager;
    }

    @Override
    public Object getPayloadInstance()
    {
        return null;
    }

    @Override
    public PathProtectionDescriptor getResourceProtection()
    {
        return new PathProtectionDescriptor( "/external_role_map/*", "authcBasic,perms[security:roles]" );
    }

    @Override
    public String getResourceUri()
    {
        return RESOURCE_URI;
    }

    /**
     * Retrieves the list of external role mappings.
     * 
     * @param sourceId The Id of the source. A source specifies where the users/roles came from, for example the source
     *            Id of 'LDAP' identifies the users/roles as coming from an LDAP source.
     */
    @Override
    @GET
    @ResourceMethodSignature( output = ExternalRoleMappingResourceResponse.class, pathParams = { @PathParam( value = "sourceId" ) } )
    public Object get( Context context, Request request, Response response, Variant variant )
        throws ResourceException
    {
        String source = this.getSourceId( request );

        try
        {
            Set<RoleMapping> roleMap = xmlManager.getRoleMappings();

            // now put this in a resource
            ExternalRoleMappingResourceResponse result = new ExternalRoleMappingResourceResponse();

            for ( RoleMapping map : roleMap )
            {
                if ( !source.equals( map.getSource() ) )
                {
                    continue;
                }

                ExternalRoleMappingResource resource = new ExternalRoleMappingResource();
                result.addData( resource );
                resource.setDefaultRole( this.securityToRestModel( map.getRoleId() ) );

                for ( RoleIdentifier mappedRole : map.getRoles() )
                {
                    resource.addMappedRole( this.securityToRestModel( mappedRole ) );
                }
            }

            return result;

        }
        catch ( InvalidConfigurationException e )
        {
            throw new ResourceException( Status.CLIENT_ERROR_NOT_FOUND, "Role Source '" + source
                + "' could not be found." );
        }

    }

    protected String getSourceId( Request request )
    {
        return getRequestAttribute( request, SOURCE_ID_KEY );
    }
}
