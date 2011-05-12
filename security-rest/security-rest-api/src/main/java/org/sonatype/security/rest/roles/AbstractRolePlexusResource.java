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

import org.restlet.data.Reference;
import org.restlet.data.Request;
import org.restlet.data.Status;
import org.restlet.resource.ResourceException;
import org.sonatype.plexus.rest.resource.PlexusResourceException;
import org.sonatype.security.authorization.Role;
import org.sonatype.security.authorization.RoleKey;
import org.sonatype.security.rest.AbstractSecurityPlexusResource;
import org.sonatype.security.rest.model.RoleKeyResource;
import org.sonatype.security.rest.model.RoleResource;

public abstract class AbstractRolePlexusResource
    extends AbstractSecurityPlexusResource
{

    protected static final String ROLE_SOURCE = "default";

    public RoleResource securityToRestModel( Role role, Request request, boolean appendResourceId )
    {
        // and will convert to the rest object
        RoleResource resource = new RoleResource();

        resource.setDescription( role.getDescription() );
        resource.setKey( securityToRestModelKey( role.getKey() ) );
        resource.setName( role.getName() );

        if ( appendResourceId )
        {
            resource.setResourceURI( this.createChildReference( request, resource.getKey() ).toString() );
        }
        else
        {
            resource.setResourceURI( this.createChildReference( request, "" ).toString() );
        }

        resource.setUserManaged( !role.isReadOnly() );

        for ( RoleKey roleId : role.getRoles() )
        {
            resource.addRole( securityToRestModelKey( roleId ) );
        }

        for ( String privId : role.getPrivileges() )
        {
            resource.addPrivilege( privId );
        }

        return resource;
    }

    protected Reference createChildReference( Request request, RoleKeyResource key )
    {
        return this.createChildReference( request, key.getId() ).addSegment( key.getSource() );
    }

    @Override
    protected RoleKeyResource securityToRestModelKey( RoleKey key )
    {
        RoleKeyResource r = new RoleKeyResource();
        r.setId( key.getRoleId() );
        r.setSource( key.getSource() );
        return r;
    }

    public Role restToSecurityModel( Role role, RoleResource resource )
    {
        if ( role == null )
        {
            role = new Role();
        }

        role.setKey( restToSecurityModel( resource.getKey() ) );
        
        role.setDescription( resource.getDescription() );
        role.setName( resource.getName() );

        role.getRoles().clear();
        for ( RoleKeyResource roleId : resource.getRoles() )
        {
            role.addRole( restToSecurityModel( roleId ) );
        }

        role.getPrivileges().clear();
        for ( String privId : resource.getPrivileges() )
        {
            role.addPrivilege( privId );
        }

        return role;
    }


    public void validateRoleContainment( Role role )
        throws ResourceException
    {
        if ( role.getRoles().size() == 0 
            && role.getPrivileges().size() == 0)
        {
            throw new PlexusResourceException( 
                Status.CLIENT_ERROR_BAD_REQUEST, 
                "Configuration error.", 
                getErrorResponse( 
                    "privileges", 
                    "One or more roles/privilegs are required." ) );
        }
    }

}
