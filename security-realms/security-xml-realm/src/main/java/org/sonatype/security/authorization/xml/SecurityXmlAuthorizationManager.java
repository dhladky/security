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
package org.sonatype.security.authorization.xml;

import static org.sonatype.security.util.ModelConversion.toPrivilege;
import static org.sonatype.security.util.ModelConversion.toRole;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.sonatype.configuration.validation.InvalidConfigurationException;
import org.sonatype.plexus.appevents.ApplicationEventMulticaster;
import org.sonatype.security.authorization.AuthorizationManager;
import org.sonatype.security.authorization.NoSuchPrivilegeException;
import org.sonatype.security.authorization.NoSuchRoleException;
import org.sonatype.security.authorization.Privilege;
import org.sonatype.security.authorization.Role;
import org.sonatype.security.events.AuthorizationConfigurationChangedEvent;
import org.sonatype.security.model.CPrivilege;
import org.sonatype.security.model.CProperty;
import org.sonatype.security.model.CRole;
import org.sonatype.security.realms.tools.ConfigurationManager;
/**
 * AuthorizationManager that wraps roles from security-xml-realm.
 */
@Singleton
@Typed( value = AuthorizationManager.class )
@Named( value = "default" )
public class SecurityXmlAuthorizationManager
    implements AuthorizationManager
{

    public static final String SOURCE = "default";

    @Inject
    @Named( value = "resourceMerging" )
    private ConfigurationManager configuration;
    
    @Inject
    private PrivilegeInheritanceManager privInheritance;
    
    @Inject
    private ApplicationEventMulticaster eventMulticaster;

    public String getSource()
    {
        return SOURCE;
    }


    // //
    // ROLE CRUDS
    // //

    public Set<Role> listRoles()
    {
        Set<Role> roles = new HashSet<Role>();
        List<CRole> secRoles = this.configuration.listRoles();

        for ( CRole CRole : secRoles )
        {
            roles.add( toRole( CRole ) );
        }

        return roles;
    }

    public Role getRole( String roleId, String source )
        throws NoSuchRoleException
    {
        return toRole( this.configuration.readRole( roleId, source ) );
    }

    public Role addRole( Role role )
        throws InvalidConfigurationException
    {
        // the roleId of the secRole might change, so we need to keep the reference
        CRole secRole = toRole( role );

        this.configuration.createRole( secRole );
        this.saveConfiguration();

        return toRole( secRole );
    }

    public Role updateRole( Role role )
        throws NoSuchRoleException,
            InvalidConfigurationException
    {
        CRole secRole = toRole( role );

        this.configuration.updateRole( secRole );
        this.saveConfiguration();

        return toRole( secRole );
    }

    public void deleteRole( String roleId, String source )
        throws NoSuchRoleException
    {
        this.configuration.deleteRole( roleId, source );
        this.saveConfiguration();
    }

    // //
    // PRIVILEGE CRUDS
    // //

    public Set<Privilege> listPrivileges()
    {
        Set<Privilege> privileges = new HashSet<Privilege>();
        List<CPrivilege> secPrivs = this.configuration.listPrivileges();

        for ( CPrivilege CPrivilege : secPrivs )
        {
            privileges.add( toPrivilege( CPrivilege ) );
        }

        return privileges;
    }

    public Privilege getPrivilege( String privilegeId )
        throws NoSuchPrivilegeException
    {
        return toPrivilege( this.configuration.readPrivilege( privilegeId ) );
    }

    public Privilege addPrivilege( Privilege privilege )
        throws InvalidConfigurationException
    {
        CPrivilege secPriv = toPrivilege( privilege );
        // create implies read, so we need to add logic for that
        addInheritedPrivileges( secPriv ); 
        
        this.configuration.createPrivilege( secPriv );
        this.saveConfiguration();

        return toPrivilege( secPriv );
    }

    public Privilege updatePrivilege( Privilege privilege )
        throws NoSuchPrivilegeException,
            InvalidConfigurationException
    {
        CPrivilege secPriv = toPrivilege( privilege );
        this.configuration.updatePrivilege( secPriv );
        this.saveConfiguration();

        return toPrivilege( secPriv );
    }

    public void deletePrivilege( String privilegeId )
        throws NoSuchPrivilegeException
    {
        this.configuration.deletePrivilege( privilegeId );
        this.saveConfiguration();
    }

    private void saveConfiguration()
    {
        this.configuration.save();
        
        // notify any listeners that the config changed
        this.fireAuthorizationChangedEvent();
    }

    public boolean supportsWrite()
    {
        return true;
    }
    
    
    private void addInheritedPrivileges( CPrivilege privilege )
    {
        CProperty methodProperty = null;

        for ( CProperty property : privilege.getProperties() )
        {
            if ( property.getKey().equals( "method" ) )
            {
                methodProperty = property;
                break;
            }
        }

        if ( methodProperty != null )
        {
            List<String> inheritedMethods = privInheritance.getInheritedMethods( methodProperty.getValue() );

            StringBuffer buf = new StringBuffer();

            for ( String method : inheritedMethods )
            {
                buf.append( method );
                buf.append( "," );
            }

            if ( buf.length() > 0 )
            {
                buf.setLength( buf.length() - 1 );

                methodProperty.setValue( buf.toString() );
            }
        }
    }
    
    private void fireAuthorizationChangedEvent()
    {
        this.eventMulticaster.notifyEventListeners( new AuthorizationConfigurationChangedEvent(null) );
    }

}
