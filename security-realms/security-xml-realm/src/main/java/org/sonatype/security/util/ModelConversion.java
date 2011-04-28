package org.sonatype.security.util;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;

import org.sonatype.security.authorization.Privilege;
import org.sonatype.security.authorization.Role;
import org.sonatype.security.authorization.RoleKey;
import org.sonatype.security.model.CPrivilege;
import org.sonatype.security.model.CProperty;
import org.sonatype.security.model.CRole;
import org.sonatype.security.model.CRoleKey;

public class ModelConversion
{

    public static Role toRole( CRole secRole )
    {
        Role role = new Role();

        role.setKey( toRoleKey( secRole.getKey() ) );
        role.setName( secRole.getName() );
        role.setDescription( secRole.getDescription() );
        role.setReadOnly( secRole.isReadOnly() );
        role.setPrivileges( new HashSet<String>( secRole.getPrivileges() ) );
        role.setRoles( toRoleKey( secRole.getRoles() ) );

        return role;
    }

    public static Set<RoleKey> toRoleKey( List<CRoleKey> roles )
    {
        Set<RoleKey> keys = new LinkedHashSet<RoleKey>();
        for ( CRoleKey cRoleKey : roles )
        {
            keys.add( toRoleKey( cRoleKey ) );
        }
        return keys;
    }

    public static RoleKey toRoleKey( CRoleKey key )
    {
        return new RoleKey( key.getId(), key.getSource() );
    }

    public static CRole toRole( Role role )
    {
        CRole secRole = new CRole();

        secRole.setKey( toRoleKey( role.getKey() ) );
        secRole.setName( role.getName() );
        secRole.setDescription( role.getDescription() );
        secRole.setReadOnly( role.isReadOnly() );
        // null check
        if ( role.getPrivileges() != null )
        {
            secRole.setPrivileges( new ArrayList<String>( role.getPrivileges() ) );
        }
        else
        {
            secRole.setPrivileges( new ArrayList<String>() );
        }

        // null check
        secRole.setRoles( toRoleKey( role.getRoles() ) );

        return secRole;
    }

    public static List<CRoleKey> toRoleKey( Set<RoleKey> roles )
    {
        List<CRoleKey> keys = new ArrayList<CRoleKey>();
        for ( RoleKey key : roles )
        {
            keys.add( toRoleKey( key ) );
        }
        return keys;
    }

    public static CRoleKey toRoleKey( String id, String source )
    {
        CRoleKey ckey = new CRoleKey();
        ckey.setId( id );
        ckey.setSource( source );
        return ckey;
    }

    public static CRoleKey toRoleKey( RoleKey key )
    {
        CRoleKey ckey = new CRoleKey();
        ckey.setId( key.getRoleId() );
        ckey.setSource( key.getSource() );
        return ckey;
    }

    public static CPrivilege toPrivilege( Privilege privilege )
    {
        CPrivilege secPriv = new CPrivilege();
        secPriv.setId( privilege.getId() );
        secPriv.setName( privilege.getName() );
        secPriv.setDescription( privilege.getDescription() );
        secPriv.setReadOnly( privilege.isReadOnly() );
        secPriv.setType( privilege.getType() );

        if ( privilege.getProperties() != null && privilege.getProperties().entrySet() != null )
        {
            for ( Entry<String, String> entry : privilege.getProperties().entrySet() )
            {
                CProperty prop = new CProperty();
                prop.setKey( entry.getKey() );
                prop.setValue( entry.getValue() );
                secPriv.addProperty( prop );
            }
        }

        return secPriv;
    }

    public static Privilege toPrivilege( CPrivilege secPriv )
    {
        Privilege privilege = new Privilege();
        privilege.setId( secPriv.getId() );
        privilege.setName( secPriv.getName() );
        privilege.setDescription( secPriv.getDescription() );
        privilege.setReadOnly( secPriv.isReadOnly() );
        privilege.setType( secPriv.getType() );

        if ( secPriv.getProperties() != null )
        {
            for ( CProperty prop : secPriv.getProperties() )
            {
                privilege.addProperty( prop.getKey(), prop.getValue() );
            }
        }

        return privilege;
    }
}
