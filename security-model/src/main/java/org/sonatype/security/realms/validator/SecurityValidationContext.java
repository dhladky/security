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
package org.sonatype.security.realms.validator;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.sonatype.configuration.validation.ValidationContext;
import org.sonatype.security.model.CRoleKey;

public class SecurityValidationContext implements ValidationContext
{
    private List<String> existingPrivilegeIds;

    private Map<String, List<String>> existingRoleIds;

    private List<String> existingUserIds;

    private Map<String, String> existingEmailMap;

    private Map<CRoleKey, List<CRoleKey>> roleContainmentMap;
    
    private Map<CRoleKey, String> existingRoleNameMap;
    
    private Map<String, List<CRoleKey>> existingUserRoleMap;

    public void addExistingPrivilegeIds()
    {
        if ( this.existingPrivilegeIds == null )
        {
            this.existingPrivilegeIds = new ArrayList<String>();
        }
    }

    public void addExistingRoleIds()
    {
        if ( this.existingRoleIds == null )
        {
            this.existingRoleIds = new LinkedHashMap<String, List<String>>();
        }

        if ( this.roleContainmentMap == null )
        {
            this.roleContainmentMap = new HashMap<CRoleKey, List<CRoleKey>>();
        }
        
        if ( this.existingRoleNameMap == null)
        {
            this.existingRoleNameMap = new HashMap<CRoleKey, String>();
        }
        
        if ( this.existingUserRoleMap == null)
        {
            this.existingUserRoleMap = new HashMap<String, List<CRoleKey>>();
        }
    }

    public void addExistingUserIds()
    {
        if ( this.existingUserIds == null )
        {
            this.existingUserIds = new ArrayList<String>();
        }

        if ( this.existingEmailMap == null )
        {
            this.existingEmailMap = new HashMap<String, String>();
        }
    }

    public List<String> getExistingPrivilegeIds()
    {
        return existingPrivilegeIds;
    }

    public Map<String, List<String>> getExistingRoleIds()
    {
        return existingRoleIds;
    }

    public List<String> getExistingUserIds()
    {
        return existingUserIds;
    }

    public Map<String, String> getExistingEmailMap()
    {
        return existingEmailMap;
    }

    public Map<CRoleKey, List<CRoleKey>> getRoleContainmentMap()
    {
        return roleContainmentMap;
    }

    public Map<CRoleKey, String> getExistingRoleNameMap()
    {
        return existingRoleNameMap;
    }

    public Map<String, List<CRoleKey>> getExistingUserRoleMap()
    {
        return existingUserRoleMap;
    }

    public void addExistingRoleIds( CRoleKey roleKey )
    {
        if ( !existingRoleIds.containsKey( roleKey.getSource() ) )
        {
            existingRoleIds.put( roleKey.getSource(), new ArrayList<String>() );
        }
        existingRoleIds.get( roleKey.getSource() ).add( roleKey.getId() );
    }

}
