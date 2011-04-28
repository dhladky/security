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
package org.sonatype.security.model.upgrade;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.List;

import javax.enterprise.inject.Typed;
import javax.inject.Named;
import javax.inject.Singleton;

import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.sonatype.configuration.upgrade.ConfigurationIsCorruptedException;
import org.sonatype.configuration.upgrade.UpgradeMessage;
import org.sonatype.security.model.CRole;
import org.sonatype.security.model.CRoleKey;
import org.sonatype.security.model.CUserRoleMapping;
import org.sonatype.security.model.v2_0_4.io.xpp3.SecurityConfigurationXpp3Reader;
import org.sonatype.security.model.v2_4_0.upgrade.BasicVersionUpgrade;

@Singleton
@Typed( value = SecurityUpgrader.class )
@Named( value = "2.0.4" )
public class Upgrade204to240
    implements SecurityUpgrader
{
    public Object loadConfiguration( File file )
        throws IOException, ConfigurationIsCorruptedException
    {
        FileReader fr = null;
        // reading without interpolation to preserve user settings as variables
        try
        {
            fr = new FileReader( file );
            return loadConfiguration( fr );
        }
        finally
        {
            if ( fr != null )
            {
                fr.close();
            }
        }
    }
    
    @Override
    public Object loadConfiguration( Reader fr )
        throws IOException, ConfigurationIsCorruptedException
    {
        try
        {
            SecurityConfigurationXpp3Reader reader = new SecurityConfigurationXpp3Reader();

            return reader.read( fr );
        }
        catch ( XmlPullParserException e )
        {
            throw new ConfigurationIsCorruptedException( fr.toString(), e );
        }
    }

    public void upgrade( UpgradeMessage message )
        throws ConfigurationIsCorruptedException
    {
        org.sonatype.security.model.v2_0_4.Configuration oldc =
            (org.sonatype.security.model.v2_0_4.Configuration) message.getConfiguration();

        org.sonatype.security.model.Configuration newc = new SecurityVersionUpgrade().upgradeConfiguration( oldc );
        
        newc.setVersion( org.sonatype.security.model.Configuration.MODEL_VERSION );
        message.setModelVersion( org.sonatype.security.model.Configuration.MODEL_VERSION );
        message.setConfiguration( newc );
    }

    class SecurityVersionUpgrade
        extends BasicVersionUpgrade
    {
        @Override
        public CRole upgradeCRole( org.sonatype.security.model.v2_0_4.CRole cRole )
        {
            CRole role = super.upgradeCRole( cRole );
            role.setKey( toKey( cRole.getId() ) );

            List<String> roles = cRole.getRoles();
            for ( String roleId : roles )
            {
                role.addRole( toKey( roleId ) );
            }
            return role;
        }

        private CRoleKey toKey( String roleId )
        {
            CRoleKey key = new CRoleKey();
            key.setId( roleId );
            key.setSource( getSource( roleId ) );
            return key;
        }

        @Override
        public CUserRoleMapping upgradeCUserRoleMapping( org.sonatype.security.model.v2_0_4.CUserRoleMapping cUserRoleMapping )
        {
            final CUserRoleMapping userMapping = super.upgradeCUserRoleMapping( cUserRoleMapping );
            List<String> roles = cUserRoleMapping.getRoles();
            for ( String roleId : roles )
            {
                userMapping.addRole( toKey( roleId ) );
            }
            return userMapping;
        }

        private String getSource( String roleId )
        {
            // TODO Auto-generated method stub
            return "default";
        }
    }


}
