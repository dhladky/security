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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Map;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.codehaus.plexus.util.IOUtil;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.codehaus.plexus.util.xml.Xpp3DomBuilder;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.slf4j.Logger;
import org.sonatype.configuration.upgrade.ConfigurationIsCorruptedException;
import org.sonatype.configuration.upgrade.UnsupportedConfigurationVersionException;
import org.sonatype.configuration.upgrade.UpgradeMessage;
import org.sonatype.security.model.Configuration;

/**
 * Default configuration updater, using versioned Modello models. It tried to detect version signature from existing
 * file and apply apropriate modello io stuff to load configuration. It is also aware of changes across model versions.
 * 
 * @author cstamas
 */
@Singleton
@Typed( value = SecurityConfigurationUpgrader.class )
@Named( value = "default" )
public class DefaultSecurityConfigurationUpgrader
    implements SecurityConfigurationUpgrader
{
    @Inject
    private Logger logger;
    
    @Inject
    private Map<String, SecurityUpgrader> upgraders;
    
    @Inject
    private Map<String, SecurityDataUpgrader> dataUpgraders;

    /**
     * This implementation relies to plexus registered upgraders. It will cycle through them until the configuration is
     * the needed (current) model version.
     * @throws  
     */
    public Configuration loadOldConfiguration( File file )
        throws IOException,
            ConfigurationIsCorruptedException,
            UnsupportedConfigurationVersionException
    {
        Reader r = new FileReader( file );

        return loadOldConfiguration( r );
    }

    public Configuration loadOldConfiguration( Reader reader )
        throws IOException, ConfigurationIsCorruptedException, UnsupportedConfigurationVersionException
    {
        byte[] bytes = IOUtil.toByteArray( reader );

        // try to find out the model version
        String modelVersion = null;

        try
        {
            Xpp3Dom dom = Xpp3DomBuilder.build( new InputStreamReader( new ByteArrayInputStream( bytes ) ) );

            modelVersion = dom.getChild( "version" ).getValue();
        }
        catch ( XmlPullParserException e )
        {
            throw new ConfigurationIsCorruptedException( reader.toString(), e );
        }

        if ( Configuration.MODEL_VERSION.equals( modelVersion ) )
        {
            // we have a problem here, model version is OK but we could not load it previously?
            throw new ConfigurationIsCorruptedException( reader.toString() );
        }

        UpgradeMessage msg = new UpgradeMessage();

        msg.setModelVersion( modelVersion );

        SecurityUpgrader upgrader = upgraders.get( msg.getModelVersion() );

        if ( upgrader != null )
                    {
            logger.info( "Upgrading old Security configuration file (version " + msg.getModelVersion() + ") from "
                + reader.toString() );

            msg.setConfiguration( upgrader.loadConfiguration( new InputStreamReader( new ByteArrayInputStream( bytes ) ) ) );

            while ( !Configuration.MODEL_VERSION.equals( msg.getModelVersion() ) )
            {

                // an application might need to upgrade content, that is NOT part of the model
                SecurityDataUpgrader dataUpgrader = this.dataUpgraders.get( msg.getModelVersion() );

                if ( upgrader != null )
                {
                    upgrader.upgrade( msg );

                    if ( dataUpgrader != null )
                    {
                        dataUpgrader.upgrade( msg.getConfiguration() );
                    }
                }
                else
                {
                    // we could parse the XML but have no model version? Is this security config at all?
                    // FIXME
                    throw new UnsupportedConfigurationVersionException( modelVersion, new File( "security.xml" ) );
                }

                upgrader = upgraders.get( msg.getModelVersion() );
            }

            logger.info( "Security configuration file upgraded to current version " + msg.getModelVersion()
                + " succesfully." );

            return (Configuration) msg.getConfiguration();
        }
        else
        {
            // we could parse the XML but have no model version? Is this security config at all?
            // FIXME
            throw new UnsupportedConfigurationVersionException( modelVersion, new File( "security.xml" ) );
        }
    }
}
