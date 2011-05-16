package org.sonatype.security.model.upgrade;

import java.io.File;

import org.codehaus.plexus.util.FileUtils;
import org.sonatype.security.model.AbstractSecurityConfigTest;
import org.sonatype.security.model.Configuration;

public class SecurityDataUpgraderTest
    extends AbstractSecurityConfigTest
{

    protected SecurityConfigurationUpgrader configurationUpgrader;

    @Override
    public void setUp()
        throws Exception
    {
        super.setUp();

        FileUtils.cleanDirectory( new File( getSecurityConfiguration() ).getParentFile() );

        this.configurationUpgrader = lookup( SecurityConfigurationUpgrader.class );
    }

    public void testFrom100()
        throws Exception
    {
        copyFromClasspathToFile( "/org/sonatype/security/model/upgrade/data-upgrade/security.xml", getSecurityConfiguration() );

        Configuration configuration = configurationUpgrader
            .loadOldConfiguration( new File( getSecurityConfiguration() ) );

        assertEquals( Configuration.MODEL_VERSION, configuration.getVersion() );

        resultIsFine( "/org/sonatype/security/model/upgrade/data-upgrade/security.xml", configuration );
    }

}
