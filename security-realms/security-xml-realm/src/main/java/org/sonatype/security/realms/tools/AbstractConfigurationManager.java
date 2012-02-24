package org.sonatype.security.realms.tools;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.security.model.Configuration;

import com.google.inject.Inject;

public abstract class AbstractConfigurationManager
    implements ConfigurationManager
{
    private Logger logger = LoggerFactory.getLogger( getClass() );

    protected Logger getLogger()
    {
        return logger;
    }

    //

    private volatile EnhancedConfiguration configuration = null;

    public synchronized void clearCache()
    {
        configuration = null;
    }

    protected synchronized EnhancedConfiguration getConfiguration()
    {
        if ( configuration != null )
        {
            return configuration;
        }

        final Configuration newConfiguration = doGetConfiguration();

        // enhancing it
        this.configuration = new EnhancedConfiguration( newConfiguration );

        return this.configuration;
    }

    protected abstract Configuration doGetConfiguration();
}
