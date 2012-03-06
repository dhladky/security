package org.sonatype.security;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.pam.FirstSuccessfulStrategy;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.realm.CachingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.util.Initializable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.inject.Nullable;
import org.sonatype.security.authentication.FirstSuccessfulModularRealmAuthenticator;
import org.sonatype.security.authorization.ExceptionCatchingModularRealmAuthorizer;

import java.util.Collection;

/**
 * Componentize the Shiro DefaultSecurityManager, and sets up caching.
 * 
 * @author Brian Demers
 * @deprecated use shiro-guice or other injection to wire up a RealmSecurityManager.
 */
@Singleton
@Typed( value = RealmSecurityManager.class )
@Named( value = "default" )
@Deprecated
public class DefaultRealmSecurityManager
    extends DefaultSecurityManager
    implements Initializable
{
    private Logger logger = LoggerFactory.getLogger( getClass() );
    private RolePermissionResolver rolePermissionResolver;
    
    @Inject
    public DefaultRealmSecurityManager( @Nullable RolePermissionResolver rolePermissionResolver )
    {
        super();
        this.rolePermissionResolver = rolePermissionResolver;
        init();
    }
    
    public void init()
        throws ShiroException
    {
        this.setSessionManager( new DefaultSessionManager() );

        // This could be injected
        // Authorizer
        ExceptionCatchingModularRealmAuthorizer authorizer =
            new ExceptionCatchingModularRealmAuthorizer( this.getRealms() );

        // if we have a Role Permission Resolver, set it, if not, don't worry about it
        if ( rolePermissionResolver != null )
        {
            authorizer.setRolePermissionResolver( rolePermissionResolver );
            logger.debug( "RolePermissionResolver was set to " + authorizer.getRolePermissionResolver() );
        }
        else
        {
            logger.warn( "No RolePermissionResolver is set" );
        }
        this.setAuthorizer( authorizer );

        // set the realm authenticator, that will automatically deligate the authentication to all the realms.
        FirstSuccessfulModularRealmAuthenticator realmAuthenticator = new FirstSuccessfulModularRealmAuthenticator();
        realmAuthenticator.setAuthenticationStrategy( new FirstSuccessfulStrategy() );

        // Authenticator
        this.setAuthenticator( realmAuthenticator );
    }
}
