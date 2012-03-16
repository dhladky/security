/**
 * Copyright (c) 2007-2012 Sonatype, Inc. All rights reserved.
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
package org.sonatype.security.web.guice;

import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.MembersInjector;
import com.google.inject.Provider;
import com.google.inject.TypeLiteral;
import com.google.inject.binder.AnnotatedBindingBuilder;
import com.google.inject.matcher.AbstractMatcher;
import com.google.inject.name.Names;
import com.google.inject.spi.TypeEncounter;
import com.google.inject.spi.TypeListener;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.guice.ShiroModule;
import org.apache.shiro.guice.web.ShiroWebModule;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.FilterChainManager;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.sonatype.security.authentication.FirstSuccessfulModularRealmAuthenticator;
import org.sonatype.security.authorization.ExceptionCatchingModularRealmAuthorizer;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;

/**
 * Extends the ShiroWebModule to configure commonly set commponents, such as, SessionDAO, Authorizer, Authenticator, etc.
 * @since 2.5
 */
public class ShiroWebGuiceModule extends ShiroWebModule
{
    private static String INJECTOR = "INJECTOR";
    
    private final ServletContext servletContext;

    public ShiroWebGuiceModule( ServletContext servletContext )
    {
        super( servletContext );
        this.servletContext = servletContext;
    }

    @Override
    protected void configureShiroWeb()
    {
        // temporarily use this realm
        bindRealm().to( NotConfiguredRealm.class );
        bind( SessionDAO.class ).to( EnterpriseCacheSessionDAO.class ).asEagerSingleton();

        try
        {
            bind( Authorizer.class ).toConstructor( ExceptionCatchingModularRealmAuthorizer.class.getConstructor( Collection.class ) );
        }
        catch ( NoSuchMethodException e )
        {
            throw new ConfigurationException("This really shouldn't happen.  Either something has changed in Shiro, or there's a bug in " + ShiroModule.class.getSimpleName(), e);
        }

        bind( Authenticator.class ).to( FirstSuccessfulModularRealmAuthenticator.class );
        bindListener( ModularRealmAuthorizerTypeListener.MATCHER, new ModularRealmAuthorizerTypeListener() );
    }

    @Override
    protected void bindWebSecurityManager( AnnotatedBindingBuilder<? super WebSecurityManager> bind )
    {
        try {
            bind(DefaultWebSecurityManager.class).toConstructor( DefaultWebSecurityManager.class.getConstructor() ).asEagerSingleton();
        } catch (NoSuchMethodException e) {
            throw new ConfigurationException("This really shouldn't happen.  Either something has changed in Shiro, or there's a bug in " + ShiroModule.class.getSimpleName(), e);
        }

        bind.to( DefaultWebSecurityManager.class );
        bind(RealmSecurityManager.class).to( DefaultWebSecurityManager.class );
        expose( RealmSecurityManager.class );
        expose( WebSecurityManager.class );
    }

    @Override
    protected void bindSessionManager(AnnotatedBindingBuilder<SessionManager> bind)
    {
        try
        {
            bind.toConstructor(DefaultWebSessionManager.class.getConstructor()).asEagerSingleton();
        } catch (NoSuchMethodException e) {
            throw new ConfigurationException("This really shouldn't happen.  Either something has changed in Shiro, or there's a bug in " + ShiroModule.class.getSimpleName(), e);
        }
    }

    /**
     * Binds an AccessControlFilter to a name, and exposes the binding.
     * @param name name to used for the filter.
     * @param accessControlFilter The instance to bind to the name.
     * @return The key use for the binding.
     */
    protected Key<AccessControlFilter> bindAccessControlFilter( final String name, AccessControlFilter accessControlFilter )
    {
        Key<AccessControlFilter> key = Key.get( AccessControlFilter.class, Names.named( name ) );

        this.requestInjection( accessControlFilter );

        bind( key ).toInstance( accessControlFilter );
        expose( key );

        return key;
    }

    /**
     * Allows paths to be protected programaticly, instead of paths configured by calling addFilterChain in the configureShiroWeb() method.
     * TODO: consider a better pattern for this.
     * NOTE: This method is NOT called by default!
     */
    protected void configureFilterChainManager()
    {
        bind( FilterChainManager.class ).toProvider( FilterChainManagerProvider.class ).in( Singleton.class);// asEagerSingleton();
        try
        {
            bind( FilterChainResolver.class ).toConstructor( PathMatchingFilterChainResolver.class.getConstructor() ).asEagerSingleton();
        }
        catch ( NoSuchMethodException e )
        {
            throw new ConfigurationException("This really shouldn't happen.  Either something has changed in Shiro, or there's a bug in " + ShiroModule.class.getSimpleName(), e);
        }

        expose( FilterChainManager.class );
    }

    /**
     * Provider that will configure a DefaultFilterChainManager, with a map of {@link AccessControlFilter}s.
     */
    private static class FilterChainManagerProvider implements Provider<FilterChainManager>
    {

        private final Map<String, AccessControlFilter> filterMap;
        private final ServletContext servletContext;

        @Inject
        public FilterChainManagerProvider( Map<String, AccessControlFilter> filterMap, @Named( "SHIRO" )ServletContext servletContext, Provider<Injector> injectorProvider )
        {
            this.filterMap = filterMap;
            this.servletContext = servletContext;
            servletContext.setAttribute( ShiroWebGuiceModule.INJECTOR, injectorProvider.get() );
        }

        @Override
        public FilterChainManager get()
        {
            DefaultFilterChainManager filterChainManager = new DefaultFilterChainManager( new SimpleFilterConfig( "SHIRO", servletContext ));

            for( Map.Entry<String, AccessControlFilter> entry : filterMap.entrySet() )
            {
                filterChainManager.addFilter( entry.getKey(), entry.getValue(), true );
            }
            return filterChainManager;
        }
    }

    /**
     * TypeListener that will inject a {@link RolePermissionResolver} into a {@link ModularRealmAuthorizer}.
     * This is needed because the default shiro-guice module will only automatically inject members in the org.apache.shiro package.
     * TODO: There must be a more simple way to do this.
     * <BR/>
     * NOTE: the need for this class should be removed in Shiro 1.3.
     */
    private static class ModularRealmAuthorizerTypeListener implements TypeListener
    {
        private static Class<ModularRealmAuthorizer> clazz = ModularRealmAuthorizer.class;
        private static com.google.inject.matcher.Matcher MATCHER = new SubClassesOf( clazz );

        private Provider<Injector> injectorProvider;

        @Override
        public <I> void hear( TypeLiteral<I> type, TypeEncounter<I> encounter )
        {
            injectorProvider = encounter.getProvider( Injector.class );

            if( clazz.isAssignableFrom( type.getRawType() ))
            {
                encounter.register( new MembersInjector<I>()
                {
                    @Override
                    public void injectMembers( I instance )
                    {
                        RolePermissionResolver rolePermissionResolver =
                            injectorProvider.get().getInstance( RolePermissionResolver.class );

                        //make sure instance is actually a ModularRealmAuthorizer
                        if ( clazz.isInstance( instance ) )
                        {
                            clazz.cast( instance ).setRolePermissionResolver( rolePermissionResolver );
                        }
                    }
                } );
            }

        }
    }

    /**
     * Simple work around for TypeListener above.
     */
    private static class SubClassesOf extends AbstractMatcher<TypeLiteral<?>>
    {
        private final Class<?> baseClass;

        private SubClassesOf(Class<?> baseClass)
        {
            this.baseClass = baseClass;
        }

        @Override
        public boolean matches(TypeLiteral<?> t)
        {
            return baseClass.isAssignableFrom( t.getRawType() );
        }
    }

    /**
     * Realm loaded at start to fulfill having a realm bound.  This is NOT used once security has been started.
     */
    private static class NotConfiguredRealm extends AuthorizingRealm
    {
        @Override
        protected AuthorizationInfo doGetAuthorizationInfo( PrincipalCollection principals )
        {
            return null;
        }

        @Override
        protected AuthenticationInfo doGetAuthenticationInfo( AuthenticationToken token )
            throws AuthenticationException
        {
            return null;
        }
    }

    /**
     * Work around for legacy code that relies on initializing when onFilterConfigSet() method is called, on an AccessControlFilter.
     */
    private static class SimpleFilterConfig implements FilterConfig
    {
        private final String name;

        private final ServletContext servletContext;

        private SimpleFilterConfig( String name, ServletContext servletContext )
        {
            this.servletContext = servletContext;
            this.name = name;
        }

        @Override
        public String getFilterName()
        {
            return name;
        }

        @Override
        public ServletContext getServletContext()
        {
            return servletContext;
        }

        @Override
        public String getInitParameter( String s )
        {
            return null;
        }

        @Override
        public Enumeration getInitParameterNames()
        {
            return null;
        }
    }
}
