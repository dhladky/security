package org.sonatype.security.sample.web;

import java.io.IOException;
import java.net.URLClassLoader;
import java.util.Collection;
import java.util.Map;
import java.util.Properties;

import javax.inject.Named;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;

import com.google.inject.Binder;
import com.google.inject.Key;
import com.google.inject.MembersInjector;
import com.google.inject.PrivateModule;
import com.google.inject.Provider;
import com.google.inject.Provides;
import com.google.inject.TypeLiteral;
import com.google.inject.binder.AnnotatedBindingBuilder;
import com.google.inject.matcher.AbstractMatcher;
import com.google.inject.name.Names;
import com.google.inject.servlet.ServletModule;
import com.google.inject.spi.TypeEncounter;
import com.google.inject.spi.TypeListener;
import com.google.sitebricks.SitebricksServletModule;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authc.pam.FirstSuccessfulStrategy;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.guice.ShiroModule;
import org.apache.shiro.guice.web.GuiceShiroFilter;
import org.apache.shiro.guice.web.ShiroWebModule;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.web.filter.authz.HttpMethodPermissionFilter;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.slf4j.Logger;
import org.sonatype.guice.bean.binders.ParameterKeys;
import org.sonatype.guice.bean.binders.SpaceModule;
import org.sonatype.guice.bean.binders.WireModule;
import org.sonatype.guice.bean.reflect.ClassSpace;
import org.sonatype.guice.bean.reflect.URLClassSpace;
import org.sonatype.inject.BeanScanning;
import org.sonatype.plexus.appevents.Event;
import org.sonatype.plexus.appevents.EventListener;
import org.sonatype.plexus.appevents.EventMulticaster;
import org.sonatype.security.SecuritySystem;
import org.sonatype.security.authentication.FirstSuccessfulModularRealmAuthenticator;
import org.sonatype.security.authorization.ExceptionCatchingModularRealmAuthorizer;
import org.sonatype.security.realms.XmlRolePermissionResolver;
import org.sonatype.security.sample.web.services.SampleService;
import org.sonatype.security.web.ShiroSecurityFilter;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Module;
import com.google.inject.servlet.GuiceServletContextListener;
import com.google.sitebricks.SitebricksModule;
import org.sonatype.security.web.WebRealmSecurityManager;

public class SampleGuiceServletConfig
    extends GuiceServletContextListener
{
    private Injector injector = null;

    private ShiroWebModule shiroWebModule;

    @Override
    protected Injector getInjector()
    {
        if ( injector == null )
        {
            injector = Guice.createInjector( getWireModule() );
        }

        return injector;
    }

    @Override
    public void contextInitialized( ServletContextEvent servletContextEvent )
    {
        shiroWebModule = getShiroModule( servletContextEvent.getServletContext() );

        servletContextEvent.getServletContext().setAttribute( ShiroSecurityFilter.INJECTORY_KEY, getInjector() );
        super.contextInitialized( servletContextEvent );

//        getInjector().createChildInjector( shiroWebModule );

        // start security?
        WebSecurityManager realmSecurityManager = getInjector().getInstance( WebSecurityManager.class );
        SecuritySystem securitySystem = getInjector().getInstance( SecuritySystem.class );
        securitySystem.start();

        assert( securitySystem.getSecurityManager() == realmSecurityManager ) : "SecuritySystem.securityManager != WebSecurityManager singleton";

    }

    protected Module getWireModule()
    {
        ClassSpace space = new URLClassSpace( getClass().getClassLoader() );

        // order matters shiro needs to be first
        return new WireModule( shiroWebModule, new SpaceModule( space, BeanScanning.INDEX ), getPropertiesModule(), getSitebricksModule() );
    }

    protected ShiroWebModule getShiroModule( ServletContext servletContext )
    {
        return new ShiroWebModule( servletContext )
        {

            @Override
            protected void configureShiroWeb()
            {
                bindRealm().to( IniRealm.class );
                bind( SessionDAO.class ).to(EnterpriseCacheSessionDAO.class).asEagerSingleton();
                bind( PERMS ).to( HttpMethodPermissionFilter.class );
                

                addFilterChain( "/test", AUTHC_BASIC, config( REST, "sample:priv-name" ) );
                addFilterChain( "/**", AUTHC_BASIC, config( REST, "sample:permToCatchAllUnprotecteds" ) );


                try
                {
                    bind( Authorizer.class ).toConstructor(
                        ExceptionCatchingModularRealmAuthorizer.class.getConstructor( Collection.class ) );
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
                try
                {
                    bind( DefaultWebSecurityManager.class ).toConstructor(
                        DefaultWebSecurityManager.class.getConstructor() ).asEagerSingleton();
                }
                catch ( NoSuchMethodException e )
                {
                    throw new ConfigurationException(
                        "This really shouldn't happen.  Either something has changed in Shiro, or there's a bug in "
                            + ShiroModule.class.getSimpleName(), e );
                }

                bind.to( DefaultWebSecurityManager.class );
                bind( RealmSecurityManager.class ).to( DefaultWebSecurityManager.class );
                expose( RealmSecurityManager.class );
                expose( WebSecurityManager.class );
            }

            @Override
            protected void bindSessionManager( AnnotatedBindingBuilder<SessionManager> bind )
            {
                try {
                    bind.toConstructor(DefaultWebSessionManager.class.getConstructor()).asEagerSingleton();
                } catch (NoSuchMethodException e) {
                    throw new ConfigurationException("This really shouldn't happen.  Either something has changed in Shiro, or there's a bug in " + ShiroModule.class.getSimpleName(), e);
                }
            }
        };
    }

    protected SitebricksModule getSitebricksModule()
    {
        return new SitebricksModule()
        {
            @Override
            protected void configureSitebricks()
            {
                scan( SampleService.class.getPackage() );
            }

            @Override
            protected SitebricksServletModule servletModule()
            {
                return new SitebricksServletModule()
                {
                    protected void configurePreFilters()
                    {
                        filter("/*").through(GuiceShiroFilter.class);
                    }
                };
            }
        };
    }

    protected AbstractModule getPropertiesModule()
    {
        return new AbstractModule()
        {
            @SuppressWarnings( { "rawtypes", "unchecked" } )
            @Override
            protected void configure()
            {
                Properties properties = getProperties();

                binder().bind( ParameterKeys.PROPERTIES ).toInstance( (Map) properties );
            }
        };

    }

    protected Properties getProperties()
    {
        Properties properties = new Properties();
        try
        {
            properties.load( getClass().getClassLoader().getResourceAsStream( "config.properties" ) );
        }
        catch ( IOException e )
        {
        }

        return properties;
    }

    static class ModularRealmAuthorizerTypeListener implements TypeListener
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
                        System.out.println( "Injecting Members: " + instance );

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

    private static class SubClassesOf extends AbstractMatcher<TypeLiteral<?>>
    {
        private final Class<?> baseClass;

        private SubClassesOf(Class<?> baseClass) {
            this.baseClass = baseClass;
        }

        @Override
        public boolean matches(TypeLiteral<?> t) {
            return baseClass.isAssignableFrom( t.getRawType() );
        }
    }
}
