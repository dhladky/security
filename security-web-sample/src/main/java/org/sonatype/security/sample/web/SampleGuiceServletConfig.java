package org.sonatype.security.sample.web;

import java.io.IOException;
import java.net.URLClassLoader;
import java.util.Map;
import java.util.Properties;

import javax.inject.Named;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;

import com.google.inject.Binder;
import com.google.inject.Key;
import com.google.inject.PrivateModule;
import com.google.inject.Provides;
import com.google.inject.TypeLiteral;
import com.google.inject.binder.AnnotatedBindingBuilder;
import com.google.inject.name.Names;
import org.apache.shiro.authc.pam.FirstSuccessfulStrategy;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.guice.web.ShiroWebModule;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.slf4j.Logger;
import org.sonatype.guice.bean.binders.ParameterKeys;
import org.sonatype.guice.bean.binders.SpaceModule;
import org.sonatype.guice.bean.binders.WireModule;
import org.sonatype.guice.bean.reflect.ClassSpace;
import org.sonatype.guice.bean.reflect.URLClassSpace;
import org.sonatype.plexus.appevents.Event;
import org.sonatype.plexus.appevents.EventListener;
import org.sonatype.plexus.appevents.EventMulticaster;
import org.sonatype.security.SecuritySystem;
import org.sonatype.security.authentication.FirstSuccessfulModularRealmAuthenticator;
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
//        getInjector().getBinding( SecuritySystem.class ).getProvider().get().start();
    }

    protected Module getWireModule()
    {
        ClassSpace space = new URLClassSpace( (URLClassLoader) getClass().getClassLoader() );

        return new WireModule( new SpaceModule( space ), /*getOtherStuffModule(),*/ shiroWebModule, getPropertiesModule(), getSitebricksModule() );
    }

    protected ShiroWebModule getShiroModule( ServletContext servletContext )
    {
        return new ShiroWebModule( servletContext )
        {
//            private DefaultWebSecurityManager securityManager;
//
//            {
//              securityManager = new DefaultWebSecurityManager();
//
//              DefaultWebSessionManager webSessionManager = new DefaultWebSessionManager();
//              webSessionManager.setSessionDAO( new EnterpriseCacheSessionDAO() );
//              securityManager.setSessionManager( webSessionManager );
//
//              FirstSuccessfulModularRealmAuthenticator realmAuthenticator = new FirstSuccessfulModularRealmAuthenticator();
//              realmAuthenticator.setAuthenticationStrategy( new FirstSuccessfulStrategy() );
//              securityManager.setAuthenticator( realmAuthenticator );
//
//            }


            @Override
            public void configure()
            {
                bind( RolePermissionResolver.class ).to( XmlRolePermissionResolver.class );

                DefaultWebSessionManager webSessionManager = new DefaultWebSessionManager();
                webSessionManager.setSessionDAO( new EnterpriseCacheSessionDAO() );
                
                bind( SessionManager.class ).toInstance( webSessionManager );

                super.configure();
            }

            @Override
            protected void configureShiroWeb()
            {
                bindRealm().to( IniRealm.class );
                

                addFilterChain( "/test", AUTHC_BASIC, PERMS, config( PERMS, "sample:priv-name" ) );
                addFilterChain( "/**", AUTHC_BASIC, PERMS, config( PERMS, "sample:permToCatchAllUnprotecteds" ) );
            }

            @Override
            protected void bindWebSecurityManager( AnnotatedBindingBuilder<? super WebSecurityManager> bind )
            {
                bind.to( WebRealmSecurityManager.class );
//                this.getMembersInjector( WebRealmSecurityManager.class ).injectMembers( getInjector().getInstance( WebRealmSecurityManager.class ) );
//                bind.toInstance( securityManager );
            }
        };
    }

    protected AbstractModule getSitebricksModule()
    {
        return new SitebricksModule()
        {
            @Override
            protected void configureSitebricks()
            {
                scan( SampleService.class.getPackage() );
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
}
