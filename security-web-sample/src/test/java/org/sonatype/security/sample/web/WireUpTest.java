/*
 * Sonatype Nexus (TM) Open Source Version
 * Copyright (c) 2007-2012 Sonatype, Inc.
 * All rights reserved. Includes the third-party code listed at http://links.sonatype.com/products/nexus/oss/attributions.
 *
 * This program and the accompanying materials are made available under the terms of the Eclipse Public License Version 1.0,
 * which accompanies this distribution and is available at http://www.eclipse.org/legal/epl-v10.html.
 *
 * Sonatype Nexus (TM) Professional Version is available from Sonatype, Inc. "Sonatype" and "Sonatype Nexus" are trademarks
 * of Sonatype, Inc. Apache Maven is a trademark of the Apache Software Foundation. M2eclipse is a trademark of the
 * Eclipse Foundation. All other trademarks are the property of their respective owners.
 */

package org.sonatype.security.sample.web;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.MembersInjector;
import com.google.inject.Module;
import com.google.inject.PrivateModule;
import com.google.inject.Provider;
import com.google.inject.Provides;
import com.google.inject.TypeLiteral;
import com.google.inject.binder.AnnotatedBindingBuilder;
import com.google.inject.binder.LinkedBindingBuilder;
import com.google.inject.internal.BindingBuilder;
import com.google.inject.matcher.AbstractMatcher;
import com.google.inject.name.Names;
import com.google.inject.spi.TypeEncounter;
import com.google.inject.spi.TypeListener;
import com.google.inject.util.Modules;
import com.google.inject.util.Providers;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.guice.ShiroModule;
import org.apache.shiro.guice.web.ShiroWebModule;
import org.apache.shiro.mgt.*;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.session.mgt.WebSessionManager;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.sonatype.guice.bean.binders.ParameterKeys;
import org.sonatype.guice.bean.binders.SpaceModule;
import org.sonatype.guice.bean.binders.WireModule;
import org.sonatype.guice.bean.reflect.ClassSpace;
import org.sonatype.guice.bean.reflect.URLClassSpace;
import org.sonatype.inject.BeanScanning;
import org.sonatype.security.DefaultRealmSecurityManager;
import org.sonatype.security.SecuritySystem;
import org.sonatype.security.authentication.FirstSuccessfulModularRealmAuthenticator;
import org.sonatype.security.authorization.ExceptionCatchingModularRealmAuthorizer;
import org.sonatype.security.realms.XmlRolePermissionResolver;
import org.sonatype.security.web.WebRealmSecurityManager;

import javax.servlet.ServletContext;
import java.lang.reflect.Field;
import java.net.URLClassLoader;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static org.easymock.EasyMock.createMock;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

/**
 */
public class WireUpTest
{

    @Test
    public void testSecurityManager()
    {
        Injector injector = Guice.createInjector( getWireModule() );

        SecurityManager securityManager = injector.getInstance( SecurityManager.class );
        assertThat( securityManager, instanceOf( DefaultWebSecurityManager.class ) );

        RealmSecurityManager realmSecurityManager = injector.getInstance( RealmSecurityManager.class );
        assertThat( realmSecurityManager, instanceOf( DefaultWebSecurityManager.class ) );
        assertThat( realmSecurityManager, equalTo( securityManager ) );

        DefaultSecurityManager defaultSecurityManager = (DefaultSecurityManager) realmSecurityManager;
        System.out.println( defaultSecurityManager.getSessionManager() );
        assertThat( defaultSecurityManager.getSessionManager(), instanceOf( DefaultWebSessionManager.class ) );
        DefaultSessionManager sessionManager = (DefaultSessionManager) defaultSecurityManager.getSessionManager();
        assertThat( sessionManager.getSessionDAO(), instanceOf( EnterpriseCacheSessionDAO.class ) );

        assertThat( defaultSecurityManager.getAuthenticator(), instanceOf( FirstSuccessfulModularRealmAuthenticator.class ) );
        assertThat( defaultSecurityManager.getAuthorizer(), instanceOf( ExceptionCatchingModularRealmAuthorizer.class ) );
        ExceptionCatchingModularRealmAuthorizer authorizer = (ExceptionCatchingModularRealmAuthorizer) defaultSecurityManager.getAuthorizer();

        assertThat( authorizer.getRolePermissionResolver(), instanceOf( XmlRolePermissionResolver.class ) );
        
    }

    @Test
    public void testSecurityManagerFromSecuritySystem()
    {
        Injector injector = Guice.createInjector( getWireModule() );
        SecuritySystem securitySystem = injector.getInstance( SecuritySystem.class );

        SecurityManager securityManager = injector.getInstance( SecurityManager.class );

        assertThat( securitySystem.getSecurityManager(), Matchers.equalTo( securityManager ) );
        assertThat( securitySystem.getSecurityManager(), equalTo( (RealmSecurityManager) injector.getInstance( WebSecurityManager.class ) ) );

        assertThat( securityManager, instanceOf( DefaultWebSecurityManager.class ) );
        DefaultSecurityManager realmSecurityManager = (DefaultSecurityManager) securityManager;

        System.out.println( realmSecurityManager.getSessionManager() );
        assertThat( realmSecurityManager.getSessionManager(), instanceOf( DefaultWebSessionManager.class ) );
        DefaultSessionManager sessionManager = (DefaultSessionManager) realmSecurityManager.getSessionManager();
        assertThat( sessionManager.getSessionDAO(), instanceOf( EnterpriseCacheSessionDAO.class ) );

    }


    private Module getWireModule()
    {
        ClassSpace space = new URLClassSpace( getClass().getClassLoader() );
        // order matters, shiro needs to be first
        return new WireModule( getShiroModule(), new SpaceModule( space, BeanScanning.INDEX ), getPropertiesModule() );
//        return new WireModule( new SpaceModule( space, BeanScanning.INDEX ), getShiroModule(), getPropertiesModule() );
    }

    private Module getShiroModule()
    {
        ServletContext servletContext = createMock(ServletContext.class);
        return new ShiroWebModule( servletContext )
        {

            @Override
            protected void configureShiroWeb()
            {

//                bindRealmSecurityManager( bind( SecurityManager.class ) );
                
                bindRealm().to( IniRealm.class );
                bind( SessionDAO.class ).to(EnterpriseCacheSessionDAO.class).asEagerSingleton();

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
//                bindConstant().annotatedWith( Names.named("shiro.authorizer") ).to( ExceptionCatchingModularRealmAuthorizer.class );
                bindListener( ModularRealmAuthorizerTypeListener.MATCHER, new ModularRealmAuthorizerTypeListener() );


            }

//            @Provides
//            Authorizer getAuthorizer()
//            {
//                RolePermissionResolver rolePermissionResolver = getProvider( Injector.class ).get().getInstance( RolePermissionResolver.class );
//                ExceptionCatchingModularRealmAuthorizer authorizer = new ExceptionCatchingModularRealmAuthorizer( Collections.<Realm>emptyList() );
//                authorizer.setRolePermissionResolver( rolePermissionResolver );
//                return authorizer;
//            }

            
            

            @Override
            protected void bindWebSecurityManager( AnnotatedBindingBuilder<? super WebSecurityManager> bind )
            {
                
                try {
                    bind(DefaultWebSecurityManager.class).toConstructor(
                        DefaultWebSecurityManager.class.getConstructor() ).asEagerSingleton();
                } catch (NoSuchMethodException e) {
                    throw new ConfigurationException("This really shouldn't happen.  Either something has changed in Shiro, or there's a bug in " + ShiroModule.class.getSimpleName(), e);
                }
                
                bind.to( DefaultWebSecurityManager.class );
                bind(RealmSecurityManager.class).to( DefaultWebSecurityManager.class );
                expose( RealmSecurityManager.class );
                expose( WebSecurityManager.class );
                

            }

//            private void bindRealmSecurityManager( AnnotatedBindingBuilder<? super SecurityManager> bind )
//            {
//                try {
//                    bind( RealmSecurityManager.class ).toConstructor(DefaultWebSecurityManager.class.getConstructor()).asEagerSingleton();
//                } catch (NoSuchMethodException e) {
//                    throw new ConfigurationException("This really shouldn't happen.  Either something has changed in Shiro, or there's a bug in " + ShiroModule.class.getSimpleName(), e);
//                }
//
//                bind.to( RealmSecurityManager.class );
//                expose( RealmSecurityManager.class );
//            }

            @Override
            protected void bindSessionManager(AnnotatedBindingBuilder<SessionManager> bind) {

                try {
                    bind.toConstructor(DefaultWebSessionManager.class.getConstructor()).asEagerSingleton();
                } catch (NoSuchMethodException e) {
                    throw new ConfigurationException("This really shouldn't happen.  Either something has changed in Shiro, or there's a bug in " + ShiroModule.class.getSimpleName(), e);
                }
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
                Map<String, Object> properties = new HashMap<String, Object>();
                properties.put( "security-xml-file", "target/foo/security.xml" );

                binder().bind( ParameterKeys.PROPERTIES ).toInstance( (Map) properties );
            }
        };

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

    private static class SubClassesOf extends AbstractMatcher<TypeLiteral<?>> {
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
