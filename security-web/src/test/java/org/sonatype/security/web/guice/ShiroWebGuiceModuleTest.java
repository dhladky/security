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

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Module;
import org.apache.shiro.guice.web.GuiceShiroFilter;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.filter.authz.HttpMethodPermissionFilter;
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.FilterChainManager;
import org.apache.shiro.web.filter.mgt.NamedFilterList;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.sonatype.guice.bean.binders.ParameterKeys;
import org.sonatype.guice.bean.binders.SpaceModule;
import org.sonatype.guice.bean.binders.WireModule;
import org.sonatype.guice.bean.reflect.ClassSpace;
import org.sonatype.guice.bean.reflect.URLClassSpace;
import org.sonatype.inject.BeanScanning;
import org.sonatype.security.SecuritySystem;
import org.sonatype.sisu.ehcache.CacheManagerComponent;

import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.ServletContext;
import java.util.HashMap;
import java.util.Map;

import static org.easymock.EasyMock.createMock;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;

/**
 * Verifies functionality of ShiroWebGuiceModule.
 * @since 2.5
 */
public class ShiroWebGuiceModuleTest
{
    private Injector injector;

    @Before
    public void setUp()
    {
        injector = Guice.createInjector( getWireModule() );
    }

    @Test
    public void testInjectionIsSetupCorrectly()
    {

        SecuritySystem securitySystem = injector.getInstance( SecuritySystem.class );

        SecurityManager securityManager = injector.getInstance( SecurityManager.class );

        assertThat( securitySystem.getSecurityManager(), Matchers.equalTo( securityManager ) );
        assertThat( securitySystem.getSecurityManager(), equalTo( (RealmSecurityManager) injector.getInstance( WebSecurityManager.class ) ) );

        assertThat( securityManager, instanceOf( DefaultWebSecurityManager.class ) );
        DefaultSecurityManager realmSecurityManager = (DefaultSecurityManager) securityManager;

        assertThat( realmSecurityManager.getSessionManager(), instanceOf( DefaultWebSessionManager.class ) );
        DefaultSessionManager sessionManager = (DefaultSessionManager) realmSecurityManager.getSessionManager();
        assertThat( sessionManager.getSessionDAO(), instanceOf( EnterpriseCacheSessionDAO.class ) );

        GuiceShiroFilter guiceFilter = injector.getInstance( GuiceShiroFilter.class );
        assertThat(  guiceFilter.getFilterChainResolver(), instanceOf( PathMatchingFilterChainResolver.class ) );

        PathMatchingFilterChainResolver filterChainResolver = (PathMatchingFilterChainResolver) guiceFilter.getFilterChainResolver();
        assertThat( filterChainResolver.getFilterChainManager(), instanceOf( DefaultFilterChainManager.class ) );
        
        assertThat( filterChainResolver.getFilterChainManager(), equalTo( injector.getInstance( FilterChainManager.class ) ) );

        // now add a protected path
        injector.getInstance( FilterChainManager.class ).createChain( "/service/**", "foobar,perms[sample:priv-name]" );

        NamedFilterList filterList =  filterChainResolver.getFilterChainManager().getChain( "/service/**" );
        assertThat( filterList.get( 0 ), instanceOf( SimpleAccessControlFilter.class ) );
        assertThat(filterList.get( 1 ), instanceOf( HttpMethodPermissionFilter.class ) );
        
        // test that injection of filters works
        assertThat( ((SimpleAccessControlFilter)filterList.get( 0 )).getSecurityXMLFilePath(), equalTo( "target/foo/security.xml" ) );

    }

    @After
    public void stopCache()
    {
        if( injector != null )
        {
            injector.getInstance( CacheManagerComponent.class ).shutdown();
        }
    }


    private Module getWireModule()
    {
        ClassSpace space = new URLClassSpace( getClass().getClassLoader() );
        // order matters, shiro needs to be first
        return new WireModule( getShiroModule(), new SpaceModule( space, BeanScanning.INDEX ), getPropertiesModule() );
    }

    private Module getShiroModule()
    {
        ServletContext servletContext = createMock( ServletContext.class );
        return new ShiroWebGuiceModule( servletContext )
        {
            @Override
            protected void configureShiroWeb()
            {
                super.configureShiroWeb();

                SimpleAccessControlFilter foobar = new SimpleAccessControlFilter();
                foobar.setApplicationName( "Foobar Application" );
                bindAccessControlFilter( "foobar", foobar );
                bindAccessControlFilter( "perms", new HttpMethodPermissionFilter() );

                configureFilterChainManager();
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
    
    private static class SimpleAccessControlFilter extends BasicHttpAuthenticationFilter
    {
        @Inject
        @Named( "${security-xml-file}" )
        private String  securityXMLFilePath;

        public String getSecurityXMLFilePath()
        {
            return securityXMLFilePath;
        }
    }
}
