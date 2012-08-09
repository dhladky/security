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
package org.sonatype.security.realms.kenai;

import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.codehaus.plexus.util.StringUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.restlet.Client;
import org.restlet.Context;
import org.restlet.data.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.appcontext.internal.Preconditions;
import org.sonatype.inject.Description;
import org.sonatype.security.realms.kenai.config.KenaiRealmConfiguration;

@Singleton
@Typed( { Realm.class } )
@Named( "kenai" )
@Description( "Kenai Realm" )
public class KenaiRealm
    extends AuthorizingRealm
{

    private final Logger logger = LoggerFactory.getLogger( getClass() );

    private final KenaiRealmConfiguration kenaiRealmConfiguration;

    private static final int PAGE_SIZE = 200;

    @Inject
    public KenaiRealm( final KenaiRealmConfiguration kenaiRealmConfiguration )
    {
        this.kenaiRealmConfiguration = Preconditions.checkNotNull( kenaiRealmConfiguration );
        // TODO: write another test before enabling this
        // this.setAuthenticationCachingEnabled( true );
    }

    @Override
    public String getName()
    {
        return "kenai";
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo( AuthenticationToken token )
        throws AuthenticationException
    {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;

        AuthenticationInfo authInfo = null;
        String username = upToken.getUsername();
        String pass = String.valueOf( upToken.getPassword() );

        if ( authenticateViaUrl( username, pass ) )
        {
            authInfo = buildAuthenticationInfo( username, upToken.getPassword() );
        }
        else
        {
            throw new AccountException( "User '" + username + "' cannot be authenticated." );
        }

        return authInfo;
    }

    protected AuthenticationInfo buildAuthenticationInfo( Object principal, Object credentials )
    {
        return new SimpleAuthenticationInfo( principal, credentials, getName() );
    }

    private boolean authenticateViaUrl( String username, String password )
    {
        Response response = makeRemoteRequest( username, password );
        try
        {
            if ( response.getStatus().isSuccess() )
            {
                if ( isAuthorizationCachingEnabled() )
                {
                    AuthorizationInfo authorizationInfo =
                        buildAuthorizationInfo( username, password, response.getEntity().getText() );

                    Object authorizationCacheKey =
                        getAuthorizationCacheKey( new SimplePrincipalCollection( username, getName() ) );

                    getAuthorizationCache().put( authorizationCacheKey, authorizationInfo );
                }

                return true;
            }
        }
        catch ( IOException e )
        {
            this.logger.error( "Failed to read response", e );
        }
        catch ( JSONException e )
        {
            this.logger.error( "Failed to read response", e );
        }
        finally
        {
            if ( response != null )
            {
                response.release();
            }
        }

        this.logger.debug( "Failed to authenticate user: {} for url: {} status: {}", new Object[] { username,
            response.getRequest().getResourceRef(), response.getStatus() } );

        return false;
    }

    private AuthorizationInfo buildAuthorizationInfo( String username, String password, String responseText )
        throws JSONException, IOException
    {
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();

        authorizationInfo.addRole( this.kenaiRealmConfiguration.getConfiguration().getDefaultRole() );

        JSONObject jsonObject = buildJsonObject( responseText );

        Set roles = buildRoleSetFromJsonObject( jsonObject );
        authorizationInfo.addRoles( roles );

        while ( ( jsonObject.has( "next" ) ) && ( jsonObject.getString( "next" ) != "null" ) )
        {
            String pagedURL = jsonObject.getString( "next" );
            this.logger.debug( "Next page of Kenai project info: {}", pagedURL );

            Response response = null;
            try
            {
                response = makeRemoteRequest( username, password, pagedURL );
                jsonObject = buildJsonObject( response );
                authorizationInfo.addRoles( buildRoleSetFromJsonObject( jsonObject ) );
            }
            finally
            {
                if ( response != null )
                {
                    response.release();
                }
            }
        }

        return authorizationInfo;
    }

    private JSONObject buildJsonObject( Response response )
        throws JSONException, IOException
    {
        if ( response.getStatus().isSuccess() )
        {
            return buildJsonObject( response.getEntity().getText() );
        }

        throw new AuthenticationException( "Error retrieving response, status code: " + response.getStatus() );
    }

    private JSONObject buildJsonObject( String responseText )
        throws JSONException, IOException
    {
        return new JSONObject( responseText );
    }

    private Set<String> buildRoleSetFromJsonObject( JSONObject jsonObject )
        throws JSONException
    {
        Set<String> roles = new HashSet<String>();
        JSONArray projectArray = jsonObject.getJSONArray( "projects" );

        for ( int ii = 0; ii < projectArray.length(); ii++ )
        {
            JSONObject projectObject = projectArray.getJSONObject( ii );
            if ( !projectObject.has( "name" ) )
                continue;
            String projectName = projectObject.getString( "name" );
            if ( StringUtils.isNotEmpty( projectName ) )
            {
                this.logger.trace( "Found project {} in request", projectName );
                roles.add( projectName );
            }
            else
            {
                this.logger.debug( "Found empty string in json object projects[{}].name", ii );
            }

        }

        return roles;
    }

    private Response makeRemoteRequest( String username, String password )
    {
        return makeRemoteRequest( username, password, this.kenaiRealmConfiguration.getConfiguration().getBaseUrl()
            + "api/projects/mine.json?size=" + 200 );
    }

    private Response makeRemoteRequest( String username, String password, String url )
    {
        Client restClient = new Client( new Context(), Protocol.HTTP );

        ChallengeScheme scheme = ChallengeScheme.HTTP_BASIC;
        ChallengeResponse authentication = new ChallengeResponse( scheme, username, password );

        Request request = new Request();

        request.setResourceRef( url );
        request.setMethod( Method.GET );
        request.setChallengeResponse( authentication );

        Response response = restClient.handle( request );
        this.logger.debug( "User: " + username + " url validation status: " + response.getStatus() );

        return response;
    }

    @Override
    protected Object getAuthorizationCacheKey( PrincipalCollection principals )
    {
        return principals.getPrimaryPrincipal().toString();
    }

    @Override
    public Cache<Object, AuthorizationInfo> getAuthorizationCache()
    {
        Cache cache = super.getAuthorizationCache();
        if ( cache == null )
        {
            return null;
        }
        if ( WrappedNonClearableCache.class.isInstance( cache ) )
        {
            return cache;
        }

        Cache wrappedCache = new WrappedNonClearableCache( cache );
        super.setAuthorizationCache( wrappedCache );
        return super.getAuthorizationCache();
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo( PrincipalCollection principals )
    {
        return null;
    }

    static class WrappedNonClearableCache
        implements Cache<Object, AuthorizationInfo>
    {
        private Cache<Object, AuthorizationInfo> cache;

        WrappedNonClearableCache( Cache<Object, AuthorizationInfo> cache )
        {
            this.cache = cache;
        }

        @Override
        public AuthorizationInfo get( Object key )
            throws CacheException
        {
            return (AuthorizationInfo) this.cache.get( key );
        }

        @Override
        public AuthorizationInfo put( Object key, AuthorizationInfo value )
            throws CacheException
        {
            return (AuthorizationInfo) this.cache.put( key, value );
        }

        @Override
        public AuthorizationInfo remove( Object key )
            throws CacheException
        {
            return (AuthorizationInfo) this.cache.remove( key );
        }

        @Override
        public void clear()
            throws CacheException
        {
        }

        @Override
        public int size()
        {
            return this.cache.size();
        }

        @Override
        public Set<Object> keys()
        {
            return this.cache.keys();
        }

        @Override
        public Collection<AuthorizationInfo> values()
        {
            return this.cache.values();
        }
    }
}
