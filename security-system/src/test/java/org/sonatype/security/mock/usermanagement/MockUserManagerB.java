package org.sonatype.security.mock.usermanagement;

import javax.enterprise.inject.Typed;
import javax.inject.Named;
import javax.inject.Singleton;

import org.sonatype.security.authorization.RoleKey;
import org.sonatype.security.usermanagement.DefaultUser;
import org.sonatype.security.usermanagement.UserManager;
import org.sonatype.security.usermanagement.UserStatus;

@Singleton
@Typed( value = UserManager.class )
@Named( value = "MockUserManagerB" )
public class MockUserManagerB
    extends AbstractMockUserManager

{
    public MockUserManagerB()
    {

        DefaultUser a = new DefaultUser();
        a.setName( "Brenda D. Burton" );
        a.setEmailAddress( "bburton@sonatype.org" );
        a.setSource( this.getSource() );
        a.setUserId( "bburton" );
        a.setStatus( UserStatus.active );
        a.addRole( new RoleKey( "RoleA", getSource() ) );
        a.addRole( new RoleKey( "RoleB", getSource() ) );
        a.addRole( new RoleKey( "RoleC", getSource() ) );

        DefaultUser b = new DefaultUser();
        b.setName( "Julian R. Blevins" );
        b.setEmailAddress( "jblevins@sonatype.org" );
        b.setSource( this.getSource() );
        b.setUserId( "jblevins" );
        b.setStatus( UserStatus.active );
        b.addRole( new RoleKey( "RoleA", getSource() ) );
        b.addRole( new RoleKey( "RoleB", getSource() ) );

        DefaultUser c = new DefaultUser();
        c.setName( "Kathryn J. Simmons" );
        c.setEmailAddress( "ksimmons@sonatype.org" );
        c.setSource( this.getSource() );
        c.setUserId( "ksimmons" );
        c.setStatus( UserStatus.active );
        c.addRole( new RoleKey( "RoleA", getSource() ) );
        c.addRole( new RoleKey( "RoleB", getSource() ) );

        DefaultUser d = new DefaultUser();
        d.setName( "Florence T. Dahmen" );
        d.setEmailAddress( "fdahmen@sonatype.org" );
        d.setSource( this.getSource() );
        d.setUserId( "fdahmen" );
        d.setStatus( UserStatus.active );
        d.addRole( new RoleKey( "RoleA", getSource() ) );
        d.addRole( new RoleKey( "RoleB", getSource() ) );

        DefaultUser e = new DefaultUser();
        e.setName( "Jill  Codar" );
        e.setEmailAddress( "jcodar@sonatype.org" );
        e.setSource( this.getSource() );
        e.setUserId( "jcodar" );
        e.setStatus( UserStatus.active );

        DefaultUser f = new DefaultUser();
        f.setName( "Joe Coder" );
        f.setEmailAddress( "jcoder@sonatype.org" );
        f.setSource( this.getSource() );
        f.setUserId( "jcoder" );
        f.setStatus( UserStatus.active );
        f.addRole( new RoleKey( "Role1", getSource() ) );
        f.addRole( new RoleKey( "Role2", getSource() ) );
        f.addRole( new RoleKey( "Role3", getSource() ) );

        this.addUser( a, a.getUserId() );
        this.addUser( b, b.getUserId() );
        this.addUser( c, c.getUserId() );
        this.addUser( d, d.getUserId() );
        this.addUser( e, e.getUserId() );
        this.addUser( f, f.getUserId() );
    }

    public String getSource()
    {
        return "MockUserManagerB";
    }


    public String getAuthenticationRealmName()
    {
        return "MockRealmB";
    }
    
}
