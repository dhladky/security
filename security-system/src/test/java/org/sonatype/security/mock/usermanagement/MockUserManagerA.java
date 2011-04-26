package org.sonatype.security.mock.usermanagement;

import javax.enterprise.inject.Typed;
import javax.inject.Named;
import javax.inject.Singleton;

import org.sonatype.security.authorization.RoleKey;
import org.sonatype.security.usermanagement.DefaultUser;
import org.sonatype.security.usermanagement.UserManager;

@Singleton
@Typed( value = UserManager.class )
@Named( value = "MockUserManagerA" )
public class MockUserManagerA
    extends AbstractMockUserManager

{
    public MockUserManagerA()
    {

        DefaultUser a = new DefaultUser();
        a.setName( "Joe Coder" );
        a.setEmailAddress( "jcoder@sonatype.org" );
        a.setSource( this.getSource() );
        a.setUserId( "jcoder" );
        a.addRole( new RoleKey( "RoleA", getSource() ) );
        a.addRole( new RoleKey( "RoleB", getSource() ) );
        a.addRole( new RoleKey( "RoleC", getSource() ) );

        DefaultUser b = new DefaultUser();
        b.setName( "Christine H. Dugas" );
        b.setEmailAddress( "cdugas@sonatype.org" );
        b.setSource( this.getSource() );
        b.setUserId( "cdugas" );
        b.addRole( new RoleKey( "RoleA", getSource() ) );
        b.addRole( new RoleKey( "RoleB", getSource() ) );
        b.addRole( new RoleKey( "Role1", getSource() ) );

        DefaultUser c = new DefaultUser();
        c.setName( "Patricia P. Peralez" );
        c.setEmailAddress( "pperalez@sonatype.org" );
        c.setSource( this.getSource() );
        c.setUserId( "pperalez" );

        DefaultUser d = new DefaultUser();
        d.setName( "Danille S. Knudsen" );
        d.setEmailAddress( "dknudsen@sonatype.org" );
        d.setSource( this.getSource() );
        d.setUserId( "dknudsen" );

        DefaultUser e = new DefaultUser();
        e.setName( "Anon e Mous" );
        e.setEmailAddress( "anonymous@sonatype.org" );
        e.setSource( this.getSource() );
        e.setUserId( "anonymous-user" );

        this.addUser( a, a.getUserId() );
        this.addUser( b, b.getUserId() );
        this.addUser( c, c.getUserId() );
        this.addUser( d, d.getUserId() );
        this.addUser( e, e.getUserId() );
    }

    public String getSource()
    {
        return "MockUserManagerA";
    }

    public String getAuthenticationRealmName()
    {
        return "MockRealmA";
    }

}
