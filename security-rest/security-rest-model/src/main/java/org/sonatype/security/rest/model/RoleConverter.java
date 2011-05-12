package org.sonatype.security.rest.model;

import java.util.List;

import com.thoughtworks.xstream.XStreamException;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.ExtendedHierarchicalStreamWriterHelper;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

public class RoleConverter
    implements Converter
{

    public boolean canConvert( @SuppressWarnings( "rawtypes" ) Class type )
    {
        return RoleResource.class.equals( type );
    }

    public void marshal( Object source, HierarchicalStreamWriter writer, MarshallingContext context )
    {
        RoleResource role = (RoleResource) source;
        writeKey( writer, role.getKey() );
        write( writer, "description", role.getDescription() );
        write( writer, "name", role.getName() );
        write( writer, "resourceURI", role.getResourceURI() );
        write( writer, "sessionTimeout", role.getSessionTimeout() );
        write( writer, "userManaged", role.isUserManaged() );

        if ( !role.getRoles().isEmpty() )
        {
            ExtendedHierarchicalStreamWriterHelper.startNode( writer, "roles", List.class );
            for ( RoleKeyResource r : role.getRoles() )
            {
                writer.startNode( "role" );
                writeKey( writer, r );
                writer.endNode();
            }
            writer.endNode();
        }

        if ( !role.getPrivileges().isEmpty() )
        {
            ExtendedHierarchicalStreamWriterHelper.startNode( writer, "privileges", List.class );
            for ( String priv : role.getPrivileges() )
            {
                write( writer, "privilege", priv );
            }
            writer.endNode();
        }
    }

    private void writeKey( HierarchicalStreamWriter writer, RoleKeyResource key )
    {
        if ( key != null )
        {
            write( writer, "id", key.getId() );
            write( writer, "source", key.getSource() );
        }
    }

    private void write( HierarchicalStreamWriter writer, String name, Object value )
    {
        if ( value == null )
        {
            return;
        }
        ExtendedHierarchicalStreamWriterHelper.startNode( writer, name, value == null ? Object.class : value.getClass() );
        writer.setValue( String.valueOf( value ) );
        writer.endNode();
    }

    public Object unmarshal( HierarchicalStreamReader reader, UnmarshallingContext context )
    {
        RoleResource r = new RoleResource();
        r.setKey( new RoleKeyResource() );
        while ( reader.hasMoreChildren() )
        {
            reader.moveDown();
            if ( "id".equals( reader.getNodeName() ) )
            {
                r.getKey().setId( reader.getValue() );
            }
            else if ( "source".equals( reader.getNodeName() ) )
            {
                r.getKey().setSource( reader.getValue() );
            }
            else if ( "description".equals( reader.getNodeName() ) )
            {
                r.setDescription( reader.getValue() );
            }
            else if ( "name".equals( reader.getNodeName() ) )
            {
                r.setName( reader.getValue() );
            }
            else if ( "sessionTimeout".equals( reader.getNodeName() ) )
            {
                r.setSessionTimeout( new Integer( reader.getValue() ) );
            }
            else if ( "userManaged".equals( reader.getNodeName() ) )
            {
                r.setUserManaged( new Boolean( reader.getValue() ) );
            }
            else if ( "resourceURI".equals( reader.getNodeName() ) )
            {
                r.setResourceURI( reader.getValue() );
            }
            else if ( "privileges".equals( reader.getNodeName() ) )
            {
                while ( reader.hasMoreChildren() )
                {
                    reader.moveDown();
                    r.addPrivilege( reader.getValue() );
                    reader.moveUp();
                }
            }
            else if ( "roles".equals( reader.getNodeName() ) )
            {
                while ( reader.hasMoreChildren() )
                {
                    reader.moveDown();
                    while ( reader.hasMoreChildren() )
                    {
                        RoleKeyResource k = new RoleKeyResource();
                        while ( reader.hasMoreChildren() )
                        {
                            reader.moveDown();
                            if ( "id".equals( reader.getNodeName() ) )
                            {
                                k.setId( reader.getValue() );
                            }
                            else if ( "source".equals( reader.getNodeName() ) )
                            {
                                k.setSource( reader.getValue() );
                            }
                            else
                            {
                                throw new XStreamException( "Unknow field" + reader.getNodeName() );
                            }
                            reader.moveUp();
                        }
                        r.addRole( k );
                    }
                    reader.moveUp();
                }
            }
            else
            {
                throw new XStreamException( "Unknow field" + reader.getNodeName() );
            }
            reader.moveUp();
        }
        return r;
    }

}
