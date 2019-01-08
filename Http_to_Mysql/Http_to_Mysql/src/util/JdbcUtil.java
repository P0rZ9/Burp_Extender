package util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

import burp.BurpExtender;
import burp.BurpExtender.LogEntry;




//�������ݿ������
public class JdbcUtil 
{
    private static JdbcUtil instance = new JdbcUtil();
    private static HashMap<String, BurpExtender.LogEntry> httplog1 = new HashMap();
    public static JdbcUtil getInstance()
    {
      return instance;
    }
    
    public static Connection getConnection() throws ClassNotFoundException, SQLException
    {
	      String driverName = "com.mysql.jdbc.Driver";
	      String userName = "root";
	      String userPasswd = "root";
	      String dbName = "httpscan";
	      String tableName = "httplog";
	      
	      String url = "jdbc:mysql://localhost:3306/" + dbName;
	      Class.forName(driverName);
	      Connection conn = DriverManager.getConnection(url, userName, userPasswd);
	      
	      return conn;
    }
    
    
    //�ͷ���Դ
    public static void release(ResultSet rs, Statement stat, Connection con)
    {
      if (rs != null)
      {
        try
        {
          rs.close();
        }
        catch (SQLException e)
        {
          e.printStackTrace();
        }
        rs = null;
      }
      if (stat != null)
      {
        try
        {
          stat.close();
        }
        catch (SQLException e)
        {
          e.printStackTrace();
        }
        stat = null;
      }
      if (con != null)
      {
        try
        {
          con.close();
        }
        catch (SQLException e)
        {
          e.printStackTrace();
        }
        con = null;
      }
    }
  


    //�������
    public static boolean insert(LogEntry httplog1, Connection conn) throws ClassNotFoundException, SQLException
	  	{	
			ResultSet st  = null;
			boolean flag = true;
			try{
				String sql = "insert into httplog(url,method,header,body,host)value(?,?,?,?,?)";                               
				PreparedStatement ps = conn.prepareStatement(sql);
				ps.setString(1, httplog1.url);
				ps.setString(2, httplog1.method);
				ps.setString(3, httplog1.allheader);
				ps.setString(4, httplog1.body);
				ps.setString(5, httplog1.host);
				int num = ps.executeUpdate();
				if(num>0) {
					flag = true;
				}else {
					flag = false;
				}
			}catch(Exception e){
				e.printStackTrace();
			}finally {
				//do
			}
			return flag;
	  	}
    
    //���ǰ����(url��body����ͬ˵����ͬһ�����ݰ�)
	public static boolean is_repeat(String url, String body, Connection conn)
	{
		boolean is_repeat = false;
		Statement stmt = null;
		ResultSet st = null;
		try
		{
		    stmt = conn.createStatement();
		    String sql = "select count(*) from httplog where url='" + url + "' and body='" + body + "'";
		    st = stmt.executeQuery(sql);
		    while (st.next())
		    {
		    	if (st.getInt(1) > 0){
		    		is_repeat = true; 
		    	}
		    }
		}
		catch (Exception e){
		    e.printStackTrace();
		}
		return is_repeat;
	}

  }



