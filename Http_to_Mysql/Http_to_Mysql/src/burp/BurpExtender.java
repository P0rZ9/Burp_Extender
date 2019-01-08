package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.net.URL;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

import burp.BurpExtender.LogEntry;
import http.CheckUrl;
import util.JdbcUtil;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IMessageEditorController
{
	  private IBurpExtenderCallbacks callbacks;
	  private IExtensionHelpers helpers;
	  private JSplitPane splitPane;
	  private IMessageEditor requestViewer;
	  private IMessageEditor responseViewer;
	  private List<LogEntry> log = new ArrayList();
	  private IHttpRequestResponse currentlyDisplayedItem;
	  public static PrintWriter stdout;

	  public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
	  {
	    this.callbacks = callbacks;
	    this.helpers = callbacks.getHelpers();
	    this.stdout = new PrintWriter(callbacks.getStdout(), true);
	    
	    //插件名称
	    callbacks.setExtensionName("Http-to-mysql");
	    
	    SwingUtilities.invokeLater(new Runnable()
	    {
	    	public void run()
	    	{
				BurpExtender.this.splitPane = new JSplitPane(0);
				
				//上面板内容
				BurpExtender.Table logTable = new BurpExtender.Table(BurpExtender.this);
				JScrollPane scrollPane = new JScrollPane(logTable);
				BurpExtender.this.splitPane.setLeftComponent(scrollPane);
				
				//下面板内容
				JTabbedPane tabs = new JTabbedPane();
				BurpExtender.this.requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
				BurpExtender.this.responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
				tabs.addTab("Request", BurpExtender.this.requestViewer.getComponent());
				tabs.addTab("Response", BurpExtender.this.responseViewer.getComponent());
				BurpExtender.this.splitPane.setRightComponent(tabs);
				
				//定制UI组件
				callbacks.customizeUiComponent(BurpExtender.this.splitPane);
				callbacks.customizeUiComponent(logTable);
				callbacks.customizeUiComponent(scrollPane);
				callbacks.customizeUiComponent(tabs);
				
				callbacks.addSuiteTab(BurpExtender.this);
				
				String github = "https://github.com/p0rz9";
				String author = "P0rZ9";
				
				callbacks.printOutput("#Author:" + author);
				callbacks.printOutput("#Github:" + github);
				
				callbacks.registerHttpListener(BurpExtender.this);
	    	}
	    });
	  }
  
	  public String getTabCaption()
	  {
	    return "http-to-mysql";
	  }
  
	  public Component getUiComponent()
	  {
	    return this.splitPane;
	  }
	  
	  public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
	  {
	    if (!messageIsRequest)
	    {
	    	int row = this.log.size();
	      	if (toolFlag == 4) 
	    	{	
	      		//返回包信息
		        IResponseInfo analyzeResponse = this.helpers.analyzeResponse(messageInfo.getResponse());
		        byte[] response_info = messageInfo.getResponse();
		        short status_code = analyzeResponse.getStatusCode();
		        List<String> response_header_list = analyzeResponse.getHeaders();
		        
		        //请求包信息
		        IRequestInfo analyzeRequest = this.helpers.analyzeRequest(messageInfo);
		        String request_info = new String(messageInfo.getRequest());
		        String url = analyzeRequest.getUrl().toString();
		        List<IParameter> param_list = analyzeRequest.getParameters();
		        List<String> request_header_list = analyzeRequest.getHeaders();
		        
		        //服务器信息
		        IHttpService iHttpService = messageInfo.getHttpService();
		        String host = iHttpService.getHost();
		        String path = analyzeRequest.getUrl().getPath();
		        String param = analyzeRequest.getUrl().getQuery();
		        int id = getRowCount() + 1;
		        
		        String messageBody = request_info.substring(analyzeRequest.getBodyOffset());
		        byte[] request_body = messageBody.getBytes();
		        
		        String allheader = "";
		        for (String header : request_header_list) {
		          if (header.contains(":")) {
		            allheader = allheader + header + "\n";
		          }
		        }
		        String method = this.helpers.analyzeRequest(messageInfo).getMethod();
		        
		        //检查数据包是否重复,Url情况
		        boolean is_black_ext = CheckUrl.isblackext(url);
		        boolean is_black_domain = CheckUrl.isblackdomain(host);
		        
		        if(method.equals("GET")) {
            		messageBody = param;
            	}
		        if ((!is_black_ext) && (!is_black_domain))
		        {
		          this.log.add(new LogEntry(id, this.callbacks.saveBuffersToTempFiles(messageInfo), url, allheader, messageBody, method, host));
		          boolean is_insert = false;
		          try
		          {
		        	Connection conn = JdbcUtil.getConnection();
		            boolean info_is_repeat = JdbcUtil.is_repeat(url, messageBody, conn);
		            if (!info_is_repeat)
		            {   
		            	is_insert = JdbcUtil.insert(new LogEntry(id, this.callbacks.saveBuffersToTempFiles(messageInfo), url, allheader, messageBody, method, host), conn);
		            	if (is_insert) {
		            		stdout.println("id:" + id + "插入成功");
		            	} else {
		            		stdout.println("id:" + id + "插入失败");
		            	}
		            }
		            else
		            {
		              stdout.println("request_data  is repeat");
		            }
		          }
		          catch (ClassNotFoundException|SQLException e)
		          {
		            e.printStackTrace();
		          }
		        }
		      }
		      fireTableRowsInserted(row, row);
		    }
		  }
	  
	  public int getRowCount()
	  {
		  return this.log.size();
	  }
	  
	  public int getColumnCount()
	  {
		  return 5;
	  }
	  
	  public String getColumnName(int columnIndex)
	  {
		switch (columnIndex)
		{
			case 0: 
			  return "Id";
			case 1: 
			  return "Url";
			case 2: 
			  return "Headers";
			case 3: 
			  return "Body";
			case 4: 
			  return "Method";
			default:
			  return "";
		}
		
	  }
	  
	  public Class<?> getColumnClass(int columnIndex)
	  {
		  return String.class;
	  }
	  
	  public Object getValueAt(int rowIndex, int columnIndex)
	  {
		  LogEntry logEntry = log.get(rowIndex);
		  switch (columnIndex)
		  {
		  	case 0: 
		  		return logEntry.id;
			case 1: 
				return logEntry.url;
			case 2: 
				return logEntry.allheader;
			case 3: 
				return logEntry.body;
			case 4: 
				return logEntry.method;
			default:
				return "";
		  }
		  
	  }
	  
	  public byte[] getRequest()
	  {
		  return this.currentlyDisplayedItem.getRequest();
	  }
	  
	  public byte[] getResponse()
	  {
		  return this.currentlyDisplayedItem.getResponse();
	  }
	  
	  public IHttpService getHttpService()
	  {
		  return this.currentlyDisplayedItem.getHttpService();
	  }
	  
	  
	  private class Table extends JTable
	  {
		  public Table(TableModel tableModel)
		  {
			  super(tableModel);
		  }
	    
		  public void changeSelection(int row, int col, boolean toggle, boolean extend)
		  {
		      LogEntry logEntry = log.get(row);
              requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
              responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
              currentlyDisplayedItem = logEntry.requestResponse;
		      
			  super.changeSelection(row, col, toggle, extend);
		  }
	  }
	  
	  //入库的对象类
	  public  class LogEntry
	  {
		  public int id;
		  public IHttpRequestResponsePersisted requestResponse;
		  public  String url;
		  public String allheader;
		  public String body;
		  public String method;
		  public String host;
	    
	    LogEntry(int id, IHttpRequestResponsePersisted requestResponse, String url, String allheader, String body, String method, String host)
	    {
	    	this.id = id;
	    	this.requestResponse = requestResponse;
	    	this.url = url;
	    	this.allheader = allheader;
	    	this.body = body;
	    	this.method = method;
	    	this.host = host;
	    }
	  }
	  
	
	  
	  
	  public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo, BurpExtender helpers) {}
	  
	}
