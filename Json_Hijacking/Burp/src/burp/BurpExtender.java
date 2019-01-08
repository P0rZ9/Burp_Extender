package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IMessageEditorController
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;  
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;
    public PrintWriter stdout;
    	
    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        //�ص�����
        this.callbacks = callbacks;
        
        //��ȡ��չhelper��stdout����
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        
        //�������
        callbacks.setExtensionName("Jsonp�ٳּ��");
        
        //����UI
        SwingUtilities.invokeLater(new Runnable() 
        {
            @Override
            public void run()
            {
                //�ָ����
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //���·ָ�
                        
                //�����
                Table logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable); //������
                splitPane.setLeftComponent(scrollPane);

                //�����
                JTabbedPane tabs = new JTabbedPane(); 
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitPane.setRightComponent(tabs);

                //����UI���
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(tabs);
                
                //��ӱ�ǩ
                callbacks.addSuiteTab(BurpExtender.this);
                
                //���ز�����Ĭ����Ϣ
                String payload = "?call=qwert&json=qwert&callback=qwert&cb=qwert&jsonp=qwert&jsonpcallback=qwert";
                String author = "P0rZ9";
                		
                callbacks.printOutput("#Author:"+author);
                callbacks.printOutput("#payload:"+payload);
                
                //ע�������
                callbacks.registerHttpListener(BurpExtender.this);
            }
        });
    }

    //
    // implement ITab
    //

    @Override
    public String getTabCaption()
    {
        return "Jsonp�ٳּ��";
    }

    @Override
    public Component getUiComponent()
    {
        return splitPane;
    }

    //
    // implement IHttpListener
    //
    
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        if (!messageIsRequest)
        {	int row = log.size();
        	if ((toolFlag == 4)){//����Proxy���ߵ�����
        		//������Ϣ
        		IHttpService iHttpService = messageInfo.getHttpService();
                IResponseInfo analyzeResponse = this.helpers.analyzeResponse(messageInfo.getResponse());
                byte[] response_info = messageInfo.getResponse();
                short status_code = analyzeResponse.getStatusCode();
                List<String> response_header_list = analyzeResponse.getHeaders();
                
                //������Ϣ
                IRequestInfo analyzeRequest = this.helpers.analyzeRequest(messageInfo);            
                String request_info = new String(messageInfo.getRequest());
                URL url1 = analyzeRequest.getUrl();
                List<IParameter> param_list = analyzeRequest.getParameters();
                List<String> request_header_list = analyzeRequest.getHeaders();
                
                //�����������Ϣ
                String host = iHttpService.getHost();
                String path = analyzeRequest.getUrl().getPath();
                //String param = param_list.toString();
                String param = analyzeRequest.getUrl().getQuery();
                int id = getRowCount()+1;
                
                String messageBody = request_info.substring(analyzeRequest.getBodyOffset());
                byte[] request_body = messageBody.getBytes();
                
                //1.�����url�к�Jsonp���в���
                if ((((String)request_header_list.get(0)).indexOf("callback=") != -1) || 
                  (((String)request_header_list.get(0)).indexOf("cb=") != -1) || (((String)request_header_list.get(0)).indexOf("jsonp") != -1) || 
                  (((String)request_header_list.get(0)).indexOf("json=") != -1) || (((String)request_header_list.get(0)).indexOf("call=") != -1))
                {
                    log.add(new LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo), 
                              host,path,param,helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode()));
                }
                
                //2.url�������в���,��Ӳ�������
                else
                {
                  
                  List<String> new_headers = request_header_list;
                  String header_first = "";
                  
                  //url�в���
                  if (((String)request_header_list.get(0)).indexOf("?") != -1) {
                    header_first = ((String)new_headers.get(0)).replace("?", "?call=qwert&json=qwert&callback=qwert&cb=qwert&jsonp=qwert&jsonpcallback=qwert&");
                  } else {//url�޲���
                    header_first = ((String)new_headers.get(0)).replace(" HTTP/1.1", "?call=qwert&json=qwert&callback=qwert&cb=qwert&jsonp=qwert&jsonpcallback=qwert HTTP/1.1");
                  }
                  new_headers.remove(0);
                  new_headers.add(0, header_first);
                  
                  //�µ������
                  byte[] req = this.helpers.buildHttpMessage(new_headers, request_body);
                  IHttpRequestResponse messageInfo1 = this.callbacks.makeHttpRequest(iHttpService, req);
                  
                  IRequestInfo analyzeRequest1 = this.helpers.analyzeRequest(messageInfo1);
                  String request_info1 = new String(messageInfo1.getRequest());
                  URL url2 = analyzeRequest1.getUrl();
                  
                  String req_body = request_info1.substring(analyzeRequest1.getBodyOffset());
                  
                  //�µķ��ذ�
                  IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
                  String response_info1 = new String(messageInfo1.getResponse());
                  String rep_body = response_info1.substring(analyzeResponse1.getBodyOffset());
                  if (rep_body.indexOf("qwert") != -1)
                  {	//id response host path status
                      log.add(new LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo), 
                              host,path,param,helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode()));
                    
                  }
                }
              }
	         fireTableRowsInserted(row, row);
	      }
	
	  }

    //
    // extend AbstractTableModel
    //
    
    @Override
    public int getRowCount()
    {
        return log.size();
    }

    @Override
    public int getColumnCount()
    {
        return 5;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "Id";
            case 1:
                return "Host";
            case 2:
                return "Path";
            case 3:
            	return "Param";
            case 4:
            	return "Status";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.id;
            case 1:
                return logEntry.Host;
            case 2:
            	return logEntry.Path;
            case 3:
            	return logEntry.Param;
            case 4:
            	return logEntry.Status;
            default:
                return "";
        }
    }


    
    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }


    
    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }
        
        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;
            
            super.changeSelection(row, col, toggle, extend);
        }        
    }
    

    
    //����©����url��Ϣ��
    private static class LogEntry
    {
        final int id;
        final IHttpRequestResponsePersisted requestResponse;
        //final URL url;
        final String Host;
        final String Path;
        final String Param;
        final short Status;
        

        LogEntry(int id, IHttpRequestResponsePersisted requestResponse, String host, String path, String param, short status)
        {	
        	this.Status = status;
            this.id = id;
            this.requestResponse = requestResponse;
            //this.Url = url;
            this.Param = param;
            this.Path = path;
            this.Host = host;
        }
    }

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo,
			BurpExtender helpers) {
		// TODO Auto-generated method stub
		
	}
}