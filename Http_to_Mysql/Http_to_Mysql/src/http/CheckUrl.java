package http;

/*
   *  插入数据库前检查url的类
 */
public class CheckUrl {
	
	public static String[] black_suffixs = {
			    ".ico", ".woff", ".flv", ".js", ".css", ".jpg", 
			    ".png", ".jpeg", ".gif", ".pdf", ".txt", 
			    ".rar", ".zip", ".mp4", ".svg", "woff2", 
			    ".swf", ".wmi", ".exe", ".mpeg", ".htm" };
	
	public static String[] black_hosts = { ".gov", "mozilla.com", "qq.com", "mozilla.org", "so.com", "12306.cn", 
			    "google", "cdn.bcebos.com", "gstatic", "cnzz.com", "doubleclick", "bootcss.com", 
			    "360safe.com", "mil.cn", "gov.cn", "gov.com", "cnblogs.com", "box3.cn", "bdimg.com", 
			    "360.cn", "baidu.com", "bdstatic.com", "csdn.com", "github.com", "googleadsserving.cn", ".csdn.net" };
			  
	public static boolean isblackext(String url)
	{
	    for (String black_suffix : black_suffixs) 
	    {
	    	if (url.endsWith(black_suffix)) {
	    		return true;
	    	}
	    	if (url.contains("?"))
	    	{
	    		String[] urls = url.split("\\?");
	    		return isblackext(urls[0]);
	    	}
	    }
	    return false;
	}
	  
	
	public static boolean isblackdomain(String host)
	{
	    for (String black_host : black_hosts)
	    {
	    	if (host.contains(black_host)) {
	    		return true;
	    	}
	    }
	    return false;
	}
}
